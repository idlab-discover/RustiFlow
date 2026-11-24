use std::{future, sync::Arc};

use anyhow::{anyhow, ensure, Context, Result};
use aya::maps::{MapData, RingBuf};
use tokio::{
    io::unix::AsyncFd,
    runtime::Builder,
    sync::{oneshot, watch},
    task::JoinSet,
};

use super::{
    read_env_usize, DecodeEvent, DrainPolicy, PacketGraphState, PipelineSettings,
    RealtimeSourceStats, ShardSelector, SourceBatcher,
};

pub(super) struct ReactorCount(usize);

impl ReactorCount {
    pub(super) fn from_env(ingress_only: bool) -> Result<Self> {
        let count = read_env_usize("RUSTIFLOW_EXPERIMENT_SOURCE_REACTORS", 0);
        // Separate ingress and egress rings can carry the same biflow. The
        // experiment relies on capture at one hook for ring-local ordering.
        ensure!(
            ingress_only || count == 0,
            "dedicated source reactors require --ingress-only"
        );
        Ok(Self(count))
    }
}

pub(super) struct RingSource {
    pub(super) ring: RingBuf<MapData>,
    pub(super) decode: DecodeEvent,
    pub(super) stats: Option<Arc<RealtimeSourceStats>>,
}

pub(super) struct RingSourcePipeline {
    pub(super) shard_senders: Vec<super::ShardBatchSender>,
    pub(super) shard_selector: ShardSelector,
    pub(super) drain_policy: DrainPolicy,
    pub(super) settings: PipelineSettings,
    pub(super) packet_graph: Option<PacketGraphState>,
    pub(super) realtime_offset_us: i64,
}

impl RingSourcePipeline {
    pub(super) async fn start(
        self,
        count: ReactorCount,
        shared_tasks: &mut JoinSet<()>,
        sources: Vec<RingSource>,
    ) -> Result<SourceReactors> {
        let count = count.0.min(sources.len());
        let (stop, _) = watch::channel(());
        let mut reactors = SourceReactors {
            stop,
            workers: JoinSet::new(),
        };
        if count == 0 {
            self.spawn_sources(shared_tasks, sources)?;
            return Ok(reactors);
        }

        // Each ring and its dispatcher stay together on one reactor. The
        // assignment is static so a busy source never has concurrent readers.
        let mut groups: Vec<_> = (0..count).map(|_| Vec::new()).collect();
        for (index, source) in sources.into_iter().enumerate() {
            groups[index % count].push(source);
        }

        let pipeline = Arc::new(self);
        let mut ready = Vec::with_capacity(count);
        for (index, sources) in groups.into_iter().enumerate() {
            let pipeline = Arc::clone(&pipeline);
            let mut stop = reactors.stop.subscribe();
            let (started, startup) = oneshot::channel();
            ready.push(startup);
            // Each blocking thread drives one current-thread I/O reactor.
            // Dropping the owner closes the watch channel and wakes every reactor.
            reactors.workers.spawn_blocking(move || {
                let runtime = Builder::new_current_thread()
                    .enable_io()
                    .build()
                    .with_context(|| format!("building source reactor {index}"))?;
                runtime.block_on(async {
                    let mut tasks = JoinSet::new();
                    pipeline
                        .spawn_sources(&mut tasks, sources)
                        .with_context(|| format!("starting source reactor {index}"))?;
                    drop(pipeline);
                    let _ = started.send(());

                    tokio::select! {
                        _ = stop.changed() => {
                            tasks.shutdown().await;
                            Ok(())
                        }
                        result = tasks.join_next() => {
                            match result {
                                Some(Err(error)) => Err(error).context("ring source task failed"),
                                _ => Err(anyhow!("ring source task finished unexpectedly")),
                            }
                            .with_context(|| format!("source reactor {index}"))
                        }
                    }
                })
            });
        }
        for startup in ready {
            if startup.await.is_err() {
                let error = reactors.unexpected_exit().await;
                if let Err(shutdown_error) = reactors.shutdown().await {
                    log::error!(
                        "Stopping the remaining source reactors failed: {shutdown_error:#}"
                    );
                }
                return Err(error);
            }
        }
        log::info!("Started {count} dedicated source reactors");
        Ok(reactors)
    }

    fn spawn_sources(&self, tasks: &mut JoinSet<()>, sources: Vec<RingSource>) -> Result<()> {
        for RingSource {
            ring,
            decode,
            stats,
        } in sources
        {
            // SAFETY: the ring owns its map descriptor and always reports the
            // same open descriptor until it is dropped with the AsyncFd.
            let ring = unsafe { AsyncFd::register(ring) }
                .map_err(|error| error.into_parts().1)
                .context("registering event ring")?;
            let batcher = SourceBatcher::new(
                tasks,
                &self.shard_senders,
                &self.shard_selector,
                &self.settings,
                stats,
            );
            tasks.spawn(self.drain_policy.run(
                ring,
                batcher,
                self.packet_graph.clone(),
                decode,
                self.realtime_offset_us,
            ));
        }
        Ok(())
    }
}

pub(super) struct SourceReactors {
    stop: watch::Sender<()>,
    workers: JoinSet<Result<()>>,
}

impl SourceReactors {
    /// Reports a worker failure during capture. The shared runtime needs no
    /// dedicated workers, so in that case this future stays pending.
    pub(super) async fn unexpected_exit(&mut self) -> anyhow::Error {
        match self.workers.join_next().await {
            Some(Ok(Ok(()))) => anyhow!("source reactor stopped during capture"),
            Some(Ok(Err(error))) => error,
            Some(Err(error)) => anyhow::Error::new(error).context("source reactor thread failed"),
            None => future::pending().await,
        }
    }

    pub(super) async fn shutdown(self) -> Result<()> {
        let Self { stop, mut workers } = self;
        drop(stop);
        let mut failure = None;
        while let Some(result) = workers.join_next().await {
            if let Err(error) = result
                .context("joining source reactor")
                .and_then(|inner| inner)
            {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}
