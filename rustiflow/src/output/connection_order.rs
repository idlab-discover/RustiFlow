use std::collections::{BTreeMap, VecDeque};

use anyhow::{ensure, Result};
use tokio::sync::mpsc;

use crate::{
    flow_key::FlowKey,
    flows::{
        features::connection_history::{
            Connection, ConnectionCounts, ConnectionHistory, WINDOW_SIZE,
        },
        flow::Flow,
    },
};

use super::ShardOutput;

pub(crate) enum Message<T> {
    Flow(T),
    Watermark { shard: usize, timestamp_us: i64 },
}

pub(super) async fn export<T: Flow>(
    mut receiver: mpsc::Receiver<Message<T>>,
    output: &mut ShardOutput<T>,
    offline_shards: Option<u8>,
) -> Result<()> {
    if let Some(shards) = offline_shards {
        return export_offline(receiver, output, shards).await;
    }

    let mut history = ConnectionHistory::default();
    while let Some(Message::Flow(mut flow)) = receiver.recv().await {
        if let Some(connection) = flow.connection() {
            flow.set_connection_counts(history.observe(connection));
        }
        output.export(flow).await;
    }
    Ok(())
}

type OrderKey = (i64, i64, FlowKey, u64);

async fn export_offline<T: Flow>(
    mut receiver: mpsc::Receiver<Message<T>>,
    output: &mut ShardOutput<T>,
    shards: u8,
) -> Result<()> {
    let mut shard_watermarks = vec![i64::MIN; usize::from(shards)];
    let mut watermark = i64::MIN;
    let mut pending: BTreeMap<OrderKey, (T, Connection)> = BTreeMap::new();
    let mut ordinal = 0;
    let mut window = Lookahead::default();

    while let Some(message) = receiver.recv().await {
        match message {
            Message::Flow(flow) => {
                let Some(connection) = flow.connection() else {
                    output.export(flow).await;
                    continue;
                };
                ensure!(
                    connection.last_timestamp_us >= watermark,
                    "pcap flow ended at {} µs before the export watermark at {watermark} µs; order the capture by packet timestamp",
                    connection.last_timestamp_us,
                );
                let key = (
                    connection.last_timestamp_us,
                    connection.first_timestamp_us,
                    connection.key,
                    ordinal,
                );
                ordinal += 1;
                pending.insert(key, (flow, connection));
            }
            Message::Watermark {
                shard,
                timestamp_us,
            } => {
                shard_watermarks[shard] = shard_watermarks[shard].max(timestamp_us);
                watermark = shard_watermarks.iter().copied().min().unwrap_or(i64::MIN);
                // A shard publishes its watermark after exporting all flows
                // with earlier end times. Wait for the slowest shard.
                while pending
                    .first_key_value()
                    .is_some_and(|(&(end, ..), _)| end < watermark)
                {
                    let (_, (flow, connection)) = pending.pop_first().expect("pending flow");
                    window.push(flow, connection, output).await;
                }
            }
        }
    }
    for (flow, connection) in pending.into_values() {
        window.push(flow, connection, output).await;
    }
    while !window.rows.is_empty() {
        window.pop(output).await;
    }
    Ok(())
}

struct Lookahead<T> {
    rows: VecDeque<(T, Connection)>,
    completed: usize,
}

impl<T> Default for Lookahead<T> {
    fn default() -> Self {
        Self {
            rows: VecDeque::new(),
            completed: 0,
        }
    }
}

impl<T: Flow> Lookahead<T> {
    async fn push(&mut self, flow: T, connection: Connection, output: &mut ShardOutput<T>) {
        self.completed += usize::from(connection.completed);
        self.rows.push_back((flow, connection));
        while self.rows.front().is_some_and(|(_, current)| {
            self.completed >= WINDOW_SIZE - 1 + usize::from(current.completed)
        }) {
            self.pop(output).await;
        }
    }

    async fn pop(&mut self, output: &mut ShardOutput<T>) {
        let Some((mut flow, current)) = self.rows.pop_front() else {
            return;
        };
        self.completed -= usize::from(current.completed);
        let next = self
            .rows
            .iter()
            .map(|(_, connection)| *connection)
            .filter(|c| c.completed);
        flow.set_connection_counts(ConnectionCounts::within(current, next));
        output.export(flow).await;
    }
}
