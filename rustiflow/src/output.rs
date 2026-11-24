mod connection_order;
mod parquet;

use crate::{
    args::{ExportMethodType, OutputConfig},
    export_profile,
    flows::{
        flow::Flow,
        row::{CsvRow, Record},
    },
};
use anyhow::{Context, Result};
use connection_order::Message;
use log::error;
use std::{
    fs::File,
    io::{BufWriter, Write},
    time::Instant,
};
use tokio::{sync::mpsc, task::JoinHandle};

/// Flows a shard may queue for its encoder before the shard waits.
const SHARD_FLOW_QUEUE_CAPACITY: usize = 256;
/// Flows an encoder takes from its queue per wakeup.
const ENCODER_FLOW_BATCH: usize = 64;
/// Encoded bytes an encoder accumulates before handing a chunk to the writer.
const ENCODED_CHUNK_BYTES: usize = 64 * 1024;
/// Encoded chunks that may wait for the writer.
const ENCODED_CHUNK_QUEUE_CAPACITY: usize = 64;

pub enum FlowExporter<T> {
    Shared(mpsc::Sender<Message<T>>),
    Parquet(parquet::Exporter<T>),
    Csv {
        clean: bool,
        chunks: mpsc::Sender<String>,
    },
}

/// One flow table's output. Parquet projects directly from the owned flow
/// while it is still hot in the table worker's cache.
pub enum ShardOutput<T> {
    Shared {
        messages: mpsc::Sender<Message<T>>,
        offline_shard: Option<usize>,
    },
    Channel(mpsc::Sender<T>),
    Parquet(parquet::Shard<T>),
}

impl<T> From<mpsc::Sender<T>> for ShardOutput<T> {
    fn from(sender: mpsc::Sender<T>) -> Self {
        Self::Channel(sender)
    }
}

impl<T: Flow> ShardOutput<T> {
    pub async fn export(&mut self, flow: T) {
        match self {
            Self::Channel(sender) => {
                if sender.send(flow).await.is_err() {
                    error!("Failed to send flow: export channel is closed");
                }
            }
            Self::Parquet(shard) => shard.export(&flow).await,
            Self::Shared { messages, .. } => {
                if messages.send(Message::Flow(flow)).await.is_err() {
                    error!("Failed to send flow: export channel is closed");
                }
            }
        }
    }

    pub async fn publish_watermark(&self, timestamp_us: i64) {
        if let Self::Shared {
            messages,
            offline_shard: Some(shard),
        } = self
        {
            let _ = messages
                .send(Message::Watermark {
                    shard: *shard,
                    timestamp_us,
                })
                .await;
        }
    }

    pub async fn flush(&mut self) {
        if let Self::Parquet(shard) = self {
            shard.flush().await;
        }
    }
}

/// Destination for the flows that each shard's flow table exports.
pub trait FlowSink<T>: Send + 'static {
    /// Creates the output used by one shard for its lifetime.
    fn shard_output(&self) -> ShardOutput<T>;

    fn pcap_shard_output(&self, _shard: usize) -> ShardOutput<T> {
        self.shard_output()
    }
}

/// All shards share the channel; used by tests that inspect exported flows.
impl<T: Flow> FlowSink<T> for mpsc::Sender<T> {
    fn shard_output(&self) -> ShardOutput<T> {
        self.clone().into()
    }
}

impl<T: Flow> FlowSink<T> for FlowExporter<T> {
    fn shard_output(&self) -> ShardOutput<T> {
        let (clean, chunk_sender) = match self {
            Self::Shared(messages) => {
                return ShardOutput::Shared {
                    messages: messages.clone(),
                    offline_shard: None,
                }
            }
            Self::Parquet(exporter) => return ShardOutput::Parquet(exporter.shard()),
            Self::Csv { clean, chunks } => (*clean, chunks.clone()),
        };
        let (flow_sender, mut flow_receiver) = mpsc::channel::<T>(SHARD_FLOW_QUEUE_CAPACITY);

        tokio::spawn(async move {
            let mut flows = Vec::with_capacity(ENCODER_FLOW_BATCH);
            let mut chunk = String::with_capacity(ENCODED_CHUNK_BYTES);

            while flow_receiver
                .recv_many(&mut flows, ENCODER_FLOW_BATCH)
                .await
                > 0
            {
                for flow in flows.drain(..) {
                    let dump_start = Instant::now();
                    let start = chunk.len();
                    project(&flow, clean, &mut CsvRow::new(&mut chunk));
                    export_profile::record_dump(dump_start.elapsed(), chunk.len() - start);
                    chunk.push('\n');
                }

                // Hand over full chunks, and partial ones when idle, so rows of a
                // quiet shard are not held back.
                if chunk.len() >= ENCODED_CHUNK_BYTES || flow_receiver.is_empty() {
                    let full_chunk =
                        std::mem::replace(&mut chunk, String::with_capacity(ENCODED_CHUNK_BYTES));
                    if chunk_sender.send(full_chunk).await.is_err() {
                        error!("Failed to send encoded flows: output writer is closed");
                        return;
                    }
                }
            }

            if !chunk.is_empty() && chunk_sender.send(chunk).await.is_err() {
                error!("Failed to send encoded flows: output writer is closed");
            }
        });

        flow_sender.into()
    }

    fn pcap_shard_output(&self, shard: usize) -> ShardOutput<T> {
        match self {
            Self::Shared(messages) => ShardOutput::Shared {
                messages: messages.clone(),
                offline_shard: Some(shard),
            },
            _ => self.shard_output(),
        }
    }
}

fn project<T: Flow>(flow: &T, clean: bool, row: &mut impl Record) {
    if clean {
        flow.write_clean_fields(row);
    } else {
        flow.write_fields(row);
    }
}

pub fn spawn_output_writer<T: Flow>(
    output: OutputConfig,
    offline_shards: Option<u8>,
) -> Result<(FlowExporter<T>, JoinHandle<Result<()>>)> {
    let (exporter, writer) = spawn_writer::<T>(output)?;
    if !T::USES_CONNECTION_HISTORY {
        return Ok((exporter, writer));
    }

    // A single ordered input stream gives the window and all output formats
    // the same connection order, even when several flow tables are active.
    let (sender, receiver) = mpsc::channel(SHARD_FLOW_QUEUE_CAPACITY);
    let task = tokio::spawn(async move {
        let mut output = exporter.shard_output();
        drop(exporter);
        let result = connection_order::export(receiver, &mut output, offline_shards).await;
        output.flush().await;
        drop(output);
        writer.await??;
        result
    });
    Ok((FlowExporter::Shared(sender), task))
}

fn spawn_writer<T: Flow>(
    output: OutputConfig,
) -> Result<(FlowExporter<T>, JoinHandle<Result<()>>)> {
    let clean = output.drop_contaminant_features;
    let headers = if clean {
        T::get_features_without_contamination()
    } else {
        T::get_features()
    };
    let open =
        |path: &str| File::create(path).with_context(|| format!("creating output file {path}"));
    let destination: Box<dyn Write + Send> = match output.output {
        ExportMethodType::Parquet => {
            let file = match output.export_path.as_deref() {
                Some(path) => open(path)?,
                None => File::create_new("output.parquet").context(
                    "creating output.parquet (set --export-path to choose a destination)",
                )?,
            };
            return parquet::spawn::<T>(file, &headers, clean);
        }
        ExportMethodType::Csv => Box::new(open(
            output
                .export_path
                .as_deref()
                .context("CSV output requires an export path")?,
        )?),
        ExportMethodType::Print => Box::new(std::io::stdout()),
    };
    let mut writer = BufWriter::new(destination);
    if output.header {
        writeln!(writer, "{headers}")?;
    }
    let (chunks, mut receiver) = mpsc::channel::<String>(ENCODED_CHUNK_QUEUE_CAPACITY);
    let task = tokio::task::spawn_blocking(move || {
        while let Some(rows) = receiver.blocking_recv() {
            let start = Instant::now();
            writer.write_all(rows.as_bytes())?;
            export_profile::record_write(start.elapsed());
        }
        writer.flush()?;
        Ok(())
    });
    Ok((FlowExporter::Csv { clean, chunks }, task))
}
