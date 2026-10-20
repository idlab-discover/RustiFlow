use crate::{args::ExportMethodType, export_profile, flows::flow::Flow};
use log::{debug, error};
use std::{
    fs::File,
    io::{BufWriter, Write},
    time::Instant,
};
use tokio::sync::mpsc;

/// Flows a shard may queue for its encoder before the shard waits.
const SHARD_FLOW_QUEUE_CAPACITY: usize = 256;
/// Flows an encoder takes from its queue per wakeup.
const ENCODER_FLOW_BATCH: usize = 64;
/// Encoded bytes an encoder accumulates before handing a chunk to the writer.
const ENCODED_CHUNK_BYTES: usize = 64 * 1024;
/// Encoded chunks that may wait for the writer.
pub const ENCODED_CHUNK_QUEUE_CAPACITY: usize = 64;

/// Sending side of the export pipeline.
///
/// CSV encoding dominates export cost, so each shard gets its own encoder task
/// and the single writer only copies finished bytes. Rows of one shard keep
/// their order; rows of different shards interleave, as they always have.
#[derive(Clone)]
pub struct FlowExporter {
    skip_contaminant_features: bool,
    chunk_sender: mpsc::Sender<Vec<u8>>,
}

impl FlowExporter {
    pub fn new(skip_contaminant_features: bool, chunk_sender: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            skip_contaminant_features,
            chunk_sender,
        }
    }
}

/// Destination for the flows that each shard's flow table exports.
pub trait FlowSink<T>: Send + 'static {
    /// Returns the sender one shard's flow table exports into.
    fn shard_sender(&self) -> mpsc::Sender<T>;
}

/// All shards share the channel; used by tests that inspect exported flows.
impl<T: Flow> FlowSink<T> for mpsc::Sender<T> {
    fn shard_sender(&self) -> mpsc::Sender<T> {
        self.clone()
    }
}

impl<T: Flow> FlowSink<T> for FlowExporter {
    /// Spawns an encoder task for one shard. The task ends once every clone of
    /// the returned sender is dropped, after handing its last chunk to the writer.
    fn shard_sender(&self) -> mpsc::Sender<T> {
        let (flow_sender, mut flow_receiver) = mpsc::channel::<T>(SHARD_FLOW_QUEUE_CAPACITY);
        let skip_contaminant_features = self.skip_contaminant_features;
        let chunk_sender = self.chunk_sender.clone();

        tokio::spawn(async move {
            let mut flows = Vec::with_capacity(ENCODER_FLOW_BATCH);
            let mut row = String::with_capacity(4096);
            let mut chunk = Vec::with_capacity(ENCODED_CHUNK_BYTES);

            while flow_receiver
                .recv_many(&mut flows, ENCODER_FLOW_BATCH)
                .await
                > 0
            {
                for flow in flows.drain(..) {
                    let dump_start = Instant::now();
                    row.clear();
                    if skip_contaminant_features {
                        flow.append_to_csv_row_without_contamination(&mut row);
                    } else {
                        flow.append_to_csv_row(&mut row);
                    }
                    export_profile::record_dump(dump_start.elapsed(), row.len());
                    chunk.extend_from_slice(row.as_bytes());
                    chunk.push(b'\n');
                }

                // Hand over full chunks, and partial ones when idle, so rows of a
                // quiet shard are not held back.
                if chunk.len() >= ENCODED_CHUNK_BYTES || flow_receiver.is_empty() {
                    let full_chunk =
                        std::mem::replace(&mut chunk, Vec::with_capacity(ENCODED_CHUNK_BYTES));
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

        flow_sender
    }
}

pub struct OutputWriter<T> {
    write_header: bool,
    skip_contaminant_features: bool,
    writer: BufWriter<Box<dyn Write + Send>>,
    _phantom_data: std::marker::PhantomData<T>,
}

impl<T> OutputWriter<T>
where
    T: Flow,
{
    pub fn new(
        export_type: ExportMethodType,
        write_header: bool,
        skip_contaminant_features: bool,
        file_path: Option<String>,
    ) -> Self {
        let writer: BufWriter<Box<dyn Write + Send>> = match export_type {
            ExportMethodType::Csv => {
                let path = file_path
                    .clone()
                    .expect("File path required for CSV output");
                let file = File::create(&path).expect("Failed to create file");
                BufWriter::new(Box::new(file))
            }
            ExportMethodType::Print => BufWriter::new(Box::new(std::io::stdout())),
        };

        OutputWriter {
            write_header,
            skip_contaminant_features,
            writer,
            _phantom_data: std::marker::PhantomData,
        }
    }

    pub fn init(&mut self) {
        debug!("Initializing output writer");
        if self.write_header {
            if let Err(e) = self.write_header() {
                error!("Error writing header: {}", e);
            }
        }
        debug!("Output writer initialized");
    }

    /// Writes newline-terminated CSV rows produced by a `FlowExporter` encoder.
    pub fn write_encoded(&mut self, rows: &[u8]) -> std::io::Result<()> {
        let write_start = Instant::now();
        self.writer.write_all(rows)?;
        export_profile::record_write(write_start.elapsed());
        Ok(())
    }

    /// Flushes the writer and closes the output file
    /// Explicitly called in the main function to ensure all data is written
    pub fn flush_and_close(&mut self) -> std::io::Result<()> {
        self.writer.flush() // Ensure all data is written
    }

    // Private method for writing the header
    fn write_header(&mut self) -> std::io::Result<()> {
        debug!("Writing header to output");
        let header = if self.skip_contaminant_features {
            T::get_features_without_contamination()
        } else {
            T::get_features()
        };
        self.writer.write_all(header.as_bytes())?;
        self.writer.write_all(b"\n")
    }
}
