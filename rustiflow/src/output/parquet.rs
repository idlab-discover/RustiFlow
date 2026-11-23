use std::{
    fmt::Write as _,
    fs::File,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};

use anyhow::{ensure, Context, Result};
use arrow_schema::{DataType, Field, Schema, TimeUnit};
use bytes::Bytes;
use parquet::{
    arrow::{add_encoded_arrow_schema_to_metadata, ArrowSchemaConverter},
    basic::{Compression, Encoding, Type},
    column::writer::{get_column_writer, ColumnCloseResult, ColumnWriter},
    data_type::ByteArray,
    file::{
        properties::{EnabledStatistics, WriterProperties},
        writer::{SerializedFileWriter, SerializedPageWriter, TrackedWrite},
    },
    schema::types::ColumnDescPtr,
};
use tokio::{sync::mpsc, task::JoinHandle};

use super::{project, FlowExporter};
use crate::{
    export_profile,
    flows::{
        flow::Flow,
        row::{Record, Value},
    },
};

// Start compression early on short captures, then amortize column metadata
// and encoder setup across larger groups in sustained exports.
const FIRST_GROUP_ROWS: usize = 512;
const MAX_GROUP_ROWS: usize = 4096;

struct EncodedGroup {
    bytes: Bytes,
    columns: Vec<ColumnCloseResult>,
}

struct TextColumn {
    data: String,
    ends: Vec<usize>,
}

impl TextColumn {
    fn into_values(self) -> Vec<ByteArray> {
        let data = Bytes::from(self.data);
        let mut start = 0;
        self.ends
            .into_iter()
            .map(|end| {
                let value = ByteArray::from(data.slice(start..end));
                start = end;
                value
            })
            .collect()
    }
}

enum Column {
    Integer(Vec<i64>),
    Float(Vec<f64>),
    Text(Box<TextColumn>),
}

impl Column {
    fn new(ty: Type, capacity: usize) -> Self {
        match ty {
            Type::INT64 => Self::Integer(Vec::with_capacity(capacity)),
            Type::DOUBLE => Self::Float(Vec::with_capacity(capacity)),
            Type::BYTE_ARRAY => Self::Text(Box::new(TextColumn {
                data: String::with_capacity(capacity * 8),
                ends: Vec::with_capacity(capacity),
            })),
            _ => unreachable!("unsupported flow column type"),
        }
    }
}

// Export projections have fixed arity and Rust types for each feature set.
// Visit one empty flow at startup so even a zero-record file has its schema.
#[derive(Default)]
struct Layout {
    types: Vec<DataType>,
}

impl Record for Layout {
    fn append(&mut self, value: Value<'_>) {
        self.types.push(match value {
            Value::Integer(_) => DataType::Int64,
            Value::Float(_) => DataType::Float64,
            Value::Address(_) | Value::Text(_) => DataType::Utf8,
            Value::Timestamp(_) => DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
        });
    }
}

struct BatchRow<'a>(std::slice::IterMut<'a, Column>);

impl Record for BatchRow<'_> {
    #[inline]
    fn append(&mut self, value: Value<'_>) {
        match (self.0.next(), value) {
            (Some(Column::Integer(b)), Value::Integer(n)) => b.push(n),
            (Some(Column::Float(b)), Value::Float(n)) => b.push(n),
            (Some(Column::Integer(b)), Value::Timestamp(ts)) => b.push(ts.timestamp_micros()),
            (Some(Column::Text(b)), Value::Text(s)) => {
                b.data.push_str(s);
                b.ends.push(b.data.len());
            }
            (Some(Column::Text(b)), Value::Address(ip)) => {
                write!(b.data, "{ip}").expect("writing address to string");
                b.ends.push(b.data.len());
            }
            _ => unreachable!("flow projection must match its schema"),
        }
    }
}

struct Encoder {
    descriptors: Vec<ColumnDescPtr>,
    properties: Arc<WriterProperties>,
    interrupted: AtomicBool,
}

impl Encoder {
    fn columns(&self, capacity: usize) -> Vec<Column> {
        self.descriptors
            .iter()
            .map(|d| Column::new(d.physical_type(), capacity))
            .collect()
    }

    fn encode(&self, columns: Vec<Column>) -> Result<EncodedGroup> {
        let mut bytes = TrackedWrite::new(Vec::new());
        let mut chunks = Vec::with_capacity(columns.len());
        for (column, descriptor) in columns.into_iter().zip(&self.descriptors) {
            let pages = Box::new(SerializedPageWriter::new(&mut bytes));
            let mut writer = get_column_writer(descriptor.clone(), self.properties.clone(), pages);
            match (&mut writer, column) {
                (ColumnWriter::Int64ColumnWriter(w), Column::Integer(v)) => {
                    w.write_batch(&v, None, None)?
                }
                (ColumnWriter::DoubleColumnWriter(w), Column::Float(v)) => {
                    w.write_batch(&v, None, None)?
                }
                (ColumnWriter::ByteArrayColumnWriter(w), Column::Text(v)) => {
                    w.write_batch(&v.into_values(), None, None)?
                }
                _ => unreachable!("flow projection must match the physical Parquet schema"),
            };
            chunks.push(writer.close()?);
        }
        Ok(EncodedGroup {
            bytes: bytes.into_inner()?.into(),
            columns: chunks,
        })
    }
}

type GroupJob = JoinHandle<Result<EncodedGroup>>;

#[derive(Clone)]
pub struct Exporter<T> {
    encoder: Arc<Encoder>,
    jobs: mpsc::Sender<GroupJob>,
    project: fn(&T, &mut BatchRow<'_>),
}

impl<T: Flow> Exporter<T> {
    pub(super) fn shard(&self) -> Shard<T> {
        Shard {
            exporter: self.clone(),
            columns: self.encoder.columns(FIRST_GROUP_ROWS),
            capacity: FIRST_GROUP_ROWS,
            rows: 0,
        }
    }
}

pub struct Shard<T> {
    exporter: Exporter<T>,
    columns: Vec<Column>,
    rows: usize,
    capacity: usize,
}

impl<T: Flow> Shard<T> {
    pub(super) async fn export(&mut self, flow: &T) {
        let start = Instant::now();
        if self.columns.is_empty() {
            self.columns = self.exporter.encoder.columns(self.capacity);
        }
        let mut row = BatchRow(self.columns.iter_mut());
        (self.exporter.project)(flow, &mut row);
        assert_eq!(row.0.len(), 0, "flow has fewer fields than its schema");
        export_profile::record_dump(start.elapsed(), 0);
        self.rows += 1;
        if self.rows == self.capacity {
            self.flush().await;
        }
    }

    pub(super) async fn flush(&mut self) {
        if self.rows == 0 {
            return;
        }
        let encoder = self.exporter.encoder.clone();
        // Reserve before spawning so a slow disk bounds both work and memory.
        // Sending the handle here preserves each shard's row order even when
        // later compression jobs finish first.
        if let Ok(permit) = self.exporter.jobs.reserve().await {
            let full = std::mem::take(&mut self.columns);
            permit.send(tokio::task::spawn_blocking(move || {
                let start = Instant::now();
                let group = encoder.encode(full)?;
                export_profile::record_write(start.elapsed());
                Ok(group)
            }));
        } else {
            // The writer returns the underlying error to the CLI.
            self.columns.clear();
        }
        self.rows = 0;
        self.capacity = (2 * self.capacity).min(MAX_GROUP_ROWS);
    }
}

impl<T> Drop for Shard<T> {
    fn drop(&mut self) {
        if self.rows != 0 || std::thread::panicking() {
            self.exporter
                .encoder
                .interrupted
                .store(true, Ordering::Relaxed);
        }
    }
}

fn write_groups(
    mut file: SerializedFileWriter<File>,
    mut jobs: mpsc::Receiver<GroupJob>,
    encoder: Arc<Encoder>,
) -> Result<()> {
    let runtime = tokio::runtime::Handle::current();
    while let Some(job) = jobs.blocking_recv() {
        let encoded = runtime.block_on(job).context("Parquet encoder failed")??;
        let start = Instant::now();
        let mut group = file.next_row_group()?;
        for column in encoded.columns {
            group.append_column(&encoded.bytes, column)?;
        }
        group.close()?;
        export_profile::record_write(start.elapsed());
    }
    let start = Instant::now();
    ensure!(
        !encoder.interrupted.load(Ordering::Relaxed),
        "Parquet shard stopped before its final flush"
    );
    file.finish()?;
    export_profile::record_write(start.elapsed());
    export_profile::record_file_bytes(file.bytes_written());
    Ok(())
}

pub(super) fn spawn<T: Flow>(
    file: File,
    headers: &str,
    clean: bool,
) -> Result<(FlowExporter<T>, JoinHandle<Result<()>>)> {
    let mut layout = Layout::default();
    let ip = Ipv4Addr::UNSPECIFIED.into();
    project(
        &T::new(String::new(), ip, 0, ip, 0, 0, 0),
        clean,
        &mut layout,
    );
    ensure!(
        layout.types.len() == headers.split(',').count(),
        "flow header and field counts differ"
    );
    let fields: Vec<_> = headers
        .split(',')
        .zip(layout.types)
        .map(|(name, ty)| Field::new(name, ty, false))
        .collect();
    let schema = Schema::new(fields);
    // Keep row-group min/max for predicate pushdown. These short, flat chunks
    // typically contain one data page, so page-level indexes duplicate it.
    let mut properties = WriterProperties::builder()
        .set_compression(Compression::SNAPPY)
        .set_dictionary_enabled(false)
        .set_statistics_enabled(EnabledStatistics::Chunk)
        .set_offset_index_disabled(true);
    for f in &schema.fields {
        let path = f.name().as_str().into();
        match f.data_type() {
            DataType::Utf8 => properties = properties.set_column_dictionary_enabled(path, true),
            DataType::Int64 | DataType::Timestamp(..) => {
                properties = properties.set_column_encoding(path, Encoding::DELTA_BINARY_PACKED)
            }
            DataType::Float64 => {}
            _ => unreachable!("unsupported flow column type"),
        }
    }
    let mut properties = properties.build();
    add_encoded_arrow_schema_to_metadata(&schema, &mut properties);
    let properties = Arc::new(properties);
    let physical = ArrowSchemaConverter::new().convert(&schema)?;
    let file = SerializedFileWriter::new(file, physical.root_schema_ptr(), properties.clone())?;
    let encoder = Arc::new(Encoder {
        descriptors: physical.columns().to_vec(),
        properties,
        interrupted: AtomicBool::new(false),
    });
    // At most one queued group per available CPU, plus the group being written.
    let (jobs, receiver) = mpsc::channel(num_cpus::get());
    let writer = {
        let encoder = encoder.clone();
        tokio::task::spawn_blocking(move || write_groups(file, receiver, encoder))
    };
    let exporter = Exporter::<T> {
        encoder,
        jobs,
        project: if clean {
            |flow, row| flow.write_clean_fields(row)
        } else {
            |flow, row| flow.write_fields(row)
        },
    };
    Ok((FlowExporter::Parquet(exporter), writer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{flows::basic_flow::BasicFlow, output::FlowSink};

    #[tokio::test]
    async fn an_interrupted_shard_cannot_finalize_a_partial_file() {
        let (exporter, writer) = spawn::<BasicFlow>(
            tempfile::tempfile().unwrap(),
            &BasicFlow::get_features(),
            false,
        )
        .unwrap();
        let mut shard = exporter.shard_output();
        let ip = Ipv4Addr::LOCALHOST.into();
        shard
            .export(BasicFlow::new(String::new(), ip, 0, ip, 0, 0, 0))
            .await;
        drop(shard);
        drop(exporter);
        assert!(writer.await.unwrap().is_err());
    }
}
