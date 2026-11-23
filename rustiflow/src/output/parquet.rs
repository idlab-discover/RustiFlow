use std::{fmt::Write as _, fs::File, net::Ipv4Addr, sync::Arc, time::Instant};

use anyhow::{ensure, Result};
use arrow_array::{
    builder::{Float64Builder, Int64Builder, StringBuilder, TimestampMicrosecondBuilder},
    ArrayRef, RecordBatch,
};
use arrow_schema::{DataType, Field, Schema, SchemaRef, TimeUnit};
use parquet::{arrow::ArrowWriter, basic::Compression, file::properties::WriterProperties};
use tokio::sync::mpsc;

use super::project;
use crate::{
    export_profile,
    flows::{
        flow::Flow,
        row::{Record, Value},
    },
};

const BATCH_ROWS: usize = 1024;
const ROW_GROUP_ROWS: usize = 8192;

enum Column {
    Integer(Int64Builder),
    Float(Float64Builder),
    Text(StringBuilder),
    Timestamp(TimestampMicrosecondBuilder),
}

impl Column {
    fn finish(&mut self) -> ArrayRef {
        match self {
            Self::Integer(b) => Arc::new(b.finish()),
            Self::Float(b) => Arc::new(b.finish()),
            Self::Text(b) => Arc::new(b.finish()),
            Self::Timestamp(b) => Arc::new(b.finish()),
        }
    }
}

// Export projections have fixed arity and Rust types for each feature set.
// Visit one empty flow at startup so even a zero-record file has its schema.
#[derive(Default)]
struct Layout {
    types: Vec<DataType>,
    columns: Vec<Column>,
}

impl Record for Layout {
    fn append(&mut self, value: Value<'_>) {
        let (ty, column) = match value {
            Value::Integer(_) => (DataType::Int64, Column::Integer(Int64Builder::new())),
            Value::Float(_) => (DataType::Float64, Column::Float(Float64Builder::new())),
            Value::Address(_) | Value::Text(_) => {
                (DataType::Utf8, Column::Text(StringBuilder::new()))
            }
            Value::Timestamp(_) => (
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                Column::Timestamp(TimestampMicrosecondBuilder::new().with_timezone("UTC")),
            ),
        };
        self.types.push(ty);
        self.columns.push(column);
    }
}

struct BatchRow<'a>(std::slice::IterMut<'a, Column>);

impl Record for BatchRow<'_> {
    fn append(&mut self, value: Value<'_>) {
        match (self.0.next(), value) {
            (Some(Column::Integer(b)), Value::Integer(n)) => b.append_value(n),
            (Some(Column::Float(b)), Value::Float(n)) => b.append_value(n),
            (Some(Column::Timestamp(b)), Value::Timestamp(ts)) => {
                b.append_value(ts.timestamp_micros())
            }
            (Some(Column::Text(b)), Value::Text(s)) => b.append_value(s),
            (Some(Column::Text(b)), Value::Address(ip)) => {
                write!(b, "{ip}").expect("writing address to string builder");
                b.append_value("");
            }
            _ => unreachable!("flow projection must match its schema"),
        }
    }
}

pub(super) struct Writer {
    file: ArrowWriter<File>,
    schema: SchemaRef,
    columns: Vec<Column>,
}

impl Writer {
    pub(super) fn new<T: Flow>(file: File, headers: &str, clean: bool) -> Result<Self> {
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
        let schema = Arc::new(Schema::new(fields));
        let properties = WriterProperties::builder()
            .set_compression(Compression::SNAPPY)
            .set_max_row_group_row_count(Some(ROW_GROUP_ROWS))
            .build();
        let file = ArrowWriter::try_new(file, schema.clone(), Some(properties))?;
        Ok(Self {
            file,
            schema,
            columns: layout.columns,
        })
    }

    fn write_batch(&mut self) -> Result<()> {
        let start = Instant::now();
        let arrays = self.columns.iter_mut().map(Column::finish).collect();
        self.file
            .write(&RecordBatch::try_new(self.schema.clone(), arrays)?)?;
        export_profile::record_write(start.elapsed());
        Ok(())
    }

    pub(super) fn run<T: Flow>(
        mut self,
        mut receiver: mpsc::Receiver<T>,
        clean: bool,
    ) -> Result<()> {
        let mut rows = 0;
        let mut flows = Vec::with_capacity(super::ENCODER_FLOW_BATCH);
        while receiver.blocking_recv_many(&mut flows, super::ENCODER_FLOW_BATCH) > 0 {
            for flow in &flows {
                let start = Instant::now();
                let mut row = BatchRow(self.columns.iter_mut());
                project(flow, clean, &mut row);
                ensure!(row.0.len() == 0, "flow has fewer fields than its schema");
                export_profile::record_dump(start.elapsed(), 0);
                rows += 1;
                if rows == BATCH_ROWS {
                    self.write_batch()?;
                    rows = 0;
                }
            }
            flows.clear();
        }
        if rows > 0 {
            self.write_batch()?;
        }
        let start = Instant::now();
        self.file.finish()?;
        export_profile::record_write(start.elapsed());
        export_profile::record_file_bytes(self.file.bytes_written());
        Ok(())
    }
}
