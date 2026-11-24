use std::{
    fs::{self, File},
    path::Path,
    process::Command,
    sync::Arc,
};

use arrow_array::{Array, Float64Array, Int64Array, StringArray, TimestampMicrosecondArray};
use arrow_schema::DataType;
use chrono::DateTime;
use parquet::{
    arrow::arrow_reader::ParquetRecordBatchReaderBuilder,
    basic::Compression,
    data_type::DoubleType,
    file::{
        properties::{EnabledStatistics, WriterProperties},
        statistics::Statistics,
        writer::SerializedFileWriter,
    },
    schema::parser::parse_message_type,
};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/data/nmap_tcp_syn_version.pcap"
);

fn capture(dir: &Path, args: &[&str], pcap: &str) {
    let result = Command::new(env!("CARGO_BIN_EXE_rustiflow"))
        .current_dir(dir)
        .args(args)
        .args(["--threads", "1", "pcap", pcap])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn csv_field(column: &dyn Array, row: usize) -> String {
    let array = column.as_any();
    match column.data_type() {
        DataType::Utf8 => array
            .downcast_ref::<StringArray>()
            .unwrap()
            .value(row)
            .into(),
        DataType::Int64 => array
            .downcast_ref::<Int64Array>()
            .unwrap()
            .value(row)
            .to_string(),
        DataType::Float64 => array
            .downcast_ref::<Float64Array>()
            .unwrap()
            .value(row)
            .to_string(),
        DataType::Timestamp(_, _) => DateTime::from_timestamp_micros(
            array
                .downcast_ref::<TimestampMicrosecondArray>()
                .unwrap()
                .value(row),
        )
        .unwrap()
        .to_string(),
        unexpected => panic!("unexpected field type {unexpected}"),
    }
}

#[test]
fn default_parquet_matches_csv_for_every_feature_set_and_projection() {
    for feature in ["basic", "cic", "cidds", "nfstream", "rustiflow", "custom"] {
        for clean in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let mut args = vec!["-f", feature];
            if clean {
                args.push("--drop-contaminant-features");
            }
            capture(dir.path(), &args, FIXTURE);
            args.extend(["-o", "csv", "--export-path", "check.csv", "--header"]);
            capture(dir.path(), &args, FIXTURE);

            let csv = fs::read_to_string(dir.path().join("check.csv")).unwrap();
            let mut lines = csv.lines();
            let reader = ParquetRecordBatchReaderBuilder::try_new(
                File::open(dir.path().join("output.parquet")).unwrap(),
            )
            .unwrap();
            let names = reader
                .schema()
                .fields()
                .iter()
                .map(|f| f.name().as_str())
                .collect::<Vec<_>>();
            assert_eq!(names.join(","), lines.next().unwrap());
            if feature == "basic" && !clean {
                assert_eq!(
                    reader
                        .schema()
                        .field_with_name("source_port")
                        .unwrap()
                        .data_type(),
                    &DataType::Int64
                );
                assert_eq!(
                    reader
                        .schema()
                        .field_with_name("first_timestamp")
                        .unwrap()
                        .data_type(),
                    &DataType::Timestamp(arrow_schema::TimeUnit::Microsecond, Some("UTC".into()))
                );
            }
            let mut rows = Vec::new();
            for batch in reader.build().unwrap() {
                let batch = batch.unwrap();
                for row in 0..batch.num_rows() {
                    rows.push(
                        batch
                            .columns()
                            .iter()
                            .map(|col| csv_field(col.as_ref(), row))
                            .collect::<Vec<_>>()
                            .join(","),
                    );
                }
            }
            let mut expected: Vec<_> = lines.collect();
            expected.sort_unstable();
            rows.sort_unstable();
            assert!(!rows.is_empty());
            assert_eq!(rows, expected, "{feature}, clean={clean}");
        }
    }
}

#[test]
fn empty_capture_has_a_readable_schema_and_no_rows() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("empty.pcap"),
        &fs::read(FIXTURE).unwrap()[..24],
    )
    .unwrap();
    capture(
        dir.path(),
        &["-f", "basic", "--export-path", "empty.parquet"],
        "empty.pcap",
    );
    let reader = ParquetRecordBatchReaderBuilder::try_new(
        File::open(dir.path().join("empty.parquet")).unwrap(),
    )
    .unwrap();
    assert_eq!(reader.schema().fields().len(), 10);
    assert_eq!(reader.metadata().file_metadata().num_rows(), 0);
    assert_eq!(reader.build().unwrap().count(), 0);
}

#[test]
fn double_columns_preserve_value_bits_and_statistics_across_tails() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let schema = Arc::new(parse_message_type("message flow { REQUIRED DOUBLE value; }").unwrap());
    let properties = Arc::new(
        WriterProperties::builder()
            .set_compression(Compression::SNAPPY)
            .set_dictionary_enabled(false)
            .set_statistics_enabled(EnabledStatistics::Chunk)
            .set_offset_index_disabled(true)
            .build(),
    );
    let mut writer = SerializedFileWriter::new(file.reopen().unwrap(), schema, properties).unwrap();
    let nans = [
        f64::from_bits(0xfff8_0000_0000_0002),
        f64::from_bits(0x7ff0_0000_0000_0001),
        f64::from_bits(0x7ff8_0000_0000_0003),
    ];
    let patterns: [&[f64]; 4] = [
        &nans,
        &[0.0, -0.0, nans[0]],
        &[nans[1], f64::from_bits(1), -f64::from_bits(1)],
        &[0.25, -17.5, nans[2], f64::MIN, f64::MAX],
    ];
    let mut groups = Vec::new();
    for len in [
        1, 2, 3, 4, 31, 32, 33, 34, 35, 36, 511, 512, 513, 1023, 1024, 1025, 4095, 4096, 4097,
    ] {
        for pattern in patterns {
            groups.push(
                pattern
                    .iter()
                    .copied()
                    .cycle()
                    .take(len)
                    .collect::<Vec<_>>(),
            );
        }
        // The final full vector or scalar tail holds the only non-NaN values.
        let mut tail = vec![nans[0]; len];
        tail[len - 1] = f64::INFINITY;
        if len > 1 {
            tail[len - 2] = f64::NEG_INFINITY;
        }
        groups.push(tail);
    }
    for values in &groups {
        let mut group = writer.next_row_group().unwrap();
        let mut column = group.next_column().unwrap().unwrap();
        column
            .typed::<DoubleType>()
            .write_batch(values, None, None)
            .unwrap();
        column.close().unwrap();
        group.close().unwrap();
    }
    writer.close().unwrap();

    let reader = ParquetRecordBatchReaderBuilder::try_new(file.reopen().unwrap()).unwrap();
    assert_eq!(reader.metadata().num_row_groups(), groups.len());
    for (group, values) in reader.metadata().row_groups().iter().zip(&groups) {
        let column = group.column(0);
        assert_eq!(column.compression(), Compression::SNAPPY);
        let Some(Statistics::Double(stats)) = column.statistics() else {
            panic!("missing Double column statistics");
        };
        let nan_count = values.iter().filter(|v| v.is_nan()).count();
        let extrema = values
            .iter()
            .copied()
            .filter(|v| nan_count == values.len() || !v.is_nan());
        assert_eq!(stats.nan_count_opt(), Some(nan_count as u64));
        assert_eq!(
            (
                stats.min_opt().map(|v| v.to_bits()),
                stats.max_opt().map(|v| v.to_bits())
            ),
            (
                extrema.clone().min_by(f64::total_cmp).map(f64::to_bits),
                extrema.max_by(f64::total_cmp).map(f64::to_bits)
            ),
            "statistics for a {}-row group",
            values.len()
        );
    }
    let mut decoded = Vec::new();
    for batch in reader.build().unwrap() {
        let batch = batch.unwrap();
        let values = batch
            .column(0)
            .as_any()
            .downcast_ref::<Float64Array>()
            .unwrap();
        decoded.extend(values.values().iter().map(|v| v.to_bits()));
    }
    assert_eq!(
        decoded,
        groups
            .into_iter()
            .flatten()
            .map(f64::to_bits)
            .collect::<Vec<_>>()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn replay_drains_multiple_row_groups_and_the_partial_tail() {
    check_replay_parquet_tail(Command::new(env!("CARGO_BIN_EXE_rustiflow")));

    let mut recycling = Command::new(env!("CARGO_BIN_EXE_rustiflow"));
    recycling
        .env("RUSTIFLOW_EXPERIMENT_RECYCLE_SHARD_BATCHES", "1")
        .env("RUSTIFLOW_REALTIME_SHARD_BATCH_SIZE", "8")
        .env("RUSTIFLOW_REALTIME_SHARD_QUEUE_CAPACITY", "1")
        .env("RUSTIFLOW_REALTIME_SOURCE_DISPATCH_QUEUE_CAPACITY", "1");
    check_replay_parquet_tail(recycling);
}

#[cfg(target_os = "linux")]
fn check_replay_parquet_tail(mut command: Command) {
    let dir = tempfile::tempdir().unwrap();
    let result = command
        .current_dir(dir.path())
        .args([
            "-f",
            "nfstream",
            "--threads",
            "2",
            "replay-bench",
            "--ipv6",
            "--packets",
            "120000",
            "--flows",
            "10000",
            "--drain-burst",
            "257",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let reader = ParquetRecordBatchReaderBuilder::try_new(
        File::open(dir.path().join("output.parquet")).unwrap(),
    )
    .unwrap();
    assert!(reader.metadata().num_row_groups() > 1);
    let mut packets = 0;
    for batch in reader.build().unwrap() {
        let batch = batch.unwrap();
        let totals = batch
            .column_by_name("bidirectional_packets")
            .unwrap()
            .as_any()
            .downcast_ref::<Int64Array>()
            .unwrap();
        packets += totals.values().iter().sum::<i64>();
    }
    assert_eq!(packets, 120000);
}

#[test]
fn config_can_omit_output_and_implicit_path_preserves_existing_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("config.toml"), "[config]\nfeatures='Basic'\nactive_timeout=3600\nidle_timeout=120\nexpiration_check_interval=60\n").unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rustiflow"));
    cmd.current_dir(dir.path())
        .args(["-c", "config.toml", "pcap", FIXTURE]);
    assert!(cmd.output().unwrap().status.success());
    let file = dir.path().join("output.parquet");
    let contents = fs::read(&file).unwrap();
    assert!(!cmd.output().unwrap().status.success());
    assert_eq!(fs::read(file).unwrap(), contents);
}

#[cfg(target_os = "linux")]
#[test]
fn parquet_write_errors_reach_the_cli() {
    let result = Command::new(env!("CARGO_BIN_EXE_rustiflow"))
        .args([
            "-f",
            "rustiflow",
            "--threads",
            "2",
            "--export-path",
            "/dev/full",
            "pcap",
            FIXTURE,
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("No space left on device"));
}
