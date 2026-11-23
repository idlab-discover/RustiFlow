use std::{
    fs::{self, File},
    path::Path,
    process::Command,
};

use arrow_array::{Array, Float64Array, Int64Array, StringArray, TimestampMicrosecondArray};
use arrow_schema::DataType;
use chrono::DateTime;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

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

#[cfg(target_os = "linux")]
#[test]
fn replay_drains_multiple_row_groups_and_the_partial_tail() {
    let dir = tempfile::tempdir().unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_rustiflow"))
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
