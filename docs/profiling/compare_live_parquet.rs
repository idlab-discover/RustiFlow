use std::{collections::BTreeMap, env, fs::File};

use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::record::Field;

fn timing(name: &str) -> bool {
    name.contains("timestamp")
        || name.contains("duration")
        || name.contains("iat")
        || name.contains("active_")
        || name.contains("idle_")
        || name.ends_with("_s")
}

fn main() {
    let mut inputs = env::args_os().skip(1);
    let mut read = || {
        let reader =
            SerializedFileReader::new(File::open(inputs.next().unwrap()).unwrap()).unwrap();
        let schema = reader
            .metadata()
            .file_metadata()
            .schema_descr()
            .root_schema()
            .clone();
        let mut rows = BTreeMap::new();
        for row in reader.get_row_iter(None).unwrap() {
            let row = row.unwrap();
            assert_eq!(row.len(), 203);
            let id = row
                .get_column_iter()
                .find(|(name, _)| name.as_str() == "flow_id")
                .unwrap()
                .1
                .to_string();
            let selected: BTreeMap<String, Field> = row
                .get_column_iter()
                .filter(|(name, _)| !timing(name))
                .map(|(name, field)| (name.clone(), field.clone()))
                .collect();
            assert!(rows.insert(id, selected).is_none());
        }
        (schema, rows)
    };
    let baseline = read();
    let candidate = read();
    assert_eq!(baseline, candidate);
    assert_eq!(baseline.1.len(), 6);
    for (flow, row) in &baseline.1 {
        println!(
            "{flow}: {:?} fields, protocol={} packets={}",
            row.len(),
            row["protocol"],
            row["packet_count"]
        );
    }
}
