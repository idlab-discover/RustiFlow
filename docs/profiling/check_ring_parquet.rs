use std::{collections::BTreeMap, env, fs, path::Path};

use parquet::{
    file::reader::{FileReader, SerializedFileReader},
    record::Field,
};

fn stable_field(name: &str) -> bool {
    !name.contains("timestamp")
        && !name.contains("duration")
        && !name.contains("iat")
        && !name.contains("active_")
        && !name.contains("idle_")
        && !name.ends_with("_s")
}

fn read_micros(dir: &Path, name: &str) -> i64 {
    fs::read_to_string(dir.join(name))
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn main() {
    let args: Vec<_> = env::args().collect();
    assert_eq!(
        args.len(),
        4,
        "usage: check_ring_parquet CASE BASE_DIR EXP_DIR"
    );
    let case = &args[1];
    let read = |dir: &Path| {
        let reader =
            SerializedFileReader::new(fs::File::open(dir.join("flows.parquet")).unwrap()).unwrap();
        let schema = reader
            .metadata()
            .file_metadata()
            .schema_descr()
            .root_schema()
            .clone();
        let start = read_micros(dir, "send-start.us");
        let end = read_micros(dir, "send-end.us");
        let last_window = if case == "backlog" {
            read_micros(dir, "tail-start.us")..=read_micros(dir, "tail-end.us")
        } else {
            start..=end
        };
        let mut flows = BTreeMap::new();
        let mut packet_counts = Vec::new();
        for row in reader.get_row_iter(None).unwrap() {
            let row = row.unwrap();
            assert_eq!(row.len(), 203);
            let all: BTreeMap<_, _> = row
                .get_column_iter()
                .map(|(name, field)| (name.as_str(), field))
                .collect();
            let (Field::TimestampMicros(first), Field::TimestampMicros(last)) =
                (all["timestamp_first"], all["timestamp_last"])
            else {
                panic!("expected microsecond timestamps");
            };
            assert!(
                (start..=end).contains(first),
                "{dir:?}: first timestamp {first}"
            );
            assert!(
                last_window.contains(last) && first <= last,
                "{dir:?}: last timestamp {last}"
            );
            let count = all["packet_count"].to_string().parse::<u64>().unwrap();
            packet_counts.push(count);
            if case == "fair" && count == 1 {
                println!("{} cold_timestamp_us={last}", dir.display());
            }
            let id = all["flow_id"].to_string();
            let stable: BTreeMap<_, _> = all
                .into_iter()
                .filter(|(name, _)| stable_field(name))
                .map(|(name, field)| (name.to_owned(), field.clone()))
                .collect();
            assert!(flows.insert(id, stable).is_none());
        }
        packet_counts.sort_unstable();
        let expected: &[u64] = match case.as_str() {
            "low" => &[1, 1, 3, 3, 6, 6],
            "backlog" => &[50_001, 50_001],
            "pressure" => &[838_860, 1_398_101],
            "ordered" => &[2053, 2053],
            "fair" => &[1, 250_000],
            _ => panic!("unknown case {case}"),
        };
        assert_eq!(packet_counts, expected);
        (schema, flows)
    };

    let (base_schema, base) = read(Path::new(&args[2]));
    let (test_schema, test) = read(Path::new(&args[3]));
    assert_eq!(base_schema, test_schema);
    assert_eq!(base.len(), test.len());
    for (id, fields) in &base {
        let other = &test[id];
        for (name, value) in fields {
            assert_eq!(value, &other[name], "{id} field {name}");
        }
    }
    println!(
        "{case}: 203 columns, {} flows, {} stable fields per flow",
        base.len(),
        base.values().next().unwrap().len()
    );
}
