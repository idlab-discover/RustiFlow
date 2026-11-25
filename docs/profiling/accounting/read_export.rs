//! Read the closed RustiFlow fixture file, including any incidental flows.
use std::error::Error;
use std::{env, fs::File};

use parquet::file::reader::{FileReader, SerializedFileReader};

fn main() -> Result<(), Box<dyn Error>> {
    let reader = SerializedFileReader::new(File::open(
        env::args_os().nth(1).ok_or("expected Parquet path")?,
    )?)?;
    if reader
        .metadata()
        .file_metadata()
        .schema_descr()
        .num_columns()
        != 203
    {
        return Err("expected full 203-column RustiFlow export".into());
    }
    let schema = reader
        .metadata()
        .file_metadata()
        .schema_descr()
        .root_schema();
    let columns = [
        "ip_version",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "protocol",
        "packet_count",
        "packet_len_total",
        "payload_len_total",
    ];
    let fields: Vec<_> = schema
        .get_fields()
        .iter()
        .filter(|field| columns.contains(&field.name()))
        .cloned()
        .collect();
    if fields.len() != columns.len() {
        return Err("missing RustiFlow export columns".into());
    }
    let projection = parquet::schema::types::Type::group_type_builder(schema.name())
        .with_fields(fields)
        .build()?;
    for row in reader.get_row_iter(Some(projection))? {
        let row = row?;
        for (index, (name, value)) in row.get_column_iter().enumerate() {
            if index > 0 {
                print!("\t");
            }
            print!("{name}={value}");
        }
        println!();
    }
    Ok(())
}
