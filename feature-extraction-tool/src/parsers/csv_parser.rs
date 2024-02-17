use super::parser::ReadError;
use csv::{ReaderBuilder, StringRecord, Trim};
use serde::de::DeserializeOwned;
use std::collections::HashSet;
use std::fs::File;

pub struct CsvParser;

fn preprocess_headers(headers: &StringRecord) -> (StringRecord, HashSet<usize>) {
    let mut unique_headers = StringRecord::new();
    let mut seen = HashSet::new();
    let mut indices = HashSet::new();

    for (index, header) in headers.iter().enumerate() {
        let trimmed_header = header.trim();
        if !seen.contains(trimmed_header) {
            unique_headers.push_field(trimmed_header);
            seen.insert(trimmed_header);
            indices.insert(index);
        }
    }

    (unique_headers, indices)
}

fn filter_record(record: &StringRecord, indices: &HashSet<usize>) -> StringRecord {
    let mut filtered = StringRecord::new();
    for (index, field) in record.iter().enumerate() {
        if indices.contains(&index) {
            filtered.push_field(field);
        }
    }
    filtered
}

impl CsvParser {
    pub fn parse<T>(
        &self,
        file_path: &str,
    ) -> Result<Box<dyn Iterator<Item = Result<T, ReadError>>>, ReadError>
    where
        T: DeserializeOwned + 'static,
    {
        let file = File::open(file_path).map_err(ReadError::Io)?;
        let mut rdr = ReaderBuilder::new().trim(Trim::All).from_reader(file);

        let headers = rdr.headers()?.clone();
        let (unique_headers, indices) = preprocess_headers(&headers);

        rdr.set_headers(unique_headers.clone());

        let iter = rdr.into_records().map(move |result| {
            result.map_err(ReadError::Csv).and_then(|record| {
                let filtered_record = filter_record(&record, &indices);

                csv::StringRecord::deserialize(&filtered_record, Some(&unique_headers))
                    .map_err(ReadError::Csv)
            })
        });

        Ok(Box::new(iter))
    }
}
