use crate::{args::ExportMethodType, flows::flow::Flow};
use log::{debug, error};
use polars::prelude::{DataFrame, Series, AnyValue, NamedFrom, ParquetWriter, PolarsError, DataType, TimeUnit};
use std::fs::File;
use std::io::{BufWriter, Write};

pub struct OutputWriter<T> {
    export_type: ExportMethodType, // Store the export type
    write_header: bool,
    skip_contaminant_features: bool,
    // For Print/Csv
    buffered_writer: Option<BufWriter<Box<dyn Write + Send>>>,
    // For Polars/Pandas
    feature_names: Option<Vec<String>>,
    polars_rows: Option<Vec<Vec<AnyValue<'static>>>>,
    export_path: Option<String>, // Store export path for Parquet/JSON

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
        let mut buffered_writer_instance = None;
        if export_type == ExportMethodType::Print || export_type == ExportMethodType::Csv {
            let writer_target: Box<dyn Write + Send> = match export_type {
                ExportMethodType::Csv => {
                    let path_str = file_path.as_ref().expect("File path required for CSV output");
                    Box::new(std::fs::File::create(path_str).expect("Failed to create CSV file"))
                }
                ExportMethodType::Print => Box::new(std::io::stdout()),
                _ => unreachable!(), // Should not happen due to if condition
            };
            buffered_writer_instance = Some(BufWriter::new(writer_target));
        }

        OutputWriter {
            export_type,
            write_header,
            skip_contaminant_features,
            buffered_writer: buffered_writer_instance,
            feature_names: None,
            polars_rows: if export_type == ExportMethodType::Polars || export_type == ExportMethodType::Pandas {
                Some(Vec::new())
            } else {
                None
            },
            export_path: file_path,
            _phantom_data: std::marker::PhantomData,
        }
    }

    pub fn init(&mut self) {
        debug!("Initializing output writer for type: {:?}", self.export_type);
        if self.export_type == ExportMethodType::Print || self.export_type == ExportMethodType::Csv {
            if self.write_header {
                if let Err(e) = self.write_header_for_csv() { // Renamed for clarity
                    error!("Error writing CSV header: {}", e);
                }
            }
        } else if (self.export_type == ExportMethodType::Polars || self.export_type == ExportMethodType::Pandas) && self.write_header {
            // For Parquet, if header is requested, we need to know the feature names
            // even if no flows are processed. This ensures an empty Parquet with correct schema can be written.
            if self.feature_names.is_none() {
                let features_str = if self.skip_contaminant_features {
                    T::get_features_without_contamination()
                } else {
                    T::get_features()
                };
                self.feature_names = Some(features_str.split(',').map(String::from).collect());
                debug!("Initialized feature_names for Parquet header (no flows yet).");
            }
        }
        debug!("Output writer initialized");
    }

    pub fn write_flow(&mut self, flow: T) -> std::io::Result<()> {
        match self.export_type {
            ExportMethodType::Print | ExportMethodType::Csv => {
                let flow_str = if self.skip_contaminant_features {
                    flow.dump_without_contamination()
                } else {
                    flow.dump()
                };
                if let Some(writer) = self.buffered_writer.as_mut() {
                    writeln!(writer, "{}", flow_str)
                } else {
                    Err(std::io::Error::new(std::io::ErrorKind::Other, "Writer not initialized for Print/CSV"))
                }
            }
            ExportMethodType::Polars | ExportMethodType::Pandas => {
                if self.feature_names.is_none() {
                    let features_str = if self.skip_contaminant_features {
                        T::get_features_without_contamination()
                    } else {
                        T::get_features()
                    };
                    self.feature_names = Some(features_str.split(',').map(String::from).collect());
                }
                if let Some(rows) = self.polars_rows.as_mut() {
                    rows.push(flow.to_polars_row());
                }
                Ok(()) // Data is buffered, actual write happens in flush_and_close
            }
        }
    }

    // Helper for Parquet
    fn finalize_parquet_output(&mut self) -> Result<(), PolarsError> {
        let export_path_str = self.export_path.as_ref().ok_or_else(|| PolarsError::ComputeError("Export path not set for Parquet output".into()))?;

        let feature_names = self.feature_names.as_ref().ok_or_else(|| PolarsError::ComputeError("Feature names not set (no flows processed?)".into()))?;

        let rows = self.polars_rows.as_ref().ok_or_else(|| PolarsError::ComputeError("No rows to write for Parquet".into()))?;

        if rows.is_empty() && self.write_header { // Only write empty schema if header was requested
            let mut series_vec: Vec<Series> = Vec::new();
            for name in feature_names {
                // Default to Utf8 for empty Series schema. This might need refinement if specific types are known a priori.
                series_vec.push(Series::new_empty(name, &DataType::Utf8));
            }
            let mut df = DataFrame::new(series_vec)?;
            let file = File::create(export_path_str).map_err(|e| PolarsError::ComputeError(format!("Failed to create Parquet file: {}", e).into()))?;
            ParquetWriter::new(file).finish(&mut df)?;
            return Ok(());
        }  else if rows.is_empty() {
            // No header requested and no data, so write nothing or an empty file based on desired behavior
            debug!("No data to write to Parquet and header not requested.");
            return Ok(());
        }


        let num_columns = feature_names.len();
        let mut polars_series_vec: Vec<Series> = Vec::with_capacity(num_columns);

        for col_idx in 0..num_columns {
            let col_name = &feature_names[col_idx];
            let mut col_values: Vec<AnyValue> = Vec::with_capacity(rows.len());
            for row in rows.iter() { // Iterate over reference to rows
                if col_idx < row.len() {
                    col_values.push(row[col_idx].clone()); // clone AnyValue
                } else {
                    // This case implies a row has fewer columns than expected by feature_names.
                    // This could happen if to_polars_row() is inconsistent.
                    error!("Row has fewer columns than feature names. Col: {}, Index: {}, Row Len: {}", col_name, col_idx, row.len());
                    col_values.push(AnyValue::Null);
                }
            }

            // Attempt to create series, handling potential type inference issues
            // Polars defaults to Float64 for mixed numerics or if it can't infer; be explicit if needed
            let mut series = Series::from_any_values_strict(col_name, &col_values, false).map_err(|e| {
                // Log detailed error for debugging type issues
                // For example, log first few values and their types
                // let problematic_values: Vec<String> = col_values.iter().take(5).map(|av| format!("{:?}", av.dtype())).collect();
                // error!("Failed to create series for column '{}'. Values: {:?}. Error: {}", col_name, problematic_values, e);
                PolarsError::SchemaMismatch(format!("Failed to create series for column '{}': {}. Ensure all values in this column are of a consistent type or handle nulls appropriately.", col_name, e).into())
            })?;


            // Special handling for timestamp columns to cast to Datetime
            // Assuming timestamp columns from BasicFlow are named "first_timestamp" and "last_timestamp"
            // In BasicFlow::get_features, they are "first_timestamp" and "last_timestamp"
            // CicFlow uses "Timestamp" (first_timestamp from BasicFlow)
            // NfFlow uses "bidirectional_first_seen_ms", "bidirectional_last_seen_ms", etc. (these are already i64 ms)
            // RustiFlow uses "timestamp_first", "timestamp_last" (these are i64 us)
            if (col_name == "first_timestamp" || col_name == "last_timestamp" || col_name == "timestamp_first" || col_name == "timestamp_last")
                && series.dtype() == &DataType::Int64 {
                if let Ok(s_int) = series.i64() {
                    match s_int.cast_with_options(&DataType::Datetime(TimeUnit::Microseconds, None), true) {
                        Ok(casted_series) => series = casted_series.into_series(),
                        Err(e) => error!("Failed to cast timestamp column '{}' to Datetime[us]: {}", col_name, e),
                    }
                }
            } else if (col_name.ends_with("_ms") && col_name.contains("seen")) // For NfFlow's ms timestamps
                 && series.dtype() == &DataType::Int64 {
                 if let Ok(s_int) = series.i64() {
                    match s_int.cast_with_options(&DataType::Datetime(TimeUnit::Milliseconds, None), true) {
                        Ok(casted_series) => series = casted_series.into_series(),
                        Err(e) => error!("Failed to cast ms timestamp column '{}' to Datetime[ms]: {}", col_name, e),
                    }
                }
            }
            // Add more specific type casting here if needed for other columns based on feature_names
            // e.g., if a column is known to be purely UInt32 but might contain Nulls, etc.

            polars_series_vec.push(series);
        }

        let mut df = DataFrame::new(polars_series_vec)?;
        let file = File::create(export_path_str).map_err(|e| PolarsError::ComputeError(format!("Failed to create Parquet file: {}", e).into()))?;
        ParquetWriter::new(file).finish(&mut df)?;
        Ok(())
    }


    pub fn flush_and_close(&mut self) -> std::io::Result<()> {
        match self.export_type {
            ExportMethodType::Print | ExportMethodType::Csv => {
                if let Some(writer) = self.buffered_writer.as_mut() {
                    writer.flush()
                } else {
                    Ok(()) // No writer to flush
                }
            }
            ExportMethodType::Polars | ExportMethodType::Pandas => {
                match self.finalize_parquet_output() {
                    Ok(_) => Ok(()),
                    Err(e) => {
                        error!("Error writing Parquet file: {}", e);
                        Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Parquet finalization error: {}",e)))
                    }
                }
            }
        }
    }

    // Private method for writing the header
    fn write_header_for_csv(&mut self) -> std::io::Result<()> {
        if let Some(writer) = self.buffered_writer.as_mut() {
            debug!("Writing header to output");
            let header = if self.skip_contaminant_features {
                T::get_features_without_contamination()
            } else {
                T::get_features()
            };
            writeln!(writer, "{}", header)
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::Other, "Writer not initialized for CSV header"))
        }
    }

    pub fn write_inter_flow_deltas(&mut self, deltas: &[i64]) -> std::io::Result<()> {
        if self.export_type == ExportMethodType::Print || self.export_type == ExportMethodType::Csv {
            if let Some(writer) = self.buffered_writer.as_mut() {
                if deltas.is_empty() {
                    writeln!(writer, "INTER_FLOW_DELTAS_US,[]")
                } else {
                    let deltas_str: Vec<String> = deltas.iter().map(|d| d.to_string()).collect();
                    writeln!(writer, "INTER_FLOW_DELTAS_US,[{}]", deltas_str.join(","))
                }
            } else {
                 Err(std::io::Error::new(std::io::ErrorKind::Other, "Writer not initialized for Print/CSV"))
            }
        } else {
            Ok(()) // Handled separately for Polars/Pandas in main.rs
        }
    }

    pub fn write_all_flow_durations(&mut self, durations: &[i64]) -> std::io::Result<()> {
        if self.export_type == ExportMethodType::Print || self.export_type == ExportMethodType::Csv {
             if let Some(writer) = self.buffered_writer.as_mut() {
                if durations.is_empty() {
                    writeln!(writer, "ALL_FLOW_DURATIONS_US,[]")
                } else {
                    let durations_str: Vec<String> = durations.iter().map(|d| d.to_string()).collect();
                    writeln!(writer, "ALL_FLOW_DURATIONS_US,[{}]", durations_str.join(","))
                }
            } else {
                Err(std::io::Error::new(std::io::ErrorKind::Other, "Writer not initialized for Print/CSV"))
            }
        } else {
            Ok(()) // Handled separately for Polars/Pandas in main.rs
        }
    }
}
