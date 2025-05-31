use rustiflow::args::{ExportMethodType, OutputConfig};
use rustiflow::flows::basic_flow::BasicFlow;
use rustiflow::flows::flow::Flow; // To access Flow trait methods like get_features, to_polars_row
use rustiflow::output::OutputWriter;
use polars::prelude::*;
use std::net::{IpAddr, Ipv4Addr};
use std::fs::File;
use tempfile::Builder; // For creating temporary files/directories
use serde_json::json; // For testing JSON output

// Helper function to create a sample BasicFlow
fn create_sample_basic_flow(id: &str, start_time: i64, packet_sizes: Vec<i32>) -> BasicFlow {
    let mut flow = BasicFlow::new(
        id.to_string(),
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        12345,
        IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
        80,
        6, // TCP
        start_time,
    );
    flow.last_timestamp_us = start_time + 1_000_000; // 1 second duration
    flow.packet_sizes = packet_sizes;
    flow
}

#[test]
fn test_basic_flow_to_polars_row_structure() {
    let flow = create_sample_basic_flow("flow1", 1000, vec![60, 120]);
    let row_values = flow.to_polars_row();
    let feature_names: Vec<&str> = BasicFlow::get_features().split(',').collect();

    assert_eq!(row_values.len(), feature_names.len(), "Number of values should match number of features");

    // Check a few specific AnyValue types (more thorough checks would be in DataFrame construction)
    if let AnyValue::Utf8Owned(val) = &row_values[0] { // flow_id (assuming Utf8Owned due to String conversion)
        assert_eq!(&**val, "flow1");
    } else { panic!("flow_id was not Utf8Owned, it was {:?}", row_values[0]); }


    if let AnyValue::Int64(val) = &row_values[6] { // first_timestamp
        assert_eq!(*val, 1000);
    } else { panic!("first_timestamp was not Int64"); }

    if let AnyValue::List(series) = &row_values[feature_names.len()-1] { // packet_sizes (last column)
         assert_eq!(series.dtype(), &DataType::List(Box::new(DataType::Int32)));
         assert_eq!(series.len(), 1, "List Series should contain one list for the row");
         // Further checks on list content would require more unwrapping
    } else { panic!("packet_sizes was not AnyValue::List"); }
}


#[test]
fn test_dataframe_construction_and_schema() {
    let flow1 = create_sample_basic_flow("f1", 1000, vec![10, 20]);
    let flow2 = create_sample_basic_flow("f2", 2000, vec![30, -40, 50]);

    let polars_rows = vec![flow1.to_polars_row(), flow2.to_polars_row()];
    let feature_names_str = BasicFlow::get_features();
    let feature_names: Vec<String> = feature_names_str.split(',').map(String::from).collect();

    let num_columns = feature_names.len();
    let mut polars_series_vec: Vec<Series> = Vec::with_capacity(num_columns);

    for col_idx in 0..num_columns {
        let col_name = &feature_names[col_idx];
        let mut col_values: Vec<AnyValue> = Vec::with_capacity(polars_rows.len());
        for row in &polars_rows {
            col_values.push(row[col_idx].clone());
        }

        let mut series = Series::from_any_values(col_name, &col_values, false).expect("Failed to create series");

        if col_name == "first_timestamp" || col_name == "last_timestamp" {
            if let Ok(s_int) = series.i64() {
                series = s_int.cast_with_options(&DataType::Datetime(TimeUnit::Microseconds, None), true)
                              .expect("Cast to Datetime failed").into_series();
            }
        }
        polars_series_vec.push(series);
    }

    let df = DataFrame::new(polars_series_vec).expect("Failed to create DataFrame");

    assert_eq!(df.shape(), (2, feature_names.len()), "DataFrame shape mismatch");
    assert_eq!(df.get_column_names(), feature_names.iter().map(|s| s.as_str()).collect::<Vec<&str>>());

    // Check dtypes
    assert_eq!(df.column("flow_id").unwrap().dtype(), &DataType::Utf8);
    assert_eq!(df.column("first_timestamp").unwrap().dtype(), &DataType::Datetime(TimeUnit::Microseconds, None));
    assert_eq!(df.column("packet_sizes").unwrap().dtype(), &DataType::List(Box::new(DataType::Int32)));
    assert_eq!(df.column("source_port").unwrap().dtype(), &DataType::UInt16); // Example
}

#[test]
fn test_parquet_write_read_cycle() {
    let temp_dir = Builder::new().prefix("rustiflow_test").tempdir().unwrap();
    let file_path = temp_dir.path().join("test_output.parquet");

    // Create a sample DataFrame (similar to test_dataframe_construction_and_schema)
    let flow1 = create_sample_basic_flow("f1", 1000, vec![10, 20]);
    let flow2 = create_sample_basic_flow("f2", 2000, vec![30, -40, 50]);
    let rows = vec![flow1.to_polars_row(), flow2.to_polars_row()];
    let features: Vec<String> = BasicFlow::get_features().split(',').map(String::from).collect();
    let mut series_list: Vec<Series> = Vec::new();
    for i in 0..features.len() {
        let col_name = &features[i];
        let values: Vec<AnyValue> = rows.iter().map(|row| row[i].clone()).collect();
        let mut s = Series::from_any_values(col_name, &values, false).unwrap();
        if col_name == "first_timestamp" || col_name == "last_timestamp" {
             s = s.cast(&DataType::Datetime(TimeUnit::Microseconds, None)).unwrap();
        }
        series_list.push(s);
    }
    let mut df = DataFrame::new(series_list).unwrap();

    // Write to Parquet
    let file = File::create(&file_path).expect("Could not create temp parquet file");
    ParquetWriter::new(file).finish(&mut df).expect("Writing Parquet failed");

    // Read from Parquet
    let read_df = LazyFrame::scan_parquet(&file_path, Default::default())
        .expect("Scanning Parquet failed")
        .collect()
        .expect("Collecting LazyFrame failed");

    assert!(df.equals(&read_df), "DataFrames are not equal after write/read cycle");
}

#[test]
fn test_empty_dataframe_to_parquet() {
    let temp_dir = Builder::new().prefix("rustiflow_empty_test").tempdir().unwrap();
    let file_path = temp_dir.path().join("empty_output.parquet");

    let mut output_writer = OutputWriter::<BasicFlow>::new(
        ExportMethodType::Polars, // or Pandas
        true, // write_header is true
        false,
        Some(file_path.to_str().unwrap().to_string()),
    );
    // No calls to output_writer.write_flow()
    output_writer.init(); // Should populate feature_names if first flow was processed, but not here.
                          // Manually set feature_names for empty case as write_flow isn't called
    let features_str = BasicFlow::get_features();
    // output_writer.feature_names = Some(features_str.split(',').map(String::from).collect());
    // The above line refers to a private field. Instead, we rely on the internal logic
    // of flush_and_close (via finalize_parquet_output) to handle this.
    // To make this test work as intended for an empty DataFrame with schema,
    // we need to ensure feature_names is populated. This typically happens if at least one
    // flow is processed, or if init took care of it for Parquet (which it doesn't directly).
    // For this test, let's simulate that `feature_names` would have been set
    // by processing at least one (even if hypothetical) flow's features.
    // This is a bit of a workaround for testing this specific OutputWriter state.
    // A more direct way would be if `init` for Polars also stored feature_names.

    // Simulate feature_names being set (as if one flow was processed to get headers)
    // This is tricky because feature_names is private. The test for OutputWriter
    // should ideally rely on its public API.
    // The current OutputWriter populates feature_names on the *first* call to write_flow.
    // If no flows are written, feature_names remains None.
    // finalize_parquet_output has a check for this and would error if feature_names is None.
    // Let's adjust the test to reflect that if rows is empty AND feature_names is None, it's an error.
    // Or, if write_header is true, it should still try to write schema.

    // To test the "empty with schema" case, we need feature_names to be set.
    // Let's assume OutputWriter's init or first write_flow (even if it's an empty flow list later)
    // correctly sets this.
    // For this test, we'll manually ensure feature_names is set inside the writer by writing a dummy flow
    // and then clearing rows, or by having init set it. Since init doesn't for parquet,
    // we'll rely on the behavior that if write_header is true, an empty schema'd file should be made.
    // The new OutputWriter code handles this: if rows.is_empty() && self.write_header ...
    // It will use self.feature_names. If that's None (because no flow was ever processed),
    // it will error. So, for this test to pass as "empty schema written",
    // feature_names must be populated. The easiest way in OutputWriter's current design
    // is to process one dummy flow to have `feature_names` set, then clear `polars_rows`
    // before `flush_and_close`. But that's not what this test is for.
    // The test should verify `OutputWriter`'s behavior given its state.

    // The logic in `finalize_parquet_output` is:
    // `let feature_names = self.feature_names.as_ref().ok_or_else(...)`
    // So, if `feature_names` is `None`, it's an error. It becomes `Some` on first `write_flow`.
    // If `write_flow` is never called, `polars_rows` is `Some([])` and `feature_names` is `None`.
    // This will error out in `finalize_parquet_output` before checking `rows.is_empty() && self.write_header`.

    // Let's refine the test: if write_header is true, feature_names MUST be available.
    // This implies that for Polars/Pandas, if write_header is true, we expect a schema.
    // If no flows are processed, OutputWriter must still get feature names from T::get_features().
    // The `init` method should probably store feature_names for Polars/Pandas if write_header is true.
    // Let's adjust `OutputWriter::init` for this. (This will be a fix in the next step if test fails)

    // For now, assuming current OutputWriter logic:
    // If no flows are processed, feature_names is None. finalize_parquet_output will error.
    // This test should expect an error, or we modify OutputWriter.
    // Given the subtask, let's assume the goal is to test the "empty but schema-valid parquet"
    // This implies feature_names *are* known.

    // Re-evaluating the test based on current OutputWriter:
    // If no `write_flow` calls, `feature_names` is `None`. `finalize_parquet_output` will return error.
    // So, `flush_and_close` will return `Err`.
    // This test should check for that *or* we assume `init` is changed to set `feature_names` for Polars if `write_header` is true.
    // The prompt implies `OutputWriter` should handle this.
    // The `finalize_parquet_output` has `if rows.is_empty() && self.write_header`.
    // This path is only taken if `feature_names` was already successfully unwrapped.
    // So, `init` *must* set `feature_names` for Polars/Pandas if `write_header` is true.

    // **Proposed change for OutputWriter::init() to make this test pass as intended:**
    // ```rust
    // pub fn init(&mut self) {
    //     debug!("Initializing output writer for type: {:?}", self.export_type);
    //     if self.export_type == ExportMethodType::Print || self.export_type == ExportMethodType::Csv {
    //         if self.write_header {
    //             if let Err(e) = self.write_header_for_csv() {
    //                 error!("Error writing CSV header: {}", e);
    //             }
    //         }
    //     } else if (self.export_type == ExportMethodType::Polars || self.export_type == ExportMethodType::Pandas) && self.write_header {
    //         if self.feature_names.is_none() { // Should always be None here if init is called first
    //             let features_str = if self.skip_contaminant_features {
    //                 T::get_features_without_contamination()
    //             } else {
    //                 T::get_features()
    //             };
    //             self.feature_names = Some(features_str.split(',').map(String::from).collect());
    //         }
    //     }
    //     debug!("Output writer initialized");
    // }
    // ```
    // Assuming the above change is made to OutputWriter, this test will then proceed.
    // For now, I'll write the test assuming `init` correctly sets `feature_names` if `write_header` is true.
    // This means `output_writer.init()` call is crucial.
    output_writer.init(); // This should now set feature_names for Polars if write_header is true.


    let result = output_writer.flush_and_close();
    assert!(result.is_ok(), "Flushing empty Parquet failed: {:?}", result.err());
    assert!(file_path.exists(), "Empty Parquet file was not created");

    // Try to read it and check schema
    let read_df_result = LazyFrame::scan_parquet(&file_path, Default::default());
    assert!(read_df_result.is_ok(), "Scanning empty Parquet failed: {:?}", read_df_result.err());
    if let Ok(lazy_frame) = read_df_result {
        let schema = lazy_frame.schema().expect("Could not get schema from empty Parquet");
        let expected_features: Vec<String> = BasicFlow::get_features().split(',').map(String::from).collect();
        assert_eq!(schema.len(), expected_features.len(), "Schema field count mismatch");
        for name in expected_features {
            assert!(schema.get_field(&name).is_some(), "Expected field {} not in schema", name);
             // Default type for empty schema in OutputWriter is Utf8
            assert_eq!(schema.get_field(&name).unwrap().data_type(), &DataType::Utf8, "Field {} has wrong type", name);
        }
    }
}


// Test for global stats JSON - this would be called from main.rs context
// but we can test the serialization logic here.
#[derive(serde::Serialize)] // Copied from main.rs for test
struct GlobalStatsTest<'a> {
    inter_flow_deltas_us: &'a [i64],
    all_flow_durations_us: &'a [i64],
}

#[test]
fn test_global_stats_json_serialization() {
    let deltas = vec![100i64, 200, 300];
    let durations = vec![1000i64, 1500, 500];
    let stats = GlobalStatsTest {
        inter_flow_deltas_us: &deltas,
        all_flow_durations_us: &durations,
    };

    let json_string = serde_json::to_string_pretty(&stats).expect("JSON serialization failed");

    let expected_json = json!({
        "inter_flow_deltas_us": [100, 200, 300],
        "all_flow_durations_us": [1000, 1500, 500]
    });
    let expected_string = serde_json::to_string_pretty(&expected_json).unwrap();

    assert_eq!(json_string, expected_string);
}
