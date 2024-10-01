use std::{
    fs::File,
    io::{BufWriter, Write}
};
use crate::{args::ExportMethodType, flows::flow::Flow};
use log::{debug, error};

pub struct OutputWriter<T> {
    write_header: bool,
    skip_contaminant_features: bool,
    writer: BufWriter<Box<dyn Write + Send>>,
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
        let writer: BufWriter<Box<dyn Write + Send>> = match export_type {
            ExportMethodType::Csv => {
                let path = file_path.clone().expect("File path required for CSV output");
                let file = File::create(&path).expect("Failed to create file");
                BufWriter::new(Box::new(file))
            }
            ExportMethodType::Print => BufWriter::new(Box::new(std::io::stdout())),
        };

        OutputWriter {
            write_header,
            skip_contaminant_features,
            writer,
            _phantom_data: std::marker::PhantomData,
        }
    }

    pub fn init(&mut self) {
        debug!("Initializing output writer");
        if self.write_header {
            if let Err(e) = self.write_header() {
                error!("Error writing header: {}", e);
            }
        }
        debug!("Output writer initialized");
    }

    pub fn write_flow(&mut self, flow: T) -> std::io::Result<()> {
        debug!("Writing flow to output");
        let flow_str = if self.skip_contaminant_features {
            flow.dump_without_contamination()
        } else {
            flow.dump()
        };
    
        writeln!(self.writer, "{}", flow_str)
    }

    /// Flushes the writer and closes the output file
    /// Explicitly called in the main function to ensure all data is written
    pub fn flush_and_close(&mut self) -> std::io::Result<()> {
        self.writer.flush() // Ensure all data is written
    }

    // Private method for writing the header
    fn write_header(&mut self) -> std::io::Result<()> {
        debug!("Writing header to output");
        let header = if self.skip_contaminant_features {
            T::get_features_without_contamination()
        } else {
            T::get_features()
        };
        writeln!(self.writer, "{}", header)
    }
}
