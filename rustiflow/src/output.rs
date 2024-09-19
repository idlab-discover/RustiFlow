use std::{
    fs::File,
    io::{BufWriter, Write}
};
use tokio::sync::mpsc::Receiver;
use crate::{args::ExportMethodType, flows::flow::Flow};
use log::{debug, error};

pub struct OutputWriter<T> {
    export_type: ExportMethodType,
    write_header: bool,
    skip_contaminant_features: bool,
    receiver: Receiver<T>,
    file_path: Option<String>,
}

impl<T> OutputWriter<T>
where
    T: Flow,
{
    pub fn new(
        export_type: ExportMethodType,
        write_header: bool,
        skip_contaminant_features: bool,
        receiver: Receiver<T>,
        file_path: Option<String>,
    ) -> Self {
        OutputWriter {
            export_type,
            write_header,
            skip_contaminant_features,
            receiver,
            file_path,
        }
    }

    pub async fn run(mut self) {
        match self.export_type {
            ExportMethodType::Csv => {
                let path = self.file_path.clone().unwrap();
                let file = File::create(&path).expect("Failed to create file");
                let mut writer = BufWriter::new(file);

                if self.write_header {
                    if let Err(e) = self.write_header(&mut writer) {
                        error!("Error writing header to file: {}", e);
                    }
                }

                while let Some(flow) = self.receiver.recv().await {
                    if let Err(e) = self.write_flow(&mut writer, flow) {
                        error!("Error writing to file: {}", e);
                    }
                }

                debug!("OutputWriter finishing up");
                
                if let Err(e) = writer.flush() {
                    error!("Error flushing writer: {}", e);
                    debug!("Exported to file: {}", path);
                }
            }
            ExportMethodType::Print => {
                if self.write_header {
                    if let Err(e) = self.write_header(&mut std::io::stdout()) {
                        error!("Error writing header to stdout: {}", e);
                    }
                }

                while let Some(flow) = self.receiver.recv().await {
                    if let Err(e) = self.write_flow(&mut std::io::stdout(), flow) {
                        error!("Error writing to stdout: {}", e);
                    }
                }
            }
        }
    }

    // Private method for writing the header
    fn write_header<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let header = if self.skip_contaminant_features {
            T::get_features_without_contamination()
        } else {
            T::get_features()
        };
        writeln!(writer, "{}", header)
    }

    // Private method for appending a flow
    fn write_flow<W: std::io::Write>(&self, writer: &mut W, flow: T) -> std::io::Result<()> {
        let message = if self.skip_contaminant_features {
            flow.dump_without_contamination()
        } else {
            flow.dump()
        };
        writeln!(writer, "{}", message)
    }
}
