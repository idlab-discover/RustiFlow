mod args;
mod parsers;
mod records;

use core::panic;

use args::{Cli, Commands, Dataset};
use clap::Parser;

use crate::{
    parsers::csv_parser::CsvParser,
    records::{cic_record::CicRecord, print::Print},
};

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Realtime => {
            handle_realtime();
        }
        Commands::Dataset { dataset, path } => {
            handle_dataset(dataset, &path);
        }
    }
}

fn handle_realtime() {
    println!("Real-time feature extraction");
}

fn handle_dataset(dataset: Dataset, path: &str) {
    println!(
        "Dataset feature extraction for {:?} from path: {}",
        dataset, path
    );

    match dataset {
        Dataset::CicIds2017 => {
            if path.ends_with(".csv") {
                let parser = CsvParser;

                match parser.parse::<CicRecord>(path) {
                    Ok(records) => {
                        for record in records {
                            match record {
                                Ok(record) => {
                                    record.print();
                                }
                                Err(err) => {
                                    // TODO: Will we output to stderr, drop the record or use default values?
                                    eprintln!("Error: {:?}", err);
                                }
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!("Error: {:?}", err);
                    }
                }
            } else if path.ends_with(".pcap") {
                panic!("This file format is not supported yet...");

            } else if path.ends_with(".parquet") {
                panic!("This file format is not supported yet...");
                
            } else {
                panic!("This file format is not supported...");
            }
        }
        _ => {
            panic!("This is not implemented yet...");
        }
    }
}
