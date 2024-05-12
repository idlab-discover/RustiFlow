use std::{fs::File, io::BufWriter};

pub fn print(output: &str, _writer: &mut Option<BufWriter<File>>, _flush_counter: &mut u8) {
    println!("{}", output);
}
