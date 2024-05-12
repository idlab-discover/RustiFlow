use std::{
    fs::File,
    io::{BufWriter, Write},
};

pub fn export_to_csv(output: &str, writer: &mut Option<BufWriter<File>>, flush_counter: &mut u8) {
    if let Some(writer) = writer {
        writeln!(writer, "{}", output).unwrap();

        *flush_counter += 1;

        if *flush_counter >= 10 {
            let _ = writer.flush();
            *flush_counter = 0;
        }
    } else {
        eprintln!("Error: No writer found for CSV output");
    }
}
