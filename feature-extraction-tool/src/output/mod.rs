use std::{fs::File, io::BufWriter};

pub type Export = fn(&str, &mut Option<BufWriter<File>>, &mut u8) -> ();
pub mod csv;
pub mod print;
