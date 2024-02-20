use csv::Error as CsvError;
use serde::de::DeserializeOwned;
use std::io;

#[derive(Debug)]
pub enum ReadError {
    Io(io::Error),
    Csv(CsvError),
}

impl From<io::Error> for ReadError {
    fn from(err: io::Error) -> Self {
        ReadError::Io(err)
    }
}

impl From<CsvError> for ReadError {
    fn from(err: CsvError) -> Self {
        ReadError::Csv(err)
    }
}

pub trait Parser {
    fn parse<T>(
        &self,
        file_path: &str,
    ) -> Result<Box<dyn Iterator<Item = Result<T, ReadError>>>, ReadError>
    where
        T: DeserializeOwned + 'static;
}
