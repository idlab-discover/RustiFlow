use chrono::{DateTime, Utc};
use std::{fmt::Write, net::IpAddr};

/// A borrowed field in the exporter's established column order.
pub enum Value<'a> {
    Integer(i64),
    Float(f64),
    Text(&'a str),
    Address(IpAddr),
    Timestamp(DateTime<Utc>),
}

macro_rules! integer_values {
    ($($ty:ty),+) => { $(
        impl From<$ty> for Value<'_> {
            fn from(value: $ty) -> Self { Self::Integer(value.into()) }
        }
    )+ };
}
integer_values!(i8, u8, i16, u16, i32, u32, i64);

impl From<f64> for Value<'_> {
    fn from(value: f64) -> Self {
        Self::Float(value)
    }
}
impl<'a> From<&'a str> for Value<'a> {
    fn from(value: &'a str) -> Self {
        Self::Text(value)
    }
}
impl From<IpAddr> for Value<'_> {
    fn from(value: IpAddr) -> Self {
        Self::Address(value)
    }
}
impl From<DateTime<Utc>> for Value<'_> {
    fn from(value: DateTime<Utc>) -> Self {
        Self::Timestamp(value)
    }
}

pub trait Record {
    fn append(&mut self, value: Value<'_>);
    fn field<'a>(&mut self, value: impl Into<Value<'a>>) {
        self.append(value.into());
    }
}

/// Append directly to the encoder's chunk, tracking separators per record.
pub struct CsvRow<'a> {
    chunk: &'a mut String,
    first: bool,
}
impl<'a> CsvRow<'a> {
    pub fn new(chunk: &'a mut String) -> Self {
        Self { chunk, first: true }
    }
}
impl Record for CsvRow<'_> {
    fn append(&mut self, value: Value<'_>) {
        if !self.first {
            self.chunk.push(',');
        }
        self.first = false;
        match value {
            Value::Integer(n) => push_i64_digits(self.chunk, n),
            Value::Float(n) => append_float(self.chunk, n),
            Value::Text(s) => self.chunk.push_str(s),
            Value::Address(ip) => write!(self.chunk, "{ip}").expect("writing to String"),
            Value::Timestamp(ts) => write!(self.chunk, "{ts}").expect("writing to String"),
        }
    }
}
/// Largest magnitude below which every integral `f64` converts to `i64` exactly.
const EXACT_INTEGER_F64_LIMIT: f64 = 9_007_199_254_740_992.0; // 2^53

/// Appends `value` as a CSV field, byte-identical to its `Display` output.
///
/// `Display` renders integral floats without a fractional part (`3`, `-0`), so
/// integral values take the much cheaper integer formatter. Most exported
/// statistics (lengths, counts, totals, empty stats) are integral. Negative zero
/// keeps the float path because `-0` has no `i64` representation.
fn append_float(output: &mut String, value: f64) {
    // The round trip through i64 tests integrality without a libm `trunc` call;
    // NaN fails the range check.
    let integer = value as i64;
    if value.abs() < EXACT_INTEGER_F64_LIMIT
        && integer as f64 == value
        && !(value == 0.0 && value.is_sign_negative())
    {
        push_i64_digits(output, integer);
    } else {
        let _ = write!(output, "{value}");
    }
}

/// Appends the decimal form of `value`, matching its `Display` output without
/// going through the `fmt` machinery.
fn push_i64_digits(output: &mut String, value: i64) {
    if value < 0 {
        output.push('-');
    }
    let mut remaining = value.unsigned_abs();
    let mut digits = [0u8; 20]; // u64::MAX has 20 decimal digits
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }
    output.extend(digits[start..].iter().map(|&digit| char::from(digit)));
}

macro_rules! fields {
    ($row:expr, $($value:expr),+ $(,)?) => {
        $( $row.field($value); )+
    };
}
pub(crate) use fields;
