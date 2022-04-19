//! Custom error type for all errors types that binsec might encounter
use std::error::Error;
use std::fmt::{self, Display};

pub type FuzzResult<R> = Result<R, FuzzError>;

#[derive(Debug)]
pub struct FuzzError(pub String);

impl FuzzError {
    pub fn new(msg: &str) -> Self {
        Self(msg.to_string())
    }
}

impl Display for FuzzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "\"{}\"", self.0)
    }
}

impl From<std::io::Error> for FuzzError {
    fn from(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}

impl From<goblin::error::Error> for FuzzError {
    fn from(error: goblin::error::Error) -> Self {
        Self(error.to_string())
    }
}

impl Error for FuzzError {}
