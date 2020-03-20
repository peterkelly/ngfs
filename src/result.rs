use std::fmt;
use std::error::Error;

#[derive(Clone)]
pub struct GeneralError {
    msg: String,
}

impl GeneralError {
    pub fn new<T: Into<String>>(msg: T) -> Box<GeneralError> {
        Box::new(GeneralError { msg: msg.into() })
    }
}

impl fmt::Display for GeneralError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl fmt::Debug for GeneralError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl Error for GeneralError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

pub fn general_error<S, T: Into<String>>(msg: T) -> Result<S, Box<dyn Error>> {
    Err(Box::new(GeneralError { msg: msg.into() }))
}
