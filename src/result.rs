use std::fmt;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Clone)]
pub struct Error {
    msg: String,
}

impl Error {
    pub fn new<T: Into<String>>(msg: T) -> Box<Error> {
        Box::new(Error { msg: msg.into() })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

pub fn error<S, T: Into<String>>(msg: T) -> Result<S> {
    Err(Box::new(Error { msg: msg.into() }))
}
