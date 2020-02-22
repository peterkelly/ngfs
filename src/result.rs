use std::fmt;

pub type GResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Clone)]
pub struct GError {
    msg: String,
}

impl GError {
    pub fn new<T: Into<String>>(msg: T) -> Box<GError> {
        Box::new(GError { msg: msg.into() })
    }
}

impl fmt::Display for GError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl std::error::Error for GError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}
