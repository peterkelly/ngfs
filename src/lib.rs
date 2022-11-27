pub mod tls;
pub mod libp2p;
pub mod ipfs;
pub mod sim;
pub mod quic;
pub mod formats;
pub mod util;
pub mod crypto;
pub mod bittorrent;

use std::fmt;
use std::error::Error;

#[derive(Clone)]
pub struct StringError {
    msg: String,
}

impl StringError {
    pub fn new<T: Into<String>>(msg: T) -> Box<StringError> {
        Box::new(StringError { msg: msg.into() })
    }
}

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl fmt::Debug for StringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl Error for StringError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {{
        let res = $crate::StringError::new(std::fmt::format(std::format_args!($($arg)*)));
        res
    }}
}
