pub mod bencoding;
pub mod util;
pub mod torrent;
pub mod protobuf;
pub mod detrand;
pub mod multibase;
pub mod cid;
pub mod p2p;
pub mod hmac;
pub mod binary;
pub mod tls;
pub mod asn1;
pub mod x509;
pub mod crypt;
pub mod libp2p;
pub mod ipfs;
pub mod io;

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
