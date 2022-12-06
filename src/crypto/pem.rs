use std::fmt;
use std::error::Error;
use crate::ipfs::types::multibase::{decode_noprefix, encode_noprefix, Base};

pub enum PEMError {
    Plain(&'static str),
    String(String),
    LabelMismatch(String, String),
}

impl fmt::Display for PEMError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PEMError::Plain(e) => write!(f, "{}", e),
            PEMError::String(e) => write!(f, "{}", e),
            PEMError::LabelMismatch(begin, end) => {
                write!(f, "Label mismatch: {:?} and {:?}",
                    format!("BEGIN {}", begin),
                    format!("END {}", end))
            }
        }
    }
}

impl fmt::Debug for PEMError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl Error for PEMError {
}

struct Parser<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Parser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Parser {
            data,
            offset: 0,
        }
    }

    fn current(&self) -> Option<u8> {
        self.data.get(self.offset).copied()
    }

    fn advance(&mut self) {
        self.offset += 1
    }

    fn expect_dashes(&mut self) -> Result<usize, PEMError> {
        let mut dash_count = 0;
        while let Some(b'-') = self.current() {
            self.advance();
            dash_count += 1;
        }
        if dash_count == 0 {
            Err(PEMError::Plain("Expected '"))
        }
        else {
            Ok(dash_count)
        }
    }

    fn expect_space(&mut self) -> Result<(), PEMError> {
        if let Some(b' ') = self.current() {
            self.advance();
            Ok(())
        }
        else {
            Err(PEMError::Plain("Expected ' '"))
        }
    }

    fn expect_newline(&mut self) -> Result<(), PEMError> {
        if let Some(b'\r') = self.current() {
            self.advance();
        }
        if let Some(b'\n') = self.current() {
            self.advance();
            Ok(())
        }
        else {
            Err(PEMError::Plain("Expected newline"))
        }
    }

    fn expect_string(&mut self, s: &str) -> Result<(), PEMError> {
        let expect_bytes = s.as_bytes();
        let mut expect_index = 0;
        while let Some(b) = expect_bytes.get(expect_index).copied() {
            if let Some(b2) = self.current() {
                if b == b2 {
                    expect_index += 1;
                    self.advance();
                }
                else {
                    return Err(PEMError::String(format!("Expected {:?}", s)));
                }
            }
        }
        Ok(())
    }

    fn read_label(&mut self) -> Result<String, PEMError> {
        let start_offset = self.offset;
        while let Some(b) = self.current() {
            match b {
                b'A'..=b'Z' | b' ' => self.advance(),
                _ => break,
            }
        }
        let end_offset = self.offset;
        let s: String = String::from_utf8(Vec::from(&self.data[start_offset..end_offset]))
            .map_err(|_| PEMError::Plain("Invalid UTF-8 label"))?;
        Ok(s)
    }

    fn expect_end(&mut self) -> Result<(), PEMError> {
        if self.offset == self.data.len() {
            Ok(())
        }
        else {
            Err(PEMError::Plain("Expected EOF"))
        }
    }

    fn read_base64(&mut self) -> Result<Vec<u8>, PEMError> {
        let mut base64_data: Vec<u8> = Vec::new();
        while let Some(b) = self.current() {
            match b {
                b'A'..=b'Z' |
                b'a'..=b'z' |
                b'0'..=b'9' |
                b'+' | b'/' | b'=' => {
                    base64_data.push(b);
                    self.advance();
                }
                b'\r' | b'\n' => {
                    self.advance();
                }
                b'-' => {
                    break;
                }
                _ => {
                    return Err(PEMError::String(format!("Expected base64-encoded data, got {}", b)))
                }
            }
        }
        Ok(base64_data)
    }
}

pub fn decode_pem(input_bytes: &[u8]) -> Result<(String, Vec<u8>), PEMError> {
    let mut parser = Parser::new(input_bytes);

    // Header
    parser.expect_dashes()?;
    parser.expect_string("BEGIN")?;
    parser.expect_space()?;
    let begin_label = parser.read_label()?;
    parser.expect_dashes()?;
    parser.expect_newline()?;

    // Body
    let base64_data = parser.read_base64()?;

    // Footer
    parser.expect_dashes()?;
    parser.expect_string("END")?;
    parser.expect_space()?;
    let end_label = parser.read_label()?;
    parser.expect_dashes()?;
    parser.expect_newline()?;
    parser.expect_end()?;

    let base64_str = String::from_utf8(base64_data)
        .map_err(|_| PEMError::Plain("Invalid UTF-8"))?;
    let decoded = decode_noprefix(&base64_str, Base::Base64Pad)
        .map_err(|_| PEMError::Plain("Invalid base64 data"))?;

    if begin_label != end_label {
        Err(PEMError::LabelMismatch(begin_label, end_label))
    }
    else {
        Ok((begin_label, decoded))
    }

}

pub fn decode_pem_with_label(input_bytes: &[u8], label: &str) -> Result<Vec<u8>, PEMError> {
    let (actual_label, data) = decode_pem(input_bytes)?;
    if actual_label != label {
        Err(PEMError::String(format!("Expected {}, got {}", label, actual_label)))
    }
    else {
        Ok(data)
    }
}

pub fn encode_pem(data: &[u8], label: &str) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();
    result.extend_from_slice(b"-----BEGIN ");
    result.extend_from_slice(label.as_bytes());
    result.extend_from_slice(b"-----\n");
    let base64_str = encode_noprefix(data, Base::Base64Pad);
    let base64_data = base64_str.as_bytes();
    let mut offset = 0;
    while offset < base64_data.len() {
        let remaining = std::cmp::min(64, base64_data.len() - offset);
        result.extend_from_slice(&base64_data[offset..offset + remaining]);
        result.push(b'\n');
        offset += remaining;
    }
    result.extend_from_slice(b"-----END ");
    result.extend_from_slice(label.as_bytes());
    result.extend_from_slice(b"-----\n");
    result
}
