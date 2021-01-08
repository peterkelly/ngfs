#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::fmt;

pub trait FromBinary {
    type Output;

    fn from_binary(reader: &mut BinaryReader) -> Result<Self::Output, Box<dyn std::error::Error>>;
}

pub enum BinaryReadError {
    UnexpectedEOF { offset: usize, expected: usize },
    SizeOverflow { offset: usize, requested: usize },
    ExpectedEOF { offset: usize, remaining: usize },
    NothingConsumed { offset: usize },
}

impl fmt::Display for BinaryReadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BinaryReadError::UnexpectedEOF { offset, expected } => {
                write!(f, "Unexpcted EOF at offset {}; expected {} bytes", offset, expected)
            }
            BinaryReadError::SizeOverflow { offset, requested } => {
                write!(f, "Arithmetic overflow at offset {}; requested {} bytes", offset, requested)
            }
            BinaryReadError::ExpectedEOF { offset, remaining } => {
                write!(f, "Unexpected additional {} bytes at offset {}", remaining, offset)
            }
            BinaryReadError::NothingConsumed { offset } => {
                write!(f, "Reader consumed no data at offset {}", offset)
            }
        }
    }
}

impl fmt::Debug for BinaryReadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::error::Error for BinaryReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

pub struct BinaryReader<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> BinaryReader<'a> {
    pub fn new<'x>(buf: &'x [u8]) -> BinaryReader<'x> {
        BinaryReader {
            buf: buf,
            offset: 0,
        }
    }

    fn new_at<'x>(buf: &'x [u8], offset: usize) -> BinaryReader<'x> {
        BinaryReader {
            buf: buf,
            offset: offset,
        }
    }

    pub fn abs_offset(&self) -> usize {
        self.offset
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.offset)
    }

    pub fn remaining_data(&self) -> &[u8] {
        &self.buf[self.offset..]
    }

    pub fn expect_eof(&self) -> Result<(), BinaryReadError> {
        let remaining = self.remaining();
        if remaining > 0 {
            Err(BinaryReadError::ExpectedEOF { offset: self.offset, remaining: remaining })
        }
        else {
            Ok(())
        }
    }

    fn check_available(&self, size: usize) -> Result<usize, BinaryReadError> {
        match self.offset.checked_add(size) {
            Some(next) if next <= self.buf.len() => Ok(next),
            Some(_) => Err(BinaryReadError::UnexpectedEOF { offset: self.offset, expected: size }),
            None => Err(BinaryReadError::SizeOverflow { offset: self.offset, requested: size }),
        }
    }

    pub fn read_nested(&mut self, size: usize) -> Result<BinaryReader, BinaryReadError> {
        let end = self.check_available(size)?;
        let res = BinaryReader::new_at(&self.buf[0..end], self.offset);
        self.offset = end;
        Ok(res)
    }

    pub fn read_fixed(&mut self, size: usize) -> Result<&[u8], BinaryReadError> {
        let end = self.check_available(size)?;
        let res = &self.buf[self.offset..end];
        self.offset = end;
        Ok(res)
    }

    pub fn read_u8(&mut self) -> Result<u8, BinaryReadError> {
        let next = self.check_available(1)?;
        let res = self.buf[self.offset];
        self.offset = next;
        Ok(res)
    }

    pub fn read_u16(&mut self) -> Result<u16, BinaryReadError> {
        let next = self.check_available(2)?;
        let mut bytes: [u8; 2] = Default::default();
        bytes.copy_from_slice(&self.buf[self.offset..next]);
        self.offset = next;
        Ok(u16::from_be_bytes(bytes))
    }

    pub fn read_u24(&mut self) -> Result<u32, BinaryReadError> {
        let next = self.check_available(3)?;
        let mut bytes: [u8; 4] = [
            0,
            self.buf[self.offset],
            self.buf[self.offset + 1],
            self.buf[self.offset + 2]];
        self.offset = next;
        Ok(u32::from_be_bytes(bytes))
    }

    pub fn read_u32(&mut self) -> Result<u32, BinaryReadError> {
        let next = self.check_available(4)?;
        let mut bytes: [u8; 4] = Default::default();
        bytes.copy_from_slice(&self.buf[self.offset..next]);
        self.offset = next;
        Ok(u32::from_be_bytes(bytes))
    }

    pub fn read_u64(&mut self) -> Result<u64, BinaryReadError> {
        let next = self.check_available(8)?;
        let mut bytes: [u8; 8] = Default::default();
        bytes.copy_from_slice(&self.buf[self.offset..next]);
        self.offset = next;
        Ok(u64::from_be_bytes(bytes))
    }

    pub fn read_item<T : FromBinary<Output = T>>(&mut self) -> Result<T, Box<dyn std::error::Error>> {
        T::from_binary(self)
    }

    pub fn read_len8_list<T : FromBinary<Output = T>>(&mut self) -> Result<Vec<T>, Box<dyn std::error::Error>> {
        let len = self.read_u8()? as usize;
        self.read_fixed_list(len)
    }

    pub fn read_len16_list<T : FromBinary<Output = T>>(&mut self) -> Result<Vec<T>, Box<dyn std::error::Error>> {
        let len = self.read_u16()? as usize;
        self.read_fixed_list(len)
    }

    fn read_fixed_list<T : FromBinary<Output = T>>(&mut self, len: usize) -> Result<Vec<T>, Box<dyn std::error::Error>> {
        let mut inner = self.read_nested(len)?;
        let mut res: Vec<T> = Vec::new();
        while inner.remaining() > 0 {
            let old_offset = inner.offset;
            res.push(T::from_binary(&mut inner)?);
            let new_offset = inner.offset;
            if old_offset == new_offset {
                return Err(BinaryReadError::NothingConsumed { offset: old_offset }.into())
            }
        }
        Ok(res)
    }
}
