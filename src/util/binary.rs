use std::fmt;

pub trait FromBinary {
    type Output;

    fn from_binary(reader: &mut BinaryReader) -> Result<Self::Output, BinaryError>;
}

pub trait ToBinary {
    fn to_binary(&self, writer: &mut BinaryWriter) -> Result<(), Box<dyn std::error::Error>>;
}

pub enum BinaryError {
    Plain(&'static str),
    String(String),
    Other(Box<dyn std::error::Error>),
    InvalidUTF8String(std::string::FromUtf8Error),
    UnexpectedEOF { offset: usize, expected: usize },
    SizeOverflow { offset: usize, requested: usize },
    ExpectedEOF { offset: usize, remaining: usize },
    NothingConsumed { offset: usize },
    ValueTooLarge,
}

impl From<std::string::FromUtf8Error> for BinaryError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        BinaryError::InvalidUTF8String(e)
    }
}

impl fmt::Display for BinaryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BinaryError::Plain(e) => write!(f, "{}", e),
            BinaryError::String(e) => write!(f, "{}", e),
            BinaryError::Other(e) => write!(f, "{}", e),
            BinaryError::InvalidUTF8String(e) => write!(f, "{}", e),
            BinaryError::UnexpectedEOF { offset, expected } => {
                write!(f, "Unexpcted EOF at offset {}; expected {} bytes", offset, expected)
            }
            BinaryError::SizeOverflow { offset, requested } => {
                write!(f, "Arithmetic overflow at offset {}; requested {} bytes", offset, requested)
            }
            BinaryError::ExpectedEOF { offset, remaining } => {
                write!(f, "Unexpected additional {} bytes at offset {}", remaining, offset)
            }
            BinaryError::NothingConsumed { offset } => {
                write!(f, "Reader consumed no data at offset {}", offset)
            }
            BinaryError::ValueTooLarge => {
                write!(f, "Value too large")
            }
        }
    }
}

impl fmt::Debug for BinaryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::error::Error for BinaryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

pub struct BinaryReader<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> BinaryReader<'a> {
    pub fn new(buf: &[u8]) -> BinaryReader {
        BinaryReader { buf, offset: 0 }
    }

    pub fn new_at(buf: &[u8], offset: usize) -> BinaryReader {
        BinaryReader { buf, offset }
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

    pub fn expect_eof(&self) -> Result<(), BinaryError> {
        let remaining = self.remaining();
        if remaining > 0 {
            Err(BinaryError::ExpectedEOF { offset: self.offset, remaining })
        }
        else {
            Ok(())
        }
    }

    fn check_available(&self, size: usize) -> Result<usize, BinaryError> {
        match self.offset.checked_add(size) {
            Some(next) if next <= self.buf.len() => Ok(next),
            Some(_) => Err(BinaryError::UnexpectedEOF { offset: self.offset, expected: size }),
            None => Err(BinaryError::SizeOverflow { offset: self.offset, requested: size }),
        }
    }

    pub fn read_nested(&mut self, size: usize) -> Result<BinaryReader<'a>, BinaryError> {
        let end = self.check_available(size)?;
        let res = BinaryReader::new_at(&self.buf[0..end], self.offset);
        self.offset = end;
        Ok(res)
    }

    pub fn read_fixed(&mut self, size: usize) -> Result<&[u8], BinaryError> {
        let end = self.check_available(size)?;
        let res = &self.buf[self.offset..end];
        self.offset = end;
        Ok(res)
    }

    pub fn read_quic_varint(&mut self) -> Result<u64, BinaryError> {
        // https://www.rfc-editor.org/rfc/rfc9000.html#sample-varint
        //
        // The length of variable-length integers is encoded in the
        // first two bits of the first byte.
        let v = self.read_u8()?;
        let prefix = v >> 6;
        let length = 1 << prefix;

        // Once the length is known, remove these bits and read any
        // remaining bytes.
        let mut v = v as u64 & 0x3f;
        for _ in 0..length - 1 {
            v = (v << 8) + self.read_u8()? as u64;
        }
        Ok(v)
    }

    pub fn read_u8(&mut self) -> Result<u8, BinaryError> {
        let next = self.check_available(1)?;
        let res = self.buf[self.offset];
        self.offset = next;
        Ok(res)
    }

    pub fn read_u16(&mut self) -> Result<u16, BinaryError> {
        let next = self.check_available(2)?;
        let mut bytes: [u8; 2] = Default::default();
        bytes.copy_from_slice(&self.buf[self.offset..next]);
        self.offset = next;
        Ok(u16::from_be_bytes(bytes))
    }

    pub fn read_u24(&mut self) -> Result<u32, BinaryError> {
        let next = self.check_available(3)?;
        let bytes: [u8; 4] = [
            0,
            self.buf[self.offset],
            self.buf[self.offset + 1],
            self.buf[self.offset + 2]];
        self.offset = next;
        Ok(u32::from_be_bytes(bytes))
    }

    pub fn read_u32(&mut self) -> Result<u32, BinaryError> {
        let next = self.check_available(4)?;
        let mut bytes: [u8; 4] = Default::default();
        bytes.copy_from_slice(&self.buf[self.offset..next]);
        self.offset = next;
        Ok(u32::from_be_bytes(bytes))
    }

    pub fn read_u64(&mut self) -> Result<u64, BinaryError> {
        let next = self.check_available(8)?;
        let mut bytes: [u8; 8] = Default::default();
        bytes.copy_from_slice(&self.buf[self.offset..next]);
        self.offset = next;
        Ok(u64::from_be_bytes(bytes))
    }

    pub fn read_len8_bytes(&mut self) -> Result<&[u8], BinaryError> {
        let len = self.read_u8()? as usize;
        self.read_fixed(len)
    }

    pub fn read_len16_bytes(&mut self) -> Result<&[u8], BinaryError> {
        let len = self.read_u16()? as usize;
        self.read_fixed(len)
    }

    pub fn read_len24_bytes(&mut self) -> Result<&[u8], BinaryError> {
        let len = self.read_u24()? as usize;
        self.read_fixed(len)
    }

    pub fn read_item<T : FromBinary<Output = T>>(&mut self) -> Result<T, BinaryError> {
        T::from_binary(self)
    }

    pub fn read_len8_list<T : FromBinary<Output = T>>(&mut self) -> Result<Vec<T>, BinaryError> {
        let len = self.read_u8()? as usize;
        self.read_fixed_list(len)
    }

    pub fn read_len16_list<T : FromBinary<Output = T>>(&mut self) -> Result<Vec<T>, BinaryError> {
        let len = self.read_u16()? as usize;
        self.read_fixed_list(len)
    }

    pub fn read_len24_list<T : FromBinary<Output = T>>(&mut self) -> Result<Vec<T>, BinaryError> {
        let len = self.read_u24()? as usize;
        self.read_fixed_list(len)
    }

    fn read_fixed_list<T : FromBinary<Output = T>>(&mut self, len: usize) -> Result<Vec<T>, BinaryError> {
        let mut inner = self.read_nested(len)?;
        let mut res: Vec<T> = Vec::new();
        while inner.remaining() > 0 {
            let old_offset = inner.offset;
            res.push(T::from_binary(&mut inner)?);
            let new_offset = inner.offset;
            if old_offset == new_offset {
                return Err(BinaryError::NothingConsumed { offset: old_offset })
            }
        }
        Ok(res)
    }
}

pub struct BinaryWriter {
    data: Vec<u8>,
}

impl BinaryWriter {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn write_u8(&mut self, value: u8) {
        self.data.push(value);
    }

    pub fn write_u16(&mut self, value: u16) {
        self.data.extend_from_slice(&value.to_be_bytes());
    }

    pub fn write_u24(&mut self, value: u32) {
        self.data.extend_from_slice(&value.to_be_bytes()[1..4]);
    }

    pub fn write_u32(&mut self, value: u32) {
        self.data.extend_from_slice(&value.to_be_bytes());
    }

    pub fn write_u64(&mut self, value: u64) {
        self.data.extend_from_slice(&value.to_be_bytes());
    }

    pub fn write_quic_varint(&mut self, value: u64) {
        let mut value_bytes = value.to_be_bytes();
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc
        if value <= 63 {
            self.data.extend_from_slice(&value_bytes[7..8]);
        }
        else if value <= 16383 {
            value_bytes[6] |= 0x40;
            self.data.extend_from_slice(&value_bytes[6..8]);
        }
        else if value <= 1073741823 {
            value_bytes[4] |= 0x80;
            self.data.extend_from_slice(&value_bytes[4..8]);
        }
        else {
            value_bytes[0] |= 0xc0;
            self.data.extend_from_slice(&value_bytes[0..8]);
        }
    }

    pub fn write_raw(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    pub fn write_len8_bytes(&mut self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        if data.len() > u8::MAX as usize {
            Err(BinaryError::ValueTooLarge.into())
        }
        else {
            self.write_u8(data.len() as u8);
            self.data.extend_from_slice(data);
            Ok(())
        }
    }

    pub fn write_len16_bytes(&mut self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        if data.len() > u16::MAX as usize {
            Err(BinaryError::ValueTooLarge.into())
        }
        else {
            self.write_u16(data.len() as u16);
            self.data.extend_from_slice(data);
            Ok(())
        }
    }

    pub fn write_len24_bytes(&mut self, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        if data.len() >= 1 << 24 {
            Err(BinaryError::ValueTooLarge.into())
        }
        else {
            self.write_u24(data.len() as u32);
            self.data.extend_from_slice(data);
            Ok(())
        }
    }

    pub fn write_len8_list<T : ToBinary>(&mut self, items: &[T]) -> Result<(), Box<dyn std::error::Error>> {
        let len_offset = self.data.len();
        self.data.push(0); // Reserve 1 byte for length
        match self.write_list_inner(items) {
            Err(e) => {
                self.data.truncate(len_offset);
                Err(e)
            }
            Ok(len) if len > (u8::MAX as usize) => {
                self.data.truncate(len_offset);
                Err(BinaryError::ValueTooLarge.into())
            }
            Ok(len) => {
                self.data[len_offset] = len as u8;
                Ok(())
            }
        }
    }

    pub fn write_len16_list<T : ToBinary>(&mut self, items: &[T]) -> Result<(), Box<dyn std::error::Error>> {
        let len_offset = self.data.len();
        self.data.push(0); // Reserve 2 bytes for length
        self.data.push(0);
        match self.write_list_inner(items) {
            Err(e) => {
                self.data.truncate(len_offset);
                Err(e)
            }
            Ok(len) if len > (u16::MAX as usize) => {
                self.data.truncate(len_offset);
                Err(BinaryError::ValueTooLarge.into())
            }
            Ok(len) => {
                let len_bytes: [u8; 2] = (len as u16).to_be_bytes();
                self.data[len_offset] = len_bytes[0];
                self.data[len_offset + 1] = len_bytes[1];
                Ok(())
            }
        }
    }

    pub fn write_len24_list<T : ToBinary>(&mut self, items: &[T]) -> Result<(), Box<dyn std::error::Error>> {
        let len_offset = self.data.len();
        self.data.push(0); // Reserve 3 bytes for length
        self.data.push(0);
        self.data.push(0);
        match self.write_list_inner(items) {
            Err(e) => {
                self.data.truncate(len_offset);
                Err(e)
            }
            Ok(len) if len >= (1 << 24) => {
                self.data.truncate(len_offset);
                Err(BinaryError::ValueTooLarge.into())
            }
            Ok(len) => {
                // println!("write_len24_list: len = {}", len);
                let len_bytes: [u8; 4] = (len as u32).to_be_bytes();
                self.data[len_offset] = len_bytes[1];
                self.data[len_offset + 1] = len_bytes[2];
                self.data[len_offset + 2] = len_bytes[3];
                Ok(())
            }
        }
    }

    fn write_list_inner<T : ToBinary>(&mut self, items: &[T]) -> Result<usize, Box<dyn std::error::Error>> {
        let start_offset = self.data.len();
        for item in items.iter() {
            item.to_binary(self)?
        }
        let end_offset = self.data.len();
        Ok(end_offset - start_offset)
    }

    pub fn write_item<T : ToBinary>(&mut self, item: &T) -> Result<(), Box<dyn std::error::Error>> {
        item.to_binary(self)
    }

    pub fn write_u16_nested<F>(&mut self, f : F) -> Result<(), Box<dyn std::error::Error>>
        where F : FnOnce(&mut BinaryWriter) -> Result<(), Box<dyn std::error::Error>>
    {
        let len_offset = self.data.len();
        self.data.push(0);
        self.data.push(0);
        let start_offset = self.data.len();
        match f(self) {
            Ok(()) => {
                let end_offset = self.data.len();
                let len = end_offset - start_offset;
                let len_bytes: [u8; 2] = (len as u16).to_be_bytes();
                self.data[len_offset] = len_bytes[0];
                self.data[len_offset + 1] = len_bytes[1];
                Ok(())
            }
            Err(e) => {
                self.data.truncate(len_offset);
                Err(e)
            }
        }
        // unimplemented!()
    }
}

impl Default for BinaryWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl From<BinaryWriter> for Vec<u8> {
    fn from(writer: BinaryWriter) -> Vec<u8> {
        writer.data
    }
}

impl AsRef<[u8]> for BinaryWriter {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}
