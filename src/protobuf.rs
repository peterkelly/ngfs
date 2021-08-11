// #![allow(unused_variables)]
// #![allow(dead_code)]
// #![allow(unused_mut)]
// #![allow(unused_assignments)]
// #![allow(unused_imports)]
// #![allow(unused_macros)]

use std::fmt;
use std::error::Error;
// use std::collections::BTreeMap;
use std::convert::TryInto;
use super::error;
use super::varint;

pub struct VarInt<'a>(pub &'a [u8]);
pub struct Bits32(pub [u8; 4]);
pub struct Bits64(pub [u8; 8]);
pub struct Bytes<'a>(pub &'a [u8]);

impl<'a> VarInt<'a> {
    pub fn to_u64(&self) -> Result<u64, varint::DecodeError> {
        varint::decode_u64(&self.0)
    }

    pub fn to_u32_unchecked(&self) -> u32 {
        let mut value: u32 = 0;
        for b in self.0.iter().rev() {
            value = (value << 7) | ((b & 0x7f) as u32);
        }
        value
    }

    pub fn to_i64_unchecked(&self) -> i64 {
        let mut value: i64 = 0;
        for b in self.0.iter().rev() {
            value = (value << 7) | ((b & 0x7f) as i64);
        }
        value
    }

    pub fn to_i32_unchecked(&self) -> i32 {
        let mut value: i32 = 0;
        for b in self.0.iter().rev() {
            value = (value << 7) | ((b & 0x7f) as i32);
        }
        value
    }

    pub fn to_i64_zigzag_unchecked(&self) -> i64 {
        let mut value: i64 = 0;
        for b in self.0.iter().rev() {
            value = (value << 7) | ((b & 0x7f) as i64);
        }
        (value << 63) ^ (value >> 1)
    }

    pub fn to_i32_zigzag_unchecked(&self) -> i32 {
        let mut value: i32 = 0;
        for b in self.0.iter().rev() {
            value = (value << 7) | ((b & 0x7f) as i32);
        }
        (value << 31) ^ (value >> 1)
    }

    pub fn to_usize(&self) -> Result<usize, varint::DecodeError> {
        varint::decode_u64(&self.0).map(|value| value as usize)
    }

    pub fn to_bool(&self) -> Result<bool, varint::DecodeError> {
        Ok(self.to_u64()? != 0)
    }

    pub fn read_from<'x, 'y>(data: &'x [u8], offset: &'y mut usize) -> Option<VarInt<'x>> {
        let start: usize = *offset;
        loop {
            match data.get(*offset) {
                Some(b) => {
                    *offset += 1;
                    if b & 0x80 == 0 {
                        break;
                    }
                }
                None => {
                    return None;
                }
            }
        }
        let end: usize = *offset;
        Some(VarInt(&data[start..end]))
    }
}

impl<'a> Bytes<'a> {
    pub fn to_string(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(Vec::from(self.0))
    }
}

impl Bits64 {
    fn bits64_to_u64(&self) -> u64 {
        u64::from_le_bytes(self.0)
    }

    fn bits64_to_i64(&self) -> i64 {
        i64::from_le_bytes(self.0)
    }

    fn bits64_to_double(&self) -> f64 {
        f64::from_le_bytes(self.0)
    }
}

impl Bits32 {
    fn bits32_to_u32(&self) -> u32 {
        u32::from_le_bytes(self.0)
    }

    fn bits32_to_i32(&self) -> i32 {
        i32::from_le_bytes(self.0)
    }

    fn bits32_to_float(&self) -> f32 {
        f32::from_le_bytes(self.0)
    }
}

#[derive(Debug)]
pub enum ReadCase {
    FieldTag,
    VarInt,
    Bits32,
    Bits64,
    BytesLength,
    Bytes,
}

pub enum FieldData<'a> {
    VarInt(VarInt<'a>),
    Bits32(Bits32),
    Bits64(Bits64),
    Bytes(Bytes<'a>),
}

impl<'a> FieldData<'a> {
    // fn as_varint(&self) -> Result<&VarInt<'a>, Box<dyn Error>> {
    //     match self {
    //         FieldData::VarInt(v) => Ok(v),
    //         _ => Err(error!("Not a varint")),
    //     }
    // }

    fn as_bytes(&self) -> Result<&Bytes<'a>, Box<dyn Error>> {
        match self {
            FieldData::Bytes(v) => Ok(v),
            _ => Err(error!("Not a byte array")),
        }
    }

    fn as_bits32(&self) -> Result<&Bits32, Box<dyn Error>> {
        match self {
            FieldData::Bits32(v) => Ok(v),
            _ => Err(error!("Not a bits32")),
        }
    }

    fn as_bits64(&self) -> Result<&Bits64, Box<dyn Error>> {
        match self {
            FieldData::Bits64(v) => Ok(v),
            _ => Err(error!("Not a bits64")),
        }
    }

    pub fn to_string(&self) -> Result<String, Box<dyn Error>> {
        Ok(self.as_bytes()?.to_string()?)
    }

    pub fn to_bytes(&self) -> Result<&'a [u8], Box<dyn Error>> {
        Ok(self.as_bytes()?.0)
    }

    pub fn to_u64(&self) -> Result<u64, Box<dyn Error>> {
        match self {
            FieldData::Bits64(v) => Ok(v.bits64_to_u64()),
            FieldData::VarInt(v) => Ok(v.to_u64()?),
            _ => Err(error!("Not a bits64 or varint")),
        }
    }

    pub fn to_i64(&self) -> Result<i64, Box<dyn Error>> {
        match self {
            FieldData::Bits64(v) => Ok(v.bits64_to_i64()),
            FieldData::VarInt(v) => Ok(v.to_i64_unchecked()),
            _ => Err(error!("Not a bits64 or varint")),
        }
    }

    pub fn to_i64_zigzag(&self) -> Result<i64, Box<dyn Error>> {
        match self {
            FieldData::VarInt(v) => Ok(v.to_i64_zigzag_unchecked()),
            _ => Err(error!("Not a varint")),
        }
    }

    pub fn to_double(&self) -> Result<f64, Box<dyn Error>> {
        Ok(self.as_bits64()?.bits64_to_double())
    }

    pub fn to_u32(&self) -> Result<u32, Box<dyn Error>> {
        match self {
            FieldData::Bits32(v) => Ok(v.bits32_to_u32()),
            FieldData::VarInt(v) => Ok(v.to_u32_unchecked()),
            _ => Err(error!("Not a bits32 or varint")),
        }
    }

    pub fn to_i32(&self) -> Result<i32, Box<dyn Error>> {
        match self {
            FieldData::Bits32(v) => Ok(v.bits32_to_i32()),
            FieldData::VarInt(v) => Ok(v.to_i32_unchecked()),
            _ => Err(error!("Not a bits32 or varint")),
        }
    }

    pub fn to_i32_zigzag(&self) -> Result<i32, Box<dyn Error>> {
        match self {
            FieldData::VarInt(v) => Ok(v.to_i32_zigzag_unchecked()),
            _ => Err(error!("Not a varint")),
        }
    }

    pub fn to_float(&self) -> Result<f32, Box<dyn Error>> {
        Ok(self.as_bits32()?.bits32_to_float())
    }

    pub fn to_bool(&self) -> Result<bool, Box<dyn Error>> {
        match self {
            FieldData::VarInt(v) => Ok(v.to_bool()?),
            _ => Err(error!("Not a varint")),
        }
    }
}


impl<'a> TryInto<String> for FieldData<'a> {
    type Error = Box<dyn Error>;

    fn try_into(self) -> Result<String, Self::Error> {
        self.to_string()
    }
}

impl<'a> TryInto<u64> for FieldData<'a> {
    type Error = Box<dyn Error>;

    fn try_into(self) -> Result<u64, Self::Error> {
        self.to_u64()
    }
}

impl<'a> TryInto<i64> for FieldData<'a> {
    type Error = Box<dyn Error>;

    fn try_into(self) -> Result<i64, Self::Error> {
        self.to_i64()
    }
}

impl<'a> TryInto<f64> for FieldData<'a> {
    type Error = Box<dyn Error>;

    fn try_into(self) -> Result<f64, Self::Error> {
        self.to_double()
    }
}

impl<'a> TryInto<u32> for FieldData<'a> {
    type Error = Box<dyn Error>;

    fn try_into(self) -> Result<u32, Self::Error> {
        self.to_u32()
    }
}

impl<'a> TryInto<i32> for FieldData<'a> {
    type Error = Box<dyn Error>;

    fn try_into(self) -> Result<i32, Self::Error> {
        self.to_i32()
    }
}

impl<'a> TryInto<f32> for FieldData<'a> {
    type Error = Box<dyn Error>;

    fn try_into(self) -> Result<f32, Self::Error> {
        self.to_float()
    }
}

fn fmt_bytes_spaces(label: &str, data: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}(", label)?;
    for (index, byte) in data.iter().enumerate() {
        if index > 0 {
            write!(f, " ")?;
        }
        write!(f, "{:02x}", byte)?;
    }
    write!(f, ")")?;
    Ok(())
}

fn fmt_bytes_hex(data: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "0x")?;
    for byte in data.iter() {
        write!(f, "{:02x}", byte)?;
    }
    Ok(())
}

impl<'a> fmt::Debug for FieldData<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldData::VarInt(v) => fmt_bytes_spaces("VarInt", v.0, f),
            FieldData::Bits32(v) => fmt_bytes_hex(&v.0, f),
            FieldData::Bits64(v) => fmt_bytes_hex(&v.0, f),
            FieldData::Bytes(v) => fmt_bytes_spaces("Bytes", v.0, f),
        }
    }
}


pub struct FieldRef<'a> {
    pub offset: usize,
    pub tag: u64,
    pub field_number: u64,
    pub wire_type: u8,
    pub data: FieldData<'a>,
}

// struct FieldSet<'a> {
//     fields: BTreeMap<u64, FieldRef<'a>>,
// }

// impl<'a> FieldSet<'a> {
//     fn new<'x>() -> FieldSet<'x> {
//         FieldSet { fields: BTreeMap::new() }
//     }

//     fn set(&mut self, num: u64, value: FieldRef<'a>) {
//         self.fields.insert(num, value);
//     }

//     fn get(&self, num: u64) -> Option<&FieldRef<'a>> {
//         self.fields.get(&num)
//     }
// }

#[derive(Debug)]
pub enum ReadError {
    EndOfFile(usize, ReadCase),
    InvalidTag,
    InvalidLength,
    LengthOverflow(usize),
    UnknownWireType(usize, u8),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for ReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

pub struct PBufWriter {
    pub data: Vec<u8>,
}

const VARINT_TYPE: u64 = 0;
const BITS64_TYPE: u64 = 1;
const LENGTH_TYPE: u64 = 2;
const BITS32_TYPE: u64 = 5;

impl PBufWriter {
    pub fn new() -> PBufWriter {
        PBufWriter { data: Vec::new() }
    }

    fn write_tag(&mut self, field_number: u32, field_type: u64) {
        assert!(field_type & !3 == 0);
        let tag = (field_number as u64) << 3 | field_type;
        varint::encode_u64(tag, &mut self.data);
    }


    pub fn write_int32(&mut self, field_number: u32, value: i32) {
        self.write_uint64(field_number, value as u64);
    }

    pub fn write_int64(&mut self, field_number: u32, value: i64) {
        self.write_uint64(field_number, value as u64);
    }

    pub fn write_uint32(&mut self, field_number: u32, value: u32) {
        self.write_uint64(field_number, value as u64);
    }

    pub fn write_uint64(&mut self, field_number: u32, value: u64) {
        self.write_tag(field_number, VARINT_TYPE);
        varint::encode_u64(value, &mut self.data);
    }

    // pub fn write_sint32(&mut self, field_number: u32, value: i32) {
    //     println!("{} {}", field_number, value);
    //     unimplemented!();
    // }

    // pub fn write_sint64(&mut self, field_number: u32, value: i64) {
    //     println!("{} {}", field_number, value);
    //     unimplemented!();
    // }

    pub fn write_bool(&mut self, field_number: u32, value: bool) {
        self.write_uint64(field_number, value as u64);
    }

    pub fn write_fixed64(&mut self, field_number: u32, value: u64) {
        self.write_tag(field_number, BITS64_TYPE);
        self.data.append(&mut Vec::from(&value.to_be_bytes()[..]));
    }

    pub fn write_sfixed64(&mut self, field_number: u32, value: i64) {
        self.write_tag(field_number, BITS64_TYPE);
        self.data.append(&mut Vec::from(&value.to_be_bytes()[..]));
    }

    pub fn write_double(&mut self, field_number: u32, value: f64) {
        self.write_tag(field_number, BITS64_TYPE);
        self.data.append(&mut Vec::from(&value.to_be_bytes()[..]));
    }

    pub fn write_fixed32(&mut self, field_number: u32, value: i32) {
        self.write_tag(field_number, BITS32_TYPE);
        self.data.append(&mut Vec::from(&value.to_be_bytes()[..]));
    }

    pub fn write_sfixed32(&mut self, field_number: u32, value: i32) {
        self.write_tag(field_number, BITS32_TYPE);
        self.data.append(&mut Vec::from(&value.to_be_bytes()[..]));
    }

    pub fn write_float(&mut self, field_number: u32, value: f32) {
        self.write_tag(field_number, BITS32_TYPE);
        self.data.append(&mut Vec::from(&value.to_be_bytes()[..]));
    }


    pub fn write_usize(&mut self, field_number: u32, value: usize) {
        self.write_uint64(field_number, value as u64);
    }

    pub fn write_bytes(&mut self, field_number: u32, bytes: &[u8]) {
        self.write_tag(field_number, LENGTH_TYPE);
        varint::encode_usize(bytes.len(), &mut self.data);
        self.data.append(&mut Vec::from(bytes));
    }

    pub fn write_string(&mut self, field_number: u32, s: &str) {
        self.write_bytes(field_number, s.as_bytes());
    }
}

pub struct PBufReader<'a> {
    pub offset: usize,
    pub data: &'a [u8],
}

impl<'a> PBufReader<'a> {
    pub fn new<'x>(data: &'x [u8]) -> PBufReader<'x> {
        PBufReader { offset: 0, data: data }
    }

    pub fn read_field(&mut self) -> Result<Option<FieldRef<'a>>, ReadError> {
        if self.offset >= self.data.len() {
            return Ok(None);
        }

        let start = self.offset;
        let tag = self.read_varint(ReadCase::FieldTag)?.to_u64()
                      .map_err(|_| ReadError::InvalidTag)?;
        let field_number = tag >> 3;
        let wire_type = tag & 0x7;

        let data: FieldData = match wire_type {
            0 => FieldData::VarInt(self.read_varint(ReadCase::VarInt)?),
            1 => FieldData::Bits64(self.read_64bit()?),
            2 => FieldData::Bytes(self.read_length_delimited()?),
            5 => FieldData::Bits32(self.read_32bit()?),
            _ => return Err(ReadError::UnknownWireType(start, wire_type as u8)),
        };

        Ok(Some(FieldRef {
            offset: start,
            tag: tag,
            field_number: field_number,
            wire_type: wire_type as u8,
            data: data,
        }))
    }

    pub fn read_varint(&mut self, read_case: ReadCase) -> Result<VarInt<'a>, ReadError> {
        let start = self.offset;
        loop {
            match self.data.get(self.offset) {
                Some(b) => {
                    self.offset += 1;
                    if b & 0x80 == 0 {
                        break;
                    }
                }
                None => {
                    return Err(ReadError::EndOfFile(start, read_case));
                }
            }
        }
        Ok(VarInt(&self.data[start..self.offset]))
    }

    pub fn read_length_delimited(&mut self) -> Result<Bytes<'a>, ReadError> {
        let nbytes = self.read_varint(ReadCase::BytesLength)?.to_usize()
                         .map_err(|_| ReadError::InvalidLength)?;
        let slice = self.read(nbytes, ReadCase::Bytes)?;
        Ok(Bytes(slice))
    }

    pub fn read_32bit(&mut self) -> Result<Bits32, ReadError> {
        let slice = self.read(4, ReadCase::Bits32)?;
        let mut four: [u8; 4] = Default::default();
        four.copy_from_slice(slice);
        Ok(Bits32(four))
    }

    pub fn read_64bit(&mut self) -> Result<Bits64, ReadError> {
        let slice = self.read(8, ReadCase::Bits64)?;
        let mut eight: [u8; 8] = Default::default();
        eight.copy_from_slice(slice);
        Ok(Bits64(eight))
    }

    pub fn read(&mut self, nbytes: usize, read_case: ReadCase) -> Result<&'a [u8], ReadError> {
        let end: usize = match self.offset.checked_add(nbytes) {
            Some(v) => v,
            None => return Err(ReadError::LengthOverflow(self.offset)),
        };

        match self.data.get(self.offset..end) {
            Some(part) => {
                self.offset = end;
                Ok(part)
            }
            None => {
                Err(ReadError::EndOfFile(self.offset, read_case))
            }
        }
    }
}
