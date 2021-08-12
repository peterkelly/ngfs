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

    pub fn to_u64_unchecked(&self) -> u64 {
        let mut value: u64 = 0;
        for b in self.0.iter().rev() {
            value = (value << 7) | ((b & 0x7f) as u64);
        }
        value
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
        let value_u64: u64 = self.to_u64_unchecked();
        ((value_u64 >> 1) as i64) ^ -((value_u64 & 1) as i64)

        // let mut value: i64 = 0;
        // for b in self.0.iter().rev() {
        //     value = (value << 7) | ((b & 0x7f) as i64);
        // }
        // (value << 63) ^ (value >> 1)
    }

    pub fn to_i32_zigzag_unchecked(&self) -> i32 {
        let value_u32: u32 = self.to_u32_unchecked();
        ((value_u32 >> 1) as i32) ^ -((value_u32 & 1) as i32)


        // let value_u64 = self.to_u64_unchecked();
        // let value_i32 = value_u64 as i32;
        // let decoded = (value_i32 >> 1) ^ -(value_i32 & 1);
        // decoded

        // let mut value: i32 = 0;
        // for b in self.0.iter().rev() {
        //     value = (value << 7) | ((b & 0x7f) as i32);
        // }
        // (value << 31) ^ (value >> 1)
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
        // done
        Ok(self.as_bytes()?.to_string()?)
    }

    pub fn to_bytes(&self) -> Result<&'a [u8], Box<dyn Error>> {
        // done
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
        // done
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
        // done
        Ok(self.as_bits32()?.bits32_to_float())
    }

    pub fn to_bool(&self) -> Result<bool, Box<dyn Error>> {
        // done
        match self {
            FieldData::VarInt(v) => Ok(v.to_bool()?),
            _ => Err(error!("Not a varint")),
        }
    }



    // ----------------- new implementations -----------------

    pub fn to_pb_bool(&self) -> Result<bool, Box<dyn Error>> {
        match self {
            FieldData::VarInt(v) => Ok(v.to_bool()?),
            _ => Err(error!("Not a varint")),
        }
    }

    pub fn to_pb_bytes(&self) -> Result<&'a [u8], Box<dyn Error>> {
        Ok(self.as_bytes()?.0)
    }

    pub fn to_pb_float(&self) -> Result<f32, Box<dyn Error>> {
        Ok(self.as_bits32()?.bits32_to_float())
    }

    pub fn to_pb_double(&self) -> Result<f64, Box<dyn Error>> {
        Ok(self.as_bits64()?.bits64_to_double())
    }

    pub fn to_pb_fixed32(&self) -> Result<u32, Box<dyn Error>> {
        match self {
            FieldData::Bits32(v) => Ok(v.bits32_to_u32()),
            _ => Err(error!("Not a bits32")),
        }
    }

    pub fn to_pb_fixed64(&self) -> Result<u64, Box<dyn Error>> {
        match self {
            FieldData::Bits64(v) => Ok(v.bits64_to_u64()),
            _ => Err(error!("Not a bits64")),
        }
    }

    pub fn to_pb_int32(&self) -> Result<i32, Box<dyn Error>> {
        match self {
            FieldData::VarInt(v) => Ok(v.to_i32_unchecked()),
            _ => Err(error!("Not a varint")),
        }
    }

    pub fn to_pb_int64(&self) -> Result<i64, Box<dyn Error>> {
        match self {
            FieldData::VarInt(v) => Ok(v.to_i64_unchecked()),
            _ => Err(error!("Not a varint")),
        }
    }

    pub fn to_pb_sfixed32(&self) -> Result<i32, Box<dyn Error>> {
        match self {
            FieldData::Bits32(v) => Ok(v.bits32_to_i32()),
            _ => Err(error!("Not a bits32")),
        }
    }

    pub fn to_pb_sfixed64(&self) -> Result<i64, Box<dyn Error>> {
        match self {
            FieldData::Bits64(v) => Ok(v.bits64_to_i64()),
            _ => Err(error!("Not a bits64")),
        }
    }

    pub fn to_pb_sint32(&self) -> Result<i32, Box<dyn Error>> {
        match self {
            FieldData::VarInt(v) => Ok(v.to_i32_zigzag_unchecked()),
            _ => Err(error!("Not a varint")),
        }
    }

    pub fn to_pb_sint64(&self) -> Result<i64, Box<dyn Error>> {
        match self {
            FieldData::VarInt(v) => Ok(v.to_i64_zigzag_unchecked()),
            _ => Err(error!("Not a varint")),
        }
    }

    pub fn to_pb_string(&self) -> Result<String, Box<dyn Error>> {
        Ok(self.as_bytes()?.to_string()?)
    }

    pub fn to_pb_uint32(&self) -> Result<u32, Box<dyn Error>> {
        match self {
            FieldData::VarInt(v) => Ok(v.to_u32_unchecked()),
            _ => Err(error!("Not a varint")),
        }
    }

    pub fn to_pb_uint64(&self) -> Result<u64, Box<dyn Error>> {
        match self {
            FieldData::VarInt(v) => Ok(v.to_u64()?),
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

// impl<'a> PBufReader<'a> {
//     pub fn new<'x>(data: &'x [u8]) -> PBufReader<'x> {
//         PBufReader { offset: 0, data: data }
//     }

//     pub fn read_field(&mut self) -> Result<Option<FieldRef<'a>>, ReadError> {

#[cfg(test)]
mod tests {
    use crate::util::from_hex;
    use super::{PBufReader};
    use std::error::Error;

    #[test]
    fn decode_test_float_nan() -> Result<(), Box<dyn Error>> {
        let data = from_hex("e5010000c07f").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert!(f32::is_nan(field.data.to_pb_float()?));
        Ok(())
    }

    #[test]
    fn decode_test_double_nan() -> Result<(), Box<dyn Error>> {
        let data = from_hex("9102000000000000f87f").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert!(f64::is_nan(field.data.to_pb_double()?));
        Ok(())
    }

    // The following code is generated from testdata/protobuf/run.sh
    #[test]
    fn decode_test_string_empty() -> Result<(), Box<dyn Error>> {
        let data = from_hex("0a00").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_string()?, "");
        Ok(())
    }

    #[test]
    fn decode_test_string_nonempty() -> Result<(), Box<dyn Error>> {
        let data = from_hex("120568656c6c6f").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_string()?, "hello");
        Ok(())
    }

    #[test]
    fn decode_test_bytes_empty() -> Result<(), Box<dyn Error>> {
        let data = from_hex("1a00").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_bytes()?, vec![]);
        Ok(())
    }

    #[test]
    fn decode_test_bytes_nonempty() -> Result<(), Box<dyn Error>> {
        let data = from_hex("2204cafebabe").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_bytes()?, vec![0xca, 0xfe, 0xba, 0xbe]);
        Ok(())
    }

    #[test]
    fn decode_test_bool_true() -> Result<(), Box<dyn Error>> {
        let data = from_hex("2801").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_bool()?, true);
        Ok(())
    }

    #[test]
    fn decode_test_bool_false() -> Result<(), Box<dyn Error>> {
        let data = from_hex("3000").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_bool()?, false);
        Ok(())
    }

    #[test]
    fn decode_test_fixed32_positive() -> Result<(), Box<dyn Error>> {
        let data = from_hex("3dd2029649").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_fixed32()?, 1234567890);
        Ok(())
    }

    #[test]
    fn decode_test_fixed32_min() -> Result<(), Box<dyn Error>> {
        let data = from_hex("4500000000").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_fixed32()?, u32::MIN);
        Ok(())
    }

    #[test]
    fn decode_test_fixed32_max() -> Result<(), Box<dyn Error>> {
        let data = from_hex("4dffffffff").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_fixed32()?, u32::MAX);
        Ok(())
    }

    #[test]
    fn decode_test_fixed64_positive() -> Result<(), Box<dyn Error>> {
        let data = from_hex("51cb44f2b09582cf4e").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_fixed64()?, 5678901234567890123);
        Ok(())
    }

    #[test]
    fn decode_test_fixed64_min() -> Result<(), Box<dyn Error>> {
        let data = from_hex("590000000000000000").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_fixed64()?, u64::MIN);
        Ok(())
    }

    #[test]
    fn decode_test_fixed64_max() -> Result<(), Box<dyn Error>> {
        let data = from_hex("61ffffffffffffffff").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_fixed64()?, u64::MAX);
        Ok(())
    }

    #[test]
    fn decode_test_sfixed32_positive() -> Result<(), Box<dyn Error>> {
        let data = from_hex("6dd2029649").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_sfixed32()?, 1234567890);
        Ok(())
    }

    #[test]
    fn decode_test_sfixed32_negative() -> Result<(), Box<dyn Error>> {
        let data = from_hex("752efd69b6").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_sfixed32()?, -1234567890);
        Ok(())
    }

    #[test]
    fn decode_test_sfixed32_zero() -> Result<(), Box<dyn Error>> {
        let data = from_hex("7d00000000").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_sfixed32()?, 0);
        Ok(())
    }

    #[test]
    fn decode_test_sfixed32_min() -> Result<(), Box<dyn Error>> {
        let data = from_hex("850100000080").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_sfixed32()?, i32::MIN);
        Ok(())
    }

    #[test]
    fn decode_test_sfixed32_max() -> Result<(), Box<dyn Error>> {
        let data = from_hex("8d01ffffff7f").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_sfixed32()?, i32::MAX);
        Ok(())
    }

    #[test]
    fn decode_test_sfixed64_positive() -> Result<(), Box<dyn Error>> {
        let data = from_hex("9101cb44f2b09582cf4e").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_sfixed64()?, 5678901234567890123);
        Ok(())
    }

    #[test]
    fn decode_test_sfixed64_negative() -> Result<(), Box<dyn Error>> {
        let data = from_hex("990135bb0d4f6a7d30b1").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_sfixed64()?, -5678901234567890123);
        Ok(())
    }

    #[test]
    fn decode_test_sfixed64_zero() -> Result<(), Box<dyn Error>> {
        let data = from_hex("a1010000000000000000").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_sfixed64()?, 0);
        Ok(())
    }

    #[test]
    fn decode_test_sfixed64_min() -> Result<(), Box<dyn Error>> {
        let data = from_hex("a9010000000000000080").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_sfixed64()?, i64::MIN);
        Ok(())
    }

    #[test]
    fn decode_test_sfixed64_max() -> Result<(), Box<dyn Error>> {
        let data = from_hex("b101ffffffffffffff7f").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_sfixed64()?, i64::MAX);
        Ok(())
    }

    #[test]
    fn decode_test_float_positive() -> Result<(), Box<dyn Error>> {
        let data = from_hex("bd01db0f4940").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_float()?, 3.141592653589793);
        Ok(())
    }

    #[test]
    fn decode_test_float_negative() -> Result<(), Box<dyn Error>> {
        let data = from_hex("c501db0f49c0").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_float()?, -3.141592653589793);
        Ok(())
    }

    #[test]
    fn decode_test_float_zero() -> Result<(), Box<dyn Error>> {
        let data = from_hex("cd0100000000").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_float()?, 0.0);
        Ok(())
    }

    #[test]
    fn decode_test_float_posinf() -> Result<(), Box<dyn Error>> {
        let data = from_hex("d5010000807f").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_float()?, f32::INFINITY);
        Ok(())
    }

    #[test]
    fn decode_test_float_neginf() -> Result<(), Box<dyn Error>> {
        let data = from_hex("dd01000080ff").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_float()?, f32::NEG_INFINITY);
        Ok(())
    }

    #[test]
    fn decode_test_double_positive() -> Result<(), Box<dyn Error>> {
        let data = from_hex("e101182d4454fb210940").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_double()?, 3.141592653589793);
        Ok(())
    }

    #[test]
    fn decode_test_double_negative() -> Result<(), Box<dyn Error>> {
        let data = from_hex("e901182d4454fb2109c0").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_double()?, -3.141592653589793);
        Ok(())
    }

    #[test]
    fn decode_test_double_zero() -> Result<(), Box<dyn Error>> {
        let data = from_hex("f1010000000000000000").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_double()?, 0.0);
        Ok(())
    }

    #[test]
    fn decode_test_double_posinf() -> Result<(), Box<dyn Error>> {
        let data = from_hex("f901000000000000f07f").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_double()?, f64::INFINITY);
        Ok(())
    }

    #[test]
    fn decode_test_double_neginf() -> Result<(), Box<dyn Error>> {
        let data = from_hex("8102000000000000f0ff").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_double()?, f64::NEG_INFINITY);
        Ok(())
    }

    #[test]
    fn decode_test_uint32_positive() -> Result<(), Box<dyn Error>> {
        let data = from_hex("8802d285d8cc04").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_uint32()?, 1234567890);
        Ok(())
    }

    #[test]
    fn decode_test_uint32_min() -> Result<(), Box<dyn Error>> {
        let data = from_hex("900200").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_uint32()?, u32::MIN);
        Ok(())
    }

    #[test]
    fn decode_test_uint32_max() -> Result<(), Box<dyn Error>> {
        let data = from_hex("9802ffffffff0f").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_uint32()?, u32::MAX);
        Ok(())
    }

    #[test]
    fn decode_test_uint64_positive() -> Result<(), Box<dyn Error>> {
        let data = from_hex("a002cb89c987dbd2e0e74e").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_uint64()?, 5678901234567890123);
        Ok(())
    }

    #[test]
    fn decode_test_uint64_min() -> Result<(), Box<dyn Error>> {
        let data = from_hex("a80200").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_uint64()?, u64::MIN);
        Ok(())
    }

    #[test]
    fn decode_test_uint64_max() -> Result<(), Box<dyn Error>> {
        let data = from_hex("b002ffffffffffffffffff01").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_uint64()?, u64::MAX);
        Ok(())
    }

    #[test]
    fn decode_test_int32_positive() -> Result<(), Box<dyn Error>> {
        let data = from_hex("b802d285d8cc04").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_int32()?, 1234567890);
        Ok(())
    }

    #[test]
    fn decode_test_int32_negative() -> Result<(), Box<dyn Error>> {
        let data = from_hex("c002aefaa7b3fbffffffff01").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_int32()?, -1234567890);
        Ok(())
    }

    #[test]
    fn decode_test_int32_zero() -> Result<(), Box<dyn Error>> {
        let data = from_hex("c80200").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_int32()?, 0);
        Ok(())
    }

    #[test]
    fn decode_test_int32_min() -> Result<(), Box<dyn Error>> {
        let data = from_hex("d00280808080f8ffffffff01").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_int32()?, i32::MIN);
        Ok(())
    }

    #[test]
    fn decode_test_int32_max() -> Result<(), Box<dyn Error>> {
        let data = from_hex("d802ffffffff07").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_int32()?, i32::MAX);
        Ok(())
    }

    #[test]
    fn decode_test_int64_positive() -> Result<(), Box<dyn Error>> {
        let data = from_hex("e002cb89c987dbd2e0e74e").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_int64()?, 5678901234567890123);
        Ok(())
    }

    #[test]
    fn decode_test_int64_negative() -> Result<(), Box<dyn Error>> {
        let data = from_hex("e802b5f6b6f8a4ad9f98b101").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_int64()?, -5678901234567890123);
        Ok(())
    }

    #[test]
    fn decode_test_int64_zero() -> Result<(), Box<dyn Error>> {
        let data = from_hex("f00200").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_int64()?, 0);
        Ok(())
    }

    #[test]
    fn decode_test_int64_min() -> Result<(), Box<dyn Error>> {
        let data = from_hex("f80280808080808080808001").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_int64()?, i64::MIN);
        Ok(())
    }

    #[test]
    fn decode_test_int64_max() -> Result<(), Box<dyn Error>> {
        let data = from_hex("8003ffffffffffffffff7f").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_int64()?, i64::MAX);
        Ok(())
    }

    #[test]
    fn decode_test_sint32_positive() -> Result<(), Box<dyn Error>> {
        let data = from_hex("8803a48bb09909").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_sint32()?, 1234567890);
        Ok(())
    }

    #[test]
    fn decode_test_sint32_negative() -> Result<(), Box<dyn Error>> {
        let data = from_hex("9003a38bb09909").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_sint32()?, -1234567890);
        Ok(())
    }

    #[test]
    fn decode_test_sint32_zero() -> Result<(), Box<dyn Error>> {
        let data = from_hex("980300").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_sint32()?, 0);
        Ok(())
    }

    #[test]
    fn decode_test_sint32_min() -> Result<(), Box<dyn Error>> {
        let data = from_hex("a003ffffffff0f").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_sint32()?, i32::MIN);
        Ok(())
    }

    #[test]
    fn decode_test_sint32_max() -> Result<(), Box<dyn Error>> {
        let data = from_hex("a803feffffff0f").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_sint32()?, i32::MAX);
        Ok(())
    }

    #[test]
    fn decode_test_sint64_positive() -> Result<(), Box<dyn Error>> {
        let data = from_hex("b0039693928fb6a5c1cf9d01").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_sint64()?, 5678901234567890123);
        Ok(())
    }

    #[test]
    fn decode_test_sint64_negative() -> Result<(), Box<dyn Error>> {
        let data = from_hex("b8039593928fb6a5c1cf9d01").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_sint64()?, -5678901234567890123);
        Ok(())
    }

    #[test]
    fn decode_test_sint64_zero() -> Result<(), Box<dyn Error>> {
        let data = from_hex("c00300").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_sint64()?, 0);
        Ok(())
    }

    #[test]
    fn decode_test_sint64_min() -> Result<(), Box<dyn Error>> {
        let data = from_hex("c803ffffffffffffffffff01").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_sint64()?, i64::MIN);
        Ok(())
    }

    #[test]
    fn decode_test_sint64_max() -> Result<(), Box<dyn Error>> {
        let data = from_hex("d003feffffffffffffffff01").unwrap();
        let mut reader = PBufReader::new(&data);
        let field = reader.read_field().unwrap().unwrap();
        assert_eq!(field.data.to_pb_sint64()?, i64::MAX);
        Ok(())
    }
}
