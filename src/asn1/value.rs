use std::fmt;
use std::error::Error;
use std::ops::Range;

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Class {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Form {
    Primitive,
    Constructed,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Identifier {
    pub class: Class,
    pub form: Form,
    pub tag: u32,
}

#[derive(Clone)]
pub struct ObjectIdentifier(pub Vec<u64>);

impl fmt::Display for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in 0..self.0.len() {
            if i > 0 {
                write!(f, ".")?;
            }
            write!(f, "{}", self.0[i])?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct BitString {
    pub unused_bits: u8,
    pub bytes: Vec<u8>,
}

impl fmt::Debug for BitString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in 0..self.bytes.len() {
            write!(f, "{:02x}", i)?;
        }
        write!(f, " (unused {})", self.unused_bits)
    }
}

#[derive(Clone)]
pub struct Integer(pub Vec<u8>);

#[derive(Clone)]
pub enum Value {
    Boolean(bool),
    Integer(Integer),
    BitString(BitString),
    OctetString(Vec<u8>),
    Null,
    ObjectIdentifier(ObjectIdentifier),
    PrintableString(String),
    UTF8String(String),


    UTCTime(String),
    GeneralizedTime(String),

    Sequence(Vec<Item>),
    Set(Vec<Item>),

    Application(u32, Vec<Item>),
    ContextSpecific(u32, Vec<Item>),
    Private(u32, Vec<Item>),

    Unknown(Identifier, u32),
}

#[derive(Clone)]
pub struct Item {
    pub range: Range<usize>,
    pub value: Value,
}

impl From<Value> for Item {
    fn from(value: Value) -> Self {
        Item { range: 0..0, value }
    }
}

impl Item {
    pub fn type_str(&self) -> &'static str {
        match self.value {
            Value::Boolean(_)            => "Boolean",
            Value::Integer(_)            => "Integer",
            Value::BitString(_)          => "BitString",
            Value::OctetString(_)        => "OctetString",
            Value::Null                  => "Null",
            Value::ObjectIdentifier(_)   => "ObjectIdentifier",
            Value::PrintableString(_)    => "PrintableString",
            Value::UTF8String(_)         => "UTF8String",
            Value::UTCTime(_)            => "UTCTime",
            Value::GeneralizedTime(_)    => "GeneralizedTime",
            Value::Sequence(_)           => "Sequence",
            Value::Set(_)                => "Set",
            Value::Application(_, _)     => "Application",
            Value::ContextSpecific(_, _) => "ContextSpecific",
            Value::Private(_, _)         => "Private",
            Value::Unknown(_, _)         => "Unknown",
        }
    }

    pub fn as_sequence_iter(&self) -> Result<std::slice::Iter<Item>, TypeError> {
        match &self.value {
            Value::Sequence(items) => Ok(items.iter()),
            _ => Err(TypeError::ExpectedSequence(self.range.clone())),
        }
    }

    pub fn as_sequence(&self) -> Result<&Vec<Item>, TypeError> {
        match &self.value {
            Value::Sequence(items) => Ok(items),
            _ => Err(TypeError::ExpectedSequence(self.range.clone())),
        }
    }

    pub fn as_exact_sequence(&self, count: usize) -> Result<&Vec<Item>, TypeError> {
        let items = self.as_sequence()?;
        if items.len() != count {
            Err(TypeError::ExpectedExactSequence(self.range.clone(), count, items.len()))
        }
        else {
            Ok(items)
        }
    }

    pub fn as_set(&self) -> Result<&Vec<Item>, TypeError> {
        match &self.value {
            Value::Set(items) => Ok(items),
            _ => Err(TypeError::ExpectedSet(self.range.clone())),
        }
    }

    pub fn as_exact_set(&self, count: usize) -> Result<&Vec<Item>, TypeError> {
        let items = self.as_set()?;
        if items.len() != count {
            Err(TypeError::ExpectedExactSet(self.range.clone(), count, items.len()))
        }
        else {
            Ok(items)
        }
    }

    pub fn as_object_identifier(&self) -> Result<&ObjectIdentifier, TypeError> {
        match &self.value {
            Value::ObjectIdentifier(oid) => Ok(oid),
            _ => Err(TypeError::ExpectedObjectIdentifier(self.range.clone())),
        }
    }

    pub fn as_bit_string(&self) -> Result<&BitString, TypeError> {
        match &self.value {
            Value::BitString(bit_string) => Ok(bit_string),
            _ => Err(TypeError::ExpectedBitString(self.range.clone())),
        }
    }

    pub fn as_octet_string(&self) -> Result<&Vec<u8>, TypeError> {
        match &self.value {
            Value::OctetString(bytes) => Ok(bytes),
            _ => Err(TypeError::ExpectedOctetString(self.range.clone())),
        }
    }

    pub fn as_integer(&self) -> Result<&Integer, TypeError> {
        match &self.value {
            Value::Integer(integer) => Ok(integer),
            _ => Err(TypeError::ExpectedInteger(self.range.clone())),
        }
    }

    pub fn as_string(&self) -> Result<&str, TypeError> {
        match &self.value {
            Value::PrintableString(s) => Ok(s),
            Value::UTF8String(s) => Ok(s),
            _ => Err(TypeError::ExpectedString(self.range.clone())),
        }
    }

    pub fn as_boolean(&self) -> Result<bool, TypeError> {
        match &self.value {
            Value::Boolean(b) => Ok(*b),
            _ => Err(TypeError::ExpectedBoolean(self.range.clone())),
        }
    }
}

pub enum TypeError {
    ExpectedSequence(Range<usize>),
    ExpectedExactSequence(Range<usize>, usize, usize),
    ExpectedSet(Range<usize>),
    ExpectedExactSet(Range<usize>, usize, usize),
    ExpectedObjectIdentifier(Range<usize>),
    ExpectedBitString(Range<usize>),
    ExpectedOctetString(Range<usize>),
    ExpectedInteger(Range<usize>),
    ExpectedString(Range<usize>),
    ExpectedBoolean(Range<usize>),
}

impl Error for TypeError {
}

impl fmt::Debug for TypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl fmt::Display for TypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeError::ExpectedSequence(range) =>
                write!(f, "Expected a sequence at {:?}", range),
            TypeError::ExpectedExactSequence(range, exp, act) =>
                write!(f, "Expected a sequence of {} items, got {} at {:?}", exp, act, range),
            TypeError::ExpectedSet(range) =>
                write!(f, "Expected a set at {:?}", range),
            TypeError::ExpectedExactSet(range, exp, act) =>
                write!(f, "Expected a set of {} items, got {} at {:?}", exp, act, range),
            TypeError::ExpectedObjectIdentifier(range) =>
                write!(f, "Expected an object identifier at {:?}", range),
            TypeError::ExpectedBitString(range) =>
                write!(f, "Expected a bit string at {:?}", range),
            TypeError::ExpectedOctetString(range) =>
                write!(f, "Expected an octet string at {:?}", range),
            TypeError::ExpectedInteger(range) =>
                write!(f, "Expected an integer at {:?}", range),
            TypeError::ExpectedString(range) =>
                write!(f, "Expected a string at {:?}", range),
            TypeError::ExpectedBoolean(range) =>
                write!(f, "Expected a boolean at {:?}", range),
        }
    }
}
