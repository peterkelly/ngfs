#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::fmt;
use std::error::Error;
use super::super::util::{BinaryData, DebugHexDump, Indent, escape_string};
use super::super::binary::BinaryReader;
use super::super::result::GeneralError;

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
    pub offset: usize,
    pub len: usize,
    pub value: Value,
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

    pub fn as_sequence_iter(&self) -> Result<std::slice::Iter<Item>, Box<dyn Error>> {
        match &self.value {
            Value::Sequence(items) => Ok(items.iter()),
            _ => Err(GeneralError::new("Expected a sequence")),
        }
    }

    pub fn as_sequence(&self) -> Result<&Vec<Item>, Box<dyn Error>> {
        match &self.value {
            Value::Sequence(items) => Ok(items),
            _ => Err(GeneralError::new("Expected a sequence")),
        }
    }

    pub fn as_exact_sequence(&self, count: usize) -> Result<&Vec<Item>, Box<dyn Error>> {
        let items = self.as_sequence()?;
        if items.len() != count {
            return Err(GeneralError::new(&format!("Expected a sequence of {} items, got {}", count, items.len())));
        }
        else {
            return Ok(items);
        }
    }

    pub fn as_set(&self) -> Result<&Vec<Item>, Box<dyn Error>> {
        match &self.value {
            Value::Set(items) => Ok(items),
            _ => Err(GeneralError::new("Expected a set")),
        }
    }

    pub fn as_exact_set(&self, count: usize) -> Result<&Vec<Item>, Box<dyn Error>> {
        let items = self.as_set()?;
        if items.len() != count {
            return Err(GeneralError::new(&format!("Expected a set of {} items, got {}", count, items.len())));
        }
        else {
            return Ok(items);
        }
    }

    pub fn as_object_identifier(&self) -> Result<&ObjectIdentifier, Box<dyn Error>> {
        match &self.value {
            Value::ObjectIdentifier(oid) => Ok(oid),
            _ => Err(GeneralError::new("Expected an object identifier")),
        }
    }

    pub fn as_bit_string(&self) -> Result<&BitString, Box<dyn Error>> {
        match &self.value {
            Value::BitString(bit_string) => Ok(bit_string),
            _ => Err(GeneralError::new("Expected a bit string")),
        }
    }

    pub fn as_octet_string(&self) -> Result<&Vec<u8>, Box<dyn Error>> {
        match &self.value {
            Value::OctetString(bytes) => Ok(bytes),
            _ => Err(GeneralError::new("Expected an octet string")),
        }
    }

    pub fn as_integer(&self) -> Result<&Integer, Box<dyn Error>> {
        match &self.value {
            Value::Integer(integer) => Ok(integer),
            _ => Err(GeneralError::new("Expected an integer")),
        }
    }

    pub fn as_string(&self) -> Result<&str, Box<dyn Error>> {
        match &self.value {
            Value::PrintableString(s) => Ok(s),
            Value::UTF8String(s) => Ok(s),
            _ => Err(GeneralError::new("Expected a string")),
        }
    }

    pub fn as_boolean(&self) -> Result<bool, Box<dyn Error>> {
        match &self.value {
            Value::Boolean(b) => Ok(*b),
            _ => Err(GeneralError::new("Expected a boolean")),
        }
    }
}
