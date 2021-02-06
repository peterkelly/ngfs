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

#[derive(Debug, Eq, PartialEq)]
pub enum Class {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Form {
    Primitive,
    Constructed,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Identifier {
    pub class: Class,
    pub form: Form,
    pub tag: u32,
}

pub struct ObjectIdentifier {
    pub parts: Vec<u64>,
}

impl fmt::Display for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in 0..self.parts.len() {
            if i > 0 {
                write!(f, ".")?;
            }
            write!(f, "{}", self.parts[i])?;
        }
        Ok(())
    }
}

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

pub enum Value {
    Boolean(bool),
    Integer(Vec<u8>),
    BitString(BitString),
    OctetString(Vec<u8>),
    Null,
    ObjectIdentifier(ObjectIdentifier),
    PrintableString(String),
    UTF8String(String),


    UTCTime(String),
    GeneralizedTime(String),

    Sequence(Vec<Value>),
    Set(Vec<Value>),

    Application(Vec<Value>),
    ContextSpecific(Vec<Value>),
    Private(Vec<Value>),

    Unknown(Identifier, u32),
}
