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
use super::value::Value;

pub struct Printer {
    pub truncate: bool,
    pub lines: bool,
}

impl Printer {
    pub fn new() -> Self {
        Self {
            truncate: false,
            lines: false,
        }
    }

    fn bytes_to_string(&self, bytes: &[u8]) -> String {
        let mut s = String::new();
        for (i, b) in bytes.iter().enumerate() {
            if self.truncate && i >= 16 {
                s.push_str("...");
                break;
            }
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    fn print_list(&self, name: &str, values: &[Value], prefix: &str, indent: &str) {
        println!("{}", name);
        for (i, value) in values.iter().enumerate() {
            if i + 1 < values.len() {
                let c_prefix = &format!("{}├── ", indent);
                let c_indent = &format!("{}│   ", indent);
                self.print_value(value, c_prefix, c_indent);
            }
            else {
                let c_prefix = &format!("{}└── ", indent);
                let c_indent = &format!("{}    ", indent);
                self.print_value(value, c_prefix, c_indent);
            }
        }
    }

    fn print_value(&self, value: &Value, prefix: &str, indent: &str) {
        print!("{}", prefix);

        match value {
            Value::Boolean(inner) => {
                println!("BOOLEAN {}", inner);
            }
            Value::Integer(inner) => {
                println!("INTEGER {}", self.bytes_to_string(inner));
            }
            Value::BitString(bitstring) => {
                println!("BIT STRING {} (unused {})",
                         self.bytes_to_string(&bitstring.bytes),
                         bitstring.unused_bits);
            }
            Value::OctetString(bytes) => {
                println!("OCTET STRING {}", self.bytes_to_string(bytes));
            }
            Value::Null => {
                println!("NULL");
            }
            Value::ObjectIdentifier(oid) => {
                println!("OBJECT {}", oid);
            }
            Value::PrintableString(s) => {
                println!("PrintableString {}", escape_string(s));
            }
            Value::UTF8String(s) => {
                println!("UTF8String {}", escape_string(s));
            }
            Value::UTCTime(s) => {
                println!("UTCTime {}", escape_string(s));
            }
            Value::GeneralizedTime(s) => {
                println!("GeneralizedTime {}", escape_string(s));
            }
            Value::Sequence(inner) => {
                self.print_list("Sequence", inner, indent, indent);
            }
            Value::Set(inner) => {
                self.print_list("Set", inner, indent, indent);
            }
            Value::Application(inner) => {
                self.print_list("Application", inner, indent, indent);
            }
            Value::ContextSpecific(inner) => {
                self.print_list("ContextSpecific", inner, indent, indent);
            }
            Value::Private(inner) => {
                self.print_list("Private", inner, indent, indent);
            }
            Value::Unknown(ident, len) => {
                println!("Unknown {:?}, len = {}", ident, len)
            }
        }
    }

    pub fn print(&self, value: &Value) {
        self.print_value(value, "", "");
    }
}
