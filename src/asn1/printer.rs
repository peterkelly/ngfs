#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::fmt;
use std::error::Error;
use std::collections::HashMap;
use super::super::util::{BinaryData, DebugHexDump, Indent, escape_string};
use super::super::binary::BinaryReader;
use super::super::result::GeneralError;
use super::value::{Value, Item, ObjectIdentifier};

pub struct ObjectDescriptor {
    pub parts: &'static [u64],
    pub name: &'static str,
    pub short: Option<&'static str>,
    pub description: &'static str,
}

pub struct ObjectRegistry {
    long_names: HashMap<Vec<u64>, String>,
    short_names: HashMap<Vec<u64>, String>,
    descriptors: HashMap<Vec<u64>, &'static ObjectDescriptor>,
}

impl ObjectRegistry {
    pub fn new() -> ObjectRegistry {
        ObjectRegistry {
            long_names: HashMap::new(),
            short_names: HashMap::new(),
            descriptors: HashMap::new(),
        }
    }

    pub fn add(&mut self, oid: &[u64], long_name: &str) {
        self.long_names.insert(oid.to_vec(), String::from(long_name));
    }

    pub fn add2(&mut self, oid: &[u64], long_name: &str, short_name: &str) {
        self.long_names.insert(oid.to_vec(), String::from(long_name));
        self.short_names.insert(oid.to_vec(), String::from(short_name));
    }

    pub fn lookup_long_name(&self, oid: &[u64]) -> Option<&str> {
        match self.long_names.get(oid) {
            Some(s) => Some(&s),
            None => None,
        }
    }

    pub fn lookup_short_name(&self, oid: &[u64]) -> Option<&str> {
        match self.short_names.get(oid) {
            Some(s) => Some(&s),
            None => None,
        }
    }

    pub fn get_long_name(&self, oid: &ObjectIdentifier) -> String {
        match self.long_names.get(&oid.0) {
            Some(s) => String::from(s),
            None => format!("{}", oid),
        }
    }

    pub fn get_short_name(&self, oid: &ObjectIdentifier) -> String {
        match self.short_names.get(&oid.0) {
            Some(s) => String::from(s),
            None => format!("{}", oid),
        }
    }

    pub fn lookup_descriptor(&self, oid: &[u64]) -> Option<&&'static ObjectDescriptor> {
    // pub fn lookup_descriptor(&self, oid: &[u64]) {
        self.descriptors.get(oid)
    }
}

pub struct Printer<'a> {
    pub truncate: bool,
    pub lines: bool,
    pub registry: Option<&'a ObjectRegistry>,
}

impl Printer<'_> {
    pub fn new() -> Self {
        Self {
            truncate: false,
            lines: false,
            registry: None,
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

    fn print_list(&self, name: &str, items: &[Item], indent: &str) {
        println!("{}", name);
        for (i, item) in items.iter().enumerate() {
            if i + 1 < items.len() {
                let c_prefix = &format!("{}├── ", indent);
                let c_indent = &format!("{}│   ", indent);
                self.print_item(item, c_prefix, c_indent);
            }
            else {
                let c_prefix = &format!("{}└── ", indent);
                let c_indent = &format!("{}    ", indent);
                self.print_item(item, c_prefix, c_indent);
            }
        }
    }

    fn print_single_child(&self, name: &str, child: &Item, indent: &str) {
        println!("{}", name);
        let c_prefix = &format!("{}└── ", indent);
        let c_indent = &format!("{}    ", indent);
        self.print_item(child, c_prefix, c_indent);
    }

    fn print_item(&self, item: &Item, prefix: &str, indent: &str) {
        print!("{}", prefix);

        match &item.value {
            Value::Boolean(inner) => {
                println!("BOOLEAN {}", inner);
            }
            Value::Integer(inner) => {
                println!("INTEGER {}", self.bytes_to_string(&inner.0));
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
                let oid_name: Option<&str> = match self.registry {
                    Some(registry) => registry.lookup_long_name(&oid.0),
                    None => None,
                };

                match oid_name {
                    Some(oid_name) => println!("OBJECT {} ({})", oid_name, oid),
                    None => println!("OBJECT {}", oid),
                };
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
                self.print_list("Sequence", inner, indent);
            }
            Value::Set(inner) => {
                self.print_list("Set", inner, indent);
            }
            Value::Application(tag, inner) => {
                let label = &format!("Application ({})", tag);
                self.print_single_child(label, inner, indent);
            }
            Value::ContextSpecific(tag, inner) => {
                let label = &format!("ContextSpecific ({})", tag);
                self.print_single_child(label, inner, indent);
            }
            Value::Private(tag, inner) => {
                let label = &format!("Private ({})", tag);
                self.print_single_child(label, inner, indent);
            }
            Value::Unknown(ident, len) => {
                println!("Unknown {:?}, len = {}", ident, len)
            }
        }
    }

    pub fn print(&self, item: &Item) {
        self.print_item(item, "", "");
    }
}
