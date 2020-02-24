#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::collections::BTreeMap;
use std::fmt;
use crate::util::BinaryData;
use crate::result::{GError, GResult, error};

pub struct Location {
    pub start: usize,
    pub end: usize,
    pub path: String,
}

pub struct ByteString {
    pub data: Vec<u8>,
}

pub struct Integer {
    pub value: usize,
}

pub struct List {
    pub items: Vec<Node>,
}

pub struct Dictionary {
    pub entries: BTreeMap<String, Node>,
}

pub enum Value {
    ByteString(ByteString),
    Integer(Integer),
    List(List),
    Dictionary(Dictionary),
}

impl Value {
    pub fn as_byte_string(&self) -> GResult<&Vec<u8>> {
        match self {
            Value::ByteString(b) => Ok(&b.data),
            _ => error("Not a byte string"),
        }
    }

    pub fn as_integer(&self) -> GResult<usize> {
        match self {
            Value::Integer(i) => Ok(i.value),
            _ => error("Not an integer"),
        }
    }

    pub fn as_list(&self) -> GResult<&Vec<Node>> {
        match self {
            Value::List(l) => Ok(&l.items),
            _ => error("Not a list"),
        }
    }

    pub fn as_dictionary(&self) -> GResult<&BTreeMap<String, Node>> {
        match self {
            Value::Dictionary(d) => Ok(&d.entries),
            _ => error("Not a dictionary"),
        }
    }
}

pub struct Node {
    // pub start: usize,
    // pub end: usize,
    pub loc: Location,
    pub value: Value,
}

impl Node {
    pub fn dump(&self, indent: usize) {
        for i in 0..indent {
            print!("    ");
        }
        match &self.value {
            Value::ByteString(b) => {
                let data = &b.data;
                match String::from_utf8(data.clone()) {
                    Ok(s) => {
                        println!("{}", s);
                    }
                    Err(e) => {
                        if data.len() <= 20 {
                            println!("{}", BinaryData(data))
                        }
                        else {
                            println!("<{} bytes of binary data>", data.len());
                        }
                    }
                }
            }
            Value::Integer(i) => {
                println!("{}", i.value);
            }
            Value::List(l) => {
                let elements = &l.items;
                println!("list");
                for element in elements {
                    element.dump(indent + 1);
                }
            }
            Value::Dictionary(d) => {
                let elements = &d.entries;
                println!("dict");
                for (key, value) in elements.iter() {
                    for i in 0..indent + 1 {
                        print!("    ");
                    }
                    println!("{} =", key);
                    value.dump(indent + 2);
                }
            }
        }
    }
}

pub struct Parser<'a> {
    offset: usize,
    data: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct ParseError {
    pub offset: usize,
    pub path: String,
    pub msg: String,
}

impl ParseError {
    fn new(offset: usize, path: &str, msg: &str) -> ParseError {
        ParseError { offset: offset, path: String::from(path), msg: String::from(msg) }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}


impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Offset {}, path \"{}\": {}", self.offset, self.path, self.msg)
    }
}

impl<'a> Parser<'a> {
    fn new(data: &[u8]) -> Parser {
        Parser { offset: 0, data: data }
    }

    fn error(&mut self, path: &str, msg: &str) -> ParseError {
        ParseError::new(self.offset, path, msg)
    }

    fn peek(&self) -> Option<u8> {
        if self.offset >= self.data.len() {
            None
        }
        else {
            Some(self.data[self.offset])
        }
    }

    fn advance(&mut self) {
        if self.offset < self.data.len() {
            self.offset += 1;
        }
    }

    fn parse_usize(&mut self, path: &String) -> Result<usize, ParseError> {
        let start = self.offset;
        loop {
            match self.peek() {
                None => break,
                Some(b'0'..=b'9') => self.advance(),
                Some(byte) => break,
            }
        }
        let end = self.offset;
        if end == start {
            return Err(self.error(path, "Expected a digit"));
        }

        let s = String::from_utf8(Vec::from(&self.data[start..end]))
            .or_else(|e| Err(ParseError::new(start, path, &format!("{}", e))))?;

        let value = s.parse::<usize>()
            .or_else(|e| Err(ParseError::new(start, path, &format!("{}", e))))?;

        Ok(value)
    }

    fn expect_byte(&mut self, path: &String, byte: u8) -> Result<(), ParseError> {
        match self.peek() {
            None => {
                Err(self.error(path, &format!("Expected {}, got end of file", byte_repr(byte))))
            }
            Some(b) if b != byte => {
                Err(self.error(path, &format!("Expected {}, got {}", byte_repr(byte), byte_repr(b))))
            }
            Some(b) => {
                self.advance();
                Ok(())
            }
        }
    }

    fn parse_byte_string(&mut self, path: &String) -> Result<Vec<u8>, ParseError> {
        let size = self.parse_usize(path)?;
        self.expect_byte(path, b':')?;

        let start = self.offset;
        let end = self.offset.checked_add(size).ok_or_else(|| self.error(path, "Integer overflow"))?;
        if end > self.data.len() {
            return Err(self.error(path, "String goes beyond end of file"));
        }

        let data: Vec<u8> = Vec::from(&self.data[start..end]);
        self.offset = end;
        Ok(data)
    }

    fn parse_list(&mut self, path: &String) -> Result<Vec<Node>, ParseError> {
        let start = self.offset;
        self.expect_byte(path, b'l')?;
        let mut elements: Vec<Node> = Vec::new();
        let mut index: usize = 0;
        loop {
            match self.peek() {
                None => {
                    return Err(self.error(path, &String::from("Premature end of file")));
                }
                Some(b'e') => {
                    self.advance();
                    break;
                }
                Some(byte) => {
                    elements.push(self.parse_node(&format!("{}/{}", path, index))?);
                    index += 1;
                }
            }
        }
        Ok(elements)
    }

    fn parse_utf8_string(&mut self, path: &String) -> Result<String, ParseError> {
        let start = self.offset;
        let data = self.parse_byte_string(path)?;
        String::from_utf8(data)
            .or_else(|e| Err(ParseError::new(start, path, &format!("{}", e))))
    }

    fn parse_dict(&mut self, path: &String) -> Result<BTreeMap<String, Node>, ParseError> {
        self.expect_byte(path, b'd')?;
        let mut elements: BTreeMap<String, Node> = BTreeMap::new();
        loop {
            match self.peek() {
                None => { return Err(ParseError::new(self.offset, path, &String::from("Premature end of file"))); }
                Some(b'e') => {
                    self.advance();
                    break;
                }
                Some(byte) => {
                    let key = self.parse_utf8_string(path)?;
                    let value = self.parse_node(&format!("{}/{}", path, key))?;
                    elements.insert(key, value);
                }
            }
        }
        Ok(elements)
    }

    fn parse_integer(&mut self, path: &String) -> Result<usize, ParseError> {
        self.expect_byte(path, b'i')?;
        let value = self.parse_usize(path)?;
        self.expect_byte(path, b'e')?;
        Ok(value)
    }

    fn parse_value(&mut self, path: &String) -> Result<Value, ParseError> {
        match self.peek() {
            None => Err(self.error(path, "Premature end of file")),
            Some(b'i') => self.parse_integer(path).map(|i| Value::Integer(Integer { value: i })),
            Some(b'l') => self.parse_list(path).map(|l| Value::List(List { items: l })),
            Some(b'd') => self.parse_dict(path).map(|d| Value::Dictionary(Dictionary { entries: d })),
            Some(b'0'..=b'9') => self.parse_byte_string(path).map(|s| Value::ByteString(ByteString { data: s })),
            Some(byte) => Err(self.error(path, &format!("Unknown value type: {}", byte))),
        }
    }

    fn parse_node(&mut self, path: &String) -> Result<Node, ParseError> {
        let start = self.offset;
        let value = self.parse_value(path)?;
        let end = self.offset;
        Ok(Node {
            loc: Location {
                start: start,
                end: end,
                path: path.clone(),
            },
            value: value,
        })
    }
}

fn byte_repr(value: u8) -> String {
    if value >= 0x20 && value <= 0x7e {
        format!("'{}'", String::from_utf8_lossy(&[value]))
    }
    else {
        format!("0x{:02x}", value)
    }
}

pub fn parse(data: &[u8]) -> Result<Node, ParseError> {
    let mut parser = Parser::new(data);
    parser.parse_node(&String::from(""))
}
