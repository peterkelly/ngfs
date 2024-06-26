use std::collections::BTreeMap;
use std::fmt;
use crate::util::util::BinaryData;

#[derive(Debug)]
pub struct ValueError {
    loc: Location,
    data: ValueErrorData,
}

impl std::error::Error for ValueError {
}

#[derive(Debug)]
enum ValueErrorData {
    InvalidUTF8String(std::string::FromUtf8Error),
    MissingDictionaryKey(String),
    IsNotType(String),
}

impl fmt::Display for ValueError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: ", self.loc.path)?;
        match &self.data {
            ValueErrorData::InvalidUTF8String(e) => {
                write!(f, "{}", e)
            }
            ValueErrorData::MissingDictionaryKey(key) => {
                write!(f, "Missing key: {}", key)
            }
            ValueErrorData::IsNotType(t) => {
                write!(f, "Expected {}", t)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Location {
    pub start: usize,
    pub end: usize,
    pub path: String,
}

impl Location {
    pub fn new(start: usize, end: usize, path: String) -> Location {
        Location { start, end, path }
    }
}

pub struct ByteString {
    pub loc: Location,
    pub data: Vec<u8>,
}

impl ByteString {
    pub fn as_string(&self) -> Result<String, ValueError> {
        match String::from_utf8(self.data.clone()) {
            Ok(s) => Ok(s),
            Err(e) => Err(ValueError {
                loc: self.loc.clone(),
                data: ValueErrorData::InvalidUTF8String(e),
            }),
        }
    }
}

pub struct Integer {
    pub loc: Location,
    pub value: usize,
}

pub struct List {
    pub loc: Location,
    pub items: Vec<Value>,
}

pub struct Dictionary {
    pub loc: Location,
    pub entries: BTreeMap<String, Value>,
}

impl Dictionary {
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.get(key)
    }

    pub fn get_required(&self, key: &str) -> Result<&Value, ValueError> {
        match self.entries.get(key) {
            Some(value) => Ok(value),
            None => Err(ValueError {
                loc: self.loc.clone(),
                data: ValueErrorData::MissingDictionaryKey(String::from(key))
            }),
        }
    }
}

pub enum Value {
    ByteString(ByteString),
    Integer(Integer),
    List(List),
    Dictionary(Dictionary),
}

impl Value {
    pub fn loc(&self) -> &Location {
        match self {
            Value::ByteString(b) => &b.loc,
            Value::Integer(i) => &i.loc,
            Value::List(l) => &l.loc,
            Value::Dictionary(d) => &d.loc,
        }
    }
}

impl Value {
    pub fn as_string(&self) -> Result<String, ValueError> {
        self.as_byte_string()?.as_string()
    }

    pub fn as_byte_string(&self) -> Result<&ByteString, ValueError> {
        match self {
            Value::ByteString(b) => Ok(b),
            _ => Err(ValueError {
                loc: self.loc().clone(),
                data: ValueErrorData::IsNotType(String::from("bytes")),
            }),
        }
    }

    pub fn as_integer(&self) -> Result<&Integer, ValueError> {
        match self {
            Value::Integer(i) => Ok(i),
            _ => Err(ValueError {
                loc: self.loc().clone(),
                data: ValueErrorData::IsNotType(String::from("integer")),
            }),
        }
    }

    pub fn as_list(&self) -> Result<&List, ValueError> {
        match self {
            Value::List(l) => Ok(l),
            _ => Err(ValueError {
                loc: self.loc().clone(),
                data: ValueErrorData::IsNotType(String::from("list")),
            }),
        }
    }

    pub fn as_dictionary(&self) -> Result<&Dictionary, ValueError> {
        match self {
            Value::Dictionary(d) => Ok(d),
            _ => Err(ValueError {
                loc: self.loc().clone(),
                data: ValueErrorData::IsNotType(String::from("dictionary")),
            }),
        }
    }

    pub fn dump(&self, indent: usize) {
        for _i in 0..indent {
            print!("    ");
        }
        match self {
            Value::ByteString(b) => {
                let data = &b.data;
                match String::from_utf8(data.clone()) {
                    Ok(s) => {
                        println!("{}", s);
                    }
                    Err(_) => {
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
                    for _ in 0..indent + 1 {
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
        ParseError { offset, path: String::from(path), msg: String::from(msg) }
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
        Parser { offset: 0, data }
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

    fn parse_usize(&mut self, path: &str) -> Result<usize, ParseError> {
        let start = self.offset;
        loop {
            match self.peek() {
                None => break,
                Some(b'0'..=b'9') => self.advance(),
                Some(_) => break,
            }
        }
        let end = self.offset;
        if end == start {
            return Err(self.error(path, "Expected a digit"));
        }

        let s = String::from_utf8(Vec::from(&self.data[start..end]))
            .map_err(|e| ParseError::new(start, path, &format!("{}", e)))?;

        let value = s.parse::<usize>()
            .map_err(|e| ParseError::new(start, path, &format!("{}", e)))?;

        Ok(value)
    }

    fn expect_byte(&mut self, path: &str, byte: u8) -> Result<(), ParseError> {
        match self.peek() {
            None => {
                Err(self.error(path, &format!("Expected {}, got end of file", byte_repr(byte))))
            }
            Some(b) if b != byte => {
                Err(self.error(path, &format!("Expected {}, got {}", byte_repr(byte), byte_repr(b))))
            }
            Some(_) => {
                self.advance();
                Ok(())
            }
        }
    }

    fn parse_byte_string(&mut self, path: &str) -> Result<Vec<u8>, ParseError> {
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

    fn parse_list(&mut self, path: &String) -> Result<Vec<Value>, ParseError> {
        self.expect_byte(path, b'l')?;
        let mut elements: Vec<Value> = Vec::new();
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
                Some(_) => {
                    elements.push(self.parse_node(&format!("{}/{}", path, index))?);
                    index += 1;
                }
            }
        }
        Ok(elements)
    }

    fn parse_utf8_string(&mut self, path: &str) -> Result<String, ParseError> {
        let start = self.offset;
        let data = self.parse_byte_string(path)?;
        String::from_utf8(data)
            .map_err(|e| ParseError::new(start, path, &format!("{}", e)))
    }

    fn parse_dict(&mut self, path: &String) -> Result<BTreeMap<String, Value>, ParseError> {
        self.expect_byte(path, b'd')?;
        let mut elements: BTreeMap<String, Value> = BTreeMap::new();
        loop {
            match self.peek() {
                None => { return Err(ParseError::new(self.offset, path, &String::from("Premature end of file"))); }
                Some(b'e') => {
                    self.advance();
                    break;
                }
                Some(_) => {
                    let key = self.parse_utf8_string(path)?;
                    let value = self.parse_node(&format!("{}/{}", path, key))?;
                    elements.insert(key, value);
                }
            }
        }
        Ok(elements)
    }

    fn parse_integer(&mut self, path: &str) -> Result<usize, ParseError> {
        self.expect_byte(path, b'i')?;
        let value = self.parse_usize(path)?;
        self.expect_byte(path, b'e')?;
        Ok(value)
    }

    fn parse_value(&mut self, path: &String) -> Result<Value, ParseError> {
        let start = self.offset;
        match self.peek() {
            None => Err(self.error(path, "Premature end of file")),
            Some(b'i') => self.parse_integer(path).map(|i| Value::Integer(Integer {
                loc: Location::new(start, self.offset, path.clone()),
                value: i
            })),
            Some(b'l') => self.parse_list(path).map(|l| Value::List(List {
                loc: Location::new(start, self.offset, path.clone()),
                items: l
            })),
            Some(b'd') => self.parse_dict(path).map(|d| Value::Dictionary(Dictionary {
                loc: Location::new(start, self.offset, path.clone()),
                entries: d
            })),
            Some(b'0'..=b'9') => self.parse_byte_string(path).map(|s| Value::ByteString(ByteString {
                loc: Location::new(start, self.offset, path.clone()),
                data: s
            })),
            Some(byte) => Err(self.error(path, &format!("Unknown value type: {}", byte))),
        }
    }

    fn parse_node(&mut self, path: &String) -> Result<Value, ParseError> {
        self.parse_value(path)
    }
}

fn byte_repr(value: u8) -> String {
    if (0x20..=0x7e).contains(&value) {
        format!("'{}'", String::from_utf8_lossy(&[value]))
    }
    else {
        format!("0x{:02x}", value)
    }
}

pub fn parse(data: &[u8]) -> Result<Value, ParseError> {
    let mut parser = Parser::new(data);
    parser.parse_node(&String::from(""))
}
