#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::collections::BTreeMap;

pub struct BEString {
    pub data: Vec<u8>,
}

pub struct BEInteger {
    pub value: usize,
}

pub struct BEList {
    pub elements: Vec<BENode>,
}

pub struct BEDictionary {
    pub elements: BTreeMap<String, BENode>,
}

pub enum BEValue {
    String(BEString),
    Integer(BEInteger),
    List(Box<BEList>),
    Dictionary(Box<BEDictionary>),
}

pub struct BENode {
    start: usize,
    end: usize,
    value: BEValue,
}

impl BENode {
    fn dump(&self, indent: usize) {
        for i in 0..indent {
            print!("    ");
        }
        match &self.value {
            BEValue::String(be_string) => {
                match String::from_utf8(be_string.data.clone()) {
                    Ok(s) => {
                        println!("{}", s);
                    }
                    Err(e) => {
                        println!("<{} bytes of binary data>", be_string.data.len());
                    }
                }
            }
            BEValue::Integer(i) => {
                println!("{}", i.value);
            }
            BEValue::List(l) => {
                println!("list");
                for element in &l.elements {
                    element.dump(indent + 1);
                }
            }
            BEValue::Dictionary(d) => {
                println!("dict");
                for (key, value) in d.elements.iter() {
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

pub struct BEParser<'a> {
    offset: usize,
    data: &'a [u8],
}

pub struct ParseError {
    offset: usize,
    path: String,
    msg: String,
}

impl ParseError {
    fn new(offset: usize, path: &str, msg: &str) -> ParseError {
        ParseError { offset: offset, path: String::from(path), msg: String::from(msg) }
    }
}

impl<'a> BEParser<'a> {
    fn new(data: &[u8]) -> BEParser {
        BEParser { offset: 0, data: data }
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

    fn parse_bytestring(&mut self, path: &String) -> Result<BEString, ParseError> {
        let size = self.parse_usize(path)?;
        self.expect_byte(path, b':')?;

        let start = self.offset;
        let end = self.offset.checked_add(size).ok_or_else(|| self.error(path, "Integer overflow"))?;
        if end > self.data.len() {
            return Err(self.error(path, "String goes beyond end of file"));
        }

        let data: Vec<u8> = Vec::from(&self.data[start..end]);
        self.offset = end;
        Ok(BEString { data })
    }

    fn parse_list(&mut self, path: &String) -> Result<BEList, ParseError> {
        let start = self.offset;
        self.expect_byte(path, b'l')?;
        let mut elements: Vec<BENode> = Vec::new();
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
        Ok(BEList { elements: elements })
    }

    fn parse_dict(&mut self, path: &String) -> Result<BEDictionary, ParseError> {
        self.expect_byte(path, b'd')?;
        let mut elements: BTreeMap<String, BENode> = BTreeMap::new();
        loop {
            match self.peek() {
                None => { return Err(ParseError::new(self.offset, path, &String::from("Premature end of file"))); }
                Some(b'e') => {
                    self.advance();
                    break;
                }
                Some(byte) => {
                    let bekey_start = self.offset;
                    let bekey = self.parse_bytestring(path)?;
                    let key = match String::from_utf8(bekey.data) {
                        Err(e) => {
                            return Err(ParseError::new(bekey_start, path, "Invalid UTF-8 string"));
                        }
                        Ok(s) => s
                    };
                    let value = self.parse_node(&format!("{}/{}", path, key))?;
                    elements.insert(key, value);
                }
            }
        }
        Ok(BEDictionary { elements: elements })
    }

    fn parse_integer(&mut self, path: &String) -> Result<BEInteger, ParseError> {
        self.expect_byte(path, b'i')?;
        let value = self.parse_usize(path)?;
        self.expect_byte(path, b'e')?;
        Ok(BEInteger { value: value })
    }

    fn parse_value_inner(&mut self, path: &String) -> Result<BEValue, ParseError> {
        match self.peek() {
            None => Err(self.error(path, "Premature end of file")),
            Some(b'i') => self.parse_integer(path).map(|i| BEValue::Integer(i)),
            Some(b'l') => self.parse_list(path).map(|l| BEValue::List(Box::new(l))),
            Some(b'd') => self.parse_dict(path).map(|d| BEValue::Dictionary(Box::new(d))),
            Some(b'0'..=b'9') => self.parse_bytestring(path).map(|s| BEValue::String(s)),
            Some(byte) => Err(self.error(path, &format!("Unknown value type: {}", byte))),
        }
    }

    fn parse_node(&mut self, path: &String) -> Result<BENode, ParseError> {
        let start = self.offset;
        let value = self.parse_value_inner(path)?;
        let end = self.offset;
        Ok(BENode { start, end, value })
    }
}

pub struct Torrent {
}

impl Torrent {
    fn parse(data: &[u8]) -> Result<BEValue, String> {
        println!("data length = {}", data.len());
        Err(String::from("Cannot parse"))
    }
}

fn test_parse(data: &[u8]) {
    let mut parser = BEParser::new(data);
    let res = parser.parse_node(&String::from(""));
    match res {
        Ok(node) => {
            node.dump(0);
        }
        Err(e) => {
            println!("Parse failed at offset {}, path \"{}\": {}", e.offset, e.path, e.msg);
        }
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

// fn main() {
//     for i in 0..=255 {
//         println!("{:02x} -- {}", i, byte_repr(i));
//     }
// }

fn main() {
    // println!("Hello World!");

    let args: Vec<String> = std::env::args().collect();
    // println!("args.len() = {}", args.len());
    // for arg in &args {
    //     let x: i32 = arg;
    //     println!("arg: {}", arg);
    // }

    if args.len() < 2 {
        eprintln!("No filename specified");
        std::process::exit(1);
    }

    let filename: &String = &args[1];
    // println!("filename = {}", filename);

    let res = std::fs::read(filename);
    match res {
        Ok(data) => {
            // let a: () = x;
            // let parser = BEParser { offset: 0, data: data.as_slice() };
            test_parse(data.as_slice());
            // let torrent = Torrent::parse(data.as_slice());
        }
        Err(err) => {
            println!("Cannot read {}: {}", filename, err);
            std::process::exit(1);
            // let b: () = x;
        }
    }
}
