// https://luca.ntop.org/Teaching/Appunti/asn1.html

#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::fmt;
use std::error::Error;
use super::util::{BinaryData, DebugHexDump, Indent, escape_string};
use super::binary::BinaryReader;
use super::result::GeneralError;

#[derive(Debug, Eq, PartialEq)]
enum Class {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

#[derive(Debug, Eq, PartialEq)]
enum Form {
    Primitive,
    Constructed,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Identifier {
    class: Class,
    form: Form,
    tag: u32,
}

fn read_identifier<'a>(reader: &'a mut BinaryReader) -> Result<Identifier, Box<dyn Error>> {
    let first = reader.read_u8()?;
    let bit8 = (first & 0x80) == 0x80;
    let bit7 = (first & 0x40) == 0x40;
    let class = match (bit8, bit7) {
        (false, false) => Class::Universal,
        (false, true) => Class::Application,
        (true, false) => Class::ContextSpecific,
        (true, true) => Class::Private,
    };
    let bit6 = (first & 0x20) == 0x20;
    let form = match bit6 {
        false => Form::Primitive,
        true => Form::Constructed,
    };
    let bits51:u8 = first & 0x1f;

    if bits51 == 0x1f {
        return Err(GeneralError::new("Unsupported: tag >= 31"));
    }

    Ok(Identifier {
        class,
        form,
        tag: bits51 as u32,
    })
}

fn read_length<'a>(reader: &'a mut BinaryReader) -> Result<u32, Box<dyn Error>> {
    let first = reader.read_u8()?;
    if first & 0x80 == 0 {
        // short form
        return Ok((first & 0x7f) as u32);
    }
    else {
        // long form
        let noctets = first & 0x7f;
        if noctets == 0x7f {
            return Err(GeneralError::new("noctets is 127"));
        }
        else if noctets == 0 {
            return Err(GeneralError::new("Unsupported: Indefinite form"));
        }
        else if noctets > 4 {
            return Err(GeneralError::new("noctets cannot fit in u32"));
        }
        else {
            let mut length: u32 = 0;
            for i in 0..noctets {
                let byte = reader.read_u8()?;
                length = (length << 8) | (byte as u32);
            }
            return Ok(length)
        }
    }
}

/*

Table 1/X.208 Universal class tag assignments
1 Boolean
2 Integer
3 Bitstring
4 Octetstring
5 Null
6 Object identifier
7 Object descriptor
8 Eternal type
9 Real type
10 Enumerated type
12-15 reserved
16 Sequence and sequence-of
17 Set and Set-of
18-22 Character string types
25-27 Character string
24-24 Time types
28- Reserved


Table 6/X.208 List of character string types
18 NumericString
19 PrintableString
20 TeletexString (T61String)
21 VideotexString
26 VisibleString
22 IA5String
25 GraphicString
27 GeneralString
 */

pub struct ObjectIdentifier {
    parts: Vec<u64>,
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
    unused_bits: u8,
    bytes: Vec<u8>,
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

fn read_value_list<'a>(reader: &mut BinaryReader) -> Result<Vec<Value>, Box<dyn Error>> {
    let mut values: Vec<Value> = Vec::new();
    while reader.remaining() > 0 {
        // let old_offset = inner.offset;
        // let new_offset = inner.offset;
        let old_remaining = reader.remaining();
        values.push(read_value(reader)?);
        let new_remaining = reader.remaining();
        if new_remaining == old_remaining {
            return Err(GeneralError::new("Value consumed 0 bytes"));
        }
    }
    Ok(values)
}

fn read_var_u64(reader: &mut BinaryReader) -> Result<u64, Box<dyn Error>> {
    let mut value: u64 = 0;
    loop {
        let b = reader.read_u8()?;
        value = (value << 7) | ((b & 0x7f) as u64);
        if b & 0x80 == 0 {
            break;
        }
    }
    Ok(value)
}

fn read_object_identifier<'a>(reader: &mut BinaryReader) -> Result<ObjectIdentifier, Box<dyn Error>> {
    let mut parts: Vec<u64> = Vec::new();
    while reader.remaining() > 0 {
        // let old_offset = inner.offset;
        // let new_offset = inner.offset;
        let old_remaining = reader.remaining();
        let part = read_var_u64(reader)?;
        // 8.19.3 The number of subidentifiers (N) shall be one less than the number of object
        // identifier components in the object identifier value being encoded.
        //
        // 8.19.4 The numerical value of the first subidentifier is derived from the values of the
        // first two object identifier components in the object identifier value being encoded,
        // using the formula:
        //
        //     (X*40) + Y
        //
        // where X is the value of the first object identifier component and Y is the value of the
        // second object identifier component.


        if parts.len() == 0 {
            parts.push(part / 40);
            parts.push(part % 40);
        }
        else {
            parts.push(part);
        }
        let new_remaining = reader.remaining();
        if new_remaining == old_remaining {
            return Err(GeneralError::new("Value consumed 0 bytes"));
        }
    }
    Ok(ObjectIdentifier { parts: parts })
}

pub fn read_value<'a>(reader: &mut BinaryReader) -> Result<Value, Box<dyn Error>> {
    let identifier = read_identifier(reader)?;
    let length = read_length(reader)?;
    let mut contents = reader.read_nested(length as usize)?;

    match identifier.class {
        Class::Universal => {
            match identifier.tag {
                1 => {
                    if identifier.form != Form::Primitive {
                        return Err(GeneralError::new("Boolean: incorrect form"));
                    }
                    if contents.remaining() != 1 {
                        return Err(GeneralError::new("Boolean: incorrect length"));
                    }
                    let byte = contents.read_u8()?;
                    if byte == 0x0 {
                        Ok(Value::Boolean(false))
                    }
                    else if byte == 0xff {
                        Ok(Value::Boolean(true))
                    }
                    else {
                        Err(GeneralError::new("Boolean value must be all zeros or ones"))
                    }
                }
                2 => {
                    match identifier.form {
                        Form::Constructed => Err(GeneralError::new("Integer: incorrect form")),
                        Form::Primitive => {
                            let bytes: Vec<u8> = contents.remaining_data().to_vec();
                            Ok(Value::Integer(bytes))
                        }
                    }
                }
                3 => {
                    match identifier.form {
                        Form::Constructed => Err(GeneralError::new("BitString: incorrect form")),
                        Form::Primitive => {
                            let unused_bits = contents.read_u8()?;
                            let bytes = contents.remaining_data().to_vec();
                            Ok(Value::BitString(BitString { unused_bits, bytes }))
                        }
                    }
                }
                4 => {
                    match identifier.form {
                        Form::Constructed => Err(GeneralError::new("Octet string: incorrect form")),
                        Form::Primitive => {
                            let data: Vec<u8> = contents.remaining_data().to_vec();
                            Ok(Value::OctetString(data))
                        }
                    }
                }
                5 => {
                    if identifier.form != Form::Primitive {
                        return Err(GeneralError::new("Null: incorrect form"));
                    }
                    if contents.remaining() != 0 {
                        return Err(GeneralError::new("Null: incorrect length"));
                    }
                    Ok(Value::Null)
                }
                6 => {
                    if identifier.form != Form::Primitive {
                        return Err(GeneralError::new("Object identifier: incorrect form"));
                    }
                    Ok(Value::ObjectIdentifier(read_object_identifier(&mut contents)?))
                }
                12 => {
                    match identifier.form {
                        Form::Constructed => Err(GeneralError::new("UTF8String: incorrect form")),
                        Form::Primitive => {
                            let s = String::from_utf8(contents.remaining_data().to_vec())?;
                            Ok(Value::UTF8String(s))
                        }
                    }
                }
                16 => {
                    match identifier.form {
                        Form::Primitive => Err(GeneralError::new("Sequence: incorrect form")),
                        Form::Constructed => Ok(Value::Sequence(read_value_list(&mut contents)?)),
                    }
                }
                17 => {
                    match identifier.form {
                        Form::Primitive => Err(GeneralError::new("Set: incorrect form")),
                        Form::Constructed => Ok(Value::Set(read_value_list(&mut contents)?)),
                    }
                }
                19 => {
                    match identifier.form {
                        Form::Constructed => Err(GeneralError::new("PrintableString: incorrect form")),
                        Form::Primitive => {
                            let s = String::from_utf8(contents.remaining_data().to_vec())?;
                            Ok(Value::PrintableString(s))
                        }
                    }
                }
                23 => {
                    match identifier.form {
                        Form::Constructed => Err(GeneralError::new("UTCTime: incorrect form")),
                        Form::Primitive => {
                            let s = String::from_utf8(contents.remaining_data().to_vec())?;
                            Ok(Value::UTCTime(s))
                        }
                    }
                }
                24 => {
                    match identifier.form {
                        Form::Constructed => Err(GeneralError::new("GeneralizedTime: incorrect form")),
                        Form::Primitive => {
                            let s = String::from_utf8(contents.remaining_data().to_vec())?;
                            Ok(Value::GeneralizedTime(s))
                        }
                    }
                }
                _ => {
                    Ok(Value::Unknown(identifier, length)) // TODO
                }
                // _ => Err(GeneralError::new(format!("Unsupported value: tag {}", identifier.tag))),
            }
        }
        Class::Application => {
            match identifier.form {
                Form::Primitive => Ok(Value::Unknown(identifier, length)),
                Form::Constructed => Ok(Value::Application(read_value_list(&mut contents)?)),
            }
        }
        Class::ContextSpecific => {
            match identifier.form {
                Form::Primitive => Ok(Value::Unknown(identifier, length)),
                Form::Constructed => Ok(Value::ContextSpecific(read_value_list(&mut contents)?)),
            }
        }
        Class::Private => {
            match identifier.form {
                Form::Primitive => Ok(Value::Unknown(identifier, length)),
                Form::Constructed => Ok(Value::Private(read_value_list(&mut contents)?)),
            }
        }
        // Class::ContextSpecific => Err(GeneralError::new("Unsupported value: class is ContextSpecific")),
        // Class::Private => Err(GeneralError::new("Unsupported value: class is Private")),

        // Class::Application => Err(GeneralError::new("Unsupported value: class is Application")),
        // Class::ContextSpecific => Err(GeneralError::new("Unsupported value: class is ContextSpecific")),
        // Class::Private => Err(GeneralError::new("Unsupported value: class is Private")),
        // _ => Ok(Value::Unknown(identifier)),
    }

    // if identifier.form == Form::Primitive && identifier.tag == 1 {
    // }
    // else {
    //     Ok(Value::Unknown(identifier))
    //     // return Err(GeneralError::new(format!("Unknown identifier {:?}", identifier)))
    // }

    // unimplemented!()
}
