// https://www.obj-sys.com/asn1tutorial/node124.html
// https://luca.ntop.org/Teaching/Appunti/asn1.html

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

use std::ops::Range;
use std::fmt;
use crate::util::binary::{BinaryReader, BinaryError};
use super::value::*;

pub enum Error {
    Binary(BinaryError),
    Plain(&'static str),
    InvalidUTF8String(std::string::FromUtf8Error),
}

impl std::error::Error for Error {
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Binary(e) => write!(f, "{}", e),
            Error::Plain(e) => write!(f, "{}", e),
            Error::InvalidUTF8String(e) => write!(f, "{}", e),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

fn read_identifier(reader: &mut BinaryReader) -> Result<Identifier, Error> {
    let first = reader.read_u8().map_err(Error::Binary)?;
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
        return Err(Error::Plain("Unsupported: tag >= 31"));
    }

    Ok(Identifier {
        class,
        form,
        tag: bits51 as u32,
    })
}

fn read_length(reader: &mut BinaryReader) -> Result<u32, Error> {
    let first = reader.read_u8().map_err(Error::Binary)?;
    if first & 0x80 == 0 {
        // short form
        Ok((first & 0x7f) as u32)
    }
    else {
        // long form
        let noctets = first & 0x7f;
        if noctets == 0x7f {
            Err(Error::Plain("noctets is 127"))
        }
        else if noctets == 0 {
            Err(Error::Plain("Unsupported: Indefinite form"))
        }
        else if noctets > 4 {
            Err(Error::Plain("noctets cannot fit in u32"))
        }
        else {
            let mut length: u32 = 0;
            for _ in 0..noctets {
                let byte = reader.read_u8().map_err(Error::Binary)?;
                length = (length << 8) | (byte as u32);
            }
            Ok(length)
        }
    }
}

fn read_item_list(reader: &mut BinaryReader) -> Result<Vec<Item>, Error> {
    let mut items: Vec<Item> = Vec::new();
    while reader.remaining() > 0 {
        // let old_offset = inner.offset;
        // let new_offset = inner.offset;
        let old_remaining = reader.remaining();
        items.push(read_item(reader)?);
        let new_remaining = reader.remaining();
        if new_remaining == old_remaining {
            return Err(Error::Plain("Value consumed 0 bytes"));
        }
    }
    Ok(items)
}

fn read_var_u64(reader: &mut BinaryReader) -> Result<u64, Error> {
    let mut value: u64 = 0;
    loop {
        let b = reader.read_u8().map_err(Error::Binary)?;
        value = (value << 7) | ((b & 0x7f) as u64);
        if b & 0x80 == 0 {
            break;
        }
    }
    Ok(value)
}

fn read_object_identifier(reader: &mut BinaryReader) -> Result<ObjectIdentifier, Error> {
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


        if parts.is_empty() {
            parts.push(part / 40);
            parts.push(part % 40);
        }
        else {
            parts.push(part);
        }
        let new_remaining = reader.remaining();
        if new_remaining == old_remaining {
            return Err(Error::Plain("Value consumed 0 bytes"));
        }
    }
    Ok(ObjectIdentifier(parts))
}

pub fn read_item(reader: &mut BinaryReader) -> Result<Item, Error> {
    let start = reader.abs_offset();
    let value = read_value(reader)?;
    let end = reader.abs_offset();
    Ok(Item {
        range: Range { start, end },
        value,
    })
}

fn read_value(reader: &mut BinaryReader) -> Result<Value, Error> {
    let identifier = read_identifier(reader)?;
    let length = read_length(reader)?;
    let mut contents = reader.read_nested(length as usize).map_err(Error::Binary)?;

    match identifier.class {
        Class::Universal => {
            match identifier.tag {
                1 => {
                    if identifier.form != Form::Primitive {
                        return Err(Error::Plain("Boolean: incorrect form"));
                    }
                    if contents.remaining() != 1 {
                        return Err(Error::Plain("Boolean: incorrect length"));
                    }
                    let byte = contents.read_u8().map_err(Error::Binary)?;
                    if byte == 0x0 {
                        Ok(Value::Boolean(false))
                    }
                    else if byte == 0xff {
                        Ok(Value::Boolean(true))
                    }
                    else {
                        Err(Error::Plain("Boolean value must be all zeros or ones"))
                    }
                }
                2 => {
                    match identifier.form {
                        Form::Constructed => Err(Error::Plain("Integer: incorrect form")),
                        Form::Primitive => {
                            let bytes: Vec<u8> = contents.remaining_data().to_vec();
                            Ok(Value::Integer(Integer(bytes)))
                        }
                    }
                }
                3 => {
                    match identifier.form {
                        Form::Constructed => Err(Error::Plain("BitString: incorrect form")),
                        Form::Primitive => {
                            let unused_bits = contents.read_u8().map_err(Error::Binary)?;
                            let bytes = contents.remaining_data().to_vec();
                            Ok(Value::BitString(BitString { unused_bits, bytes }))
                        }
                    }
                }
                4 => {
                    match identifier.form {
                        Form::Constructed => Err(Error::Plain("Octet string: incorrect form")),
                        Form::Primitive => {
                            let data: Vec<u8> = contents.remaining_data().to_vec();
                            Ok(Value::OctetString(data))
                        }
                    }
                }
                5 => {
                    if identifier.form != Form::Primitive {
                        return Err(Error::Plain("Null: incorrect form"));
                    }
                    if contents.remaining() != 0 {
                        return Err(Error::Plain("Null: incorrect length"));
                    }
                    Ok(Value::Null)
                }
                6 => {
                    if identifier.form != Form::Primitive {
                        return Err(Error::Plain("Object identifier: incorrect form"));
                    }
                    Ok(Value::ObjectIdentifier(read_object_identifier(&mut contents)?))
                }
                12 => {
                    match identifier.form {
                        Form::Constructed => Err(Error::Plain("UTF8String: incorrect form")),
                        Form::Primitive => {
                            let s = String::from_utf8(contents.remaining_data().to_vec())
                                .map_err(Error::InvalidUTF8String)?;
                            Ok(Value::UTF8String(s))
                        }
                    }
                }
                16 => {
                    match identifier.form {
                        Form::Primitive => Err(Error::Plain("Sequence: incorrect form")),
                        Form::Constructed => Ok(Value::Sequence(read_item_list(&mut contents)?)),
                    }
                }
                17 => {
                    match identifier.form {
                        Form::Primitive => Err(Error::Plain("Set: incorrect form")),
                        Form::Constructed => Ok(Value::Set(read_item_list(&mut contents)?)),
                    }
                }
                19 => {
                    match identifier.form {
                        Form::Constructed => Err(Error::Plain("PrintableString: incorrect form")),
                        Form::Primitive => {
                            let s = String::from_utf8(contents.remaining_data().to_vec())
                                .map_err(Error::InvalidUTF8String)?;
                            Ok(Value::PrintableString(s))
                        }
                    }
                }
                23 => {
                    match identifier.form {
                        Form::Constructed => Err(Error::Plain("UTCTime: incorrect form")),
                        Form::Primitive => {
                            let s = String::from_utf8(contents.remaining_data().to_vec())
                                .map_err(Error::InvalidUTF8String)?;
                            Ok(Value::UTCTime(s))
                        }
                    }
                }
                24 => {
                    match identifier.form {
                        Form::Constructed => Err(Error::Plain("GeneralizedTime: incorrect form")),
                        Form::Primitive => {
                            let s = String::from_utf8(contents.remaining_data().to_vec())
                                .map_err(Error::InvalidUTF8String)?;
                            Ok(Value::GeneralizedTime(s))
                        }
                    }
                }
                _ => {
                    Ok(Value::Unknown(identifier, length)) // TODO
                }
                // _ => Err(error!("Unsupported value: tag {}", identifier.tag)),
            }
        }
        Class::Application => {
            let tag = identifier.tag;
            match identifier.form {
                Form::Primitive => Ok(Value::Unknown(identifier, length)),
                Form::Constructed => Ok(Value::Application(tag, Box::new(read_item(&mut contents)?))),
            }
        }
        Class::ContextSpecific => {
            let tag = identifier.tag;
            match identifier.form {
                Form::Primitive => Ok(Value::Unknown(identifier, length)),
                Form::Constructed => Ok(Value::ContextSpecific(tag, Box::new(read_item(&mut contents)?))),
            }
        }
        Class::Private => {
            let tag = identifier.tag;
            match identifier.form {
                Form::Primitive => Ok(Value::Unknown(identifier, length)),
                Form::Constructed => Ok(Value::Private(tag, Box::new(read_item(&mut contents)?))),
            }
        }
        // Class::ContextSpecific => Err(error!("Unsupported value: class is ContextSpecific")),
        // Class::Private => Err(error!("Unsupported value: class is Private")),

        // Class::Application => Err(error!("Unsupported value: class is Application")),
        // Class::ContextSpecific => Err(error!("Unsupported value: class is ContextSpecific")),
        // Class::Private => Err(error!("Unsupported value: class is Private")),
        // _ => Ok(Value::Unknown(identifier)),
    }

    // if identifier.form == Form::Primitive && identifier.tag == 1 {
    // }
    // else {
    //     Ok(Value::Unknown(identifier))
    //     // return Err(error!("Unknown identifier {:?}", identifier))
    // }

    // unimplemented!()
}
