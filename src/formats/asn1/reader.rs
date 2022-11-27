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

#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::fmt;
use std::error::Error;
use std::ops::Range;
use crate::util::util::{BinaryData, DebugHexDump, Indent, escape_string};
use crate::util::binary::BinaryReader;
use crate::error;
use super::value::*;

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
        return Err(error!("Unsupported: tag >= 31"));
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
            return Err(error!("noctets is 127"));
        }
        else if noctets == 0 {
            return Err(error!("Unsupported: Indefinite form"));
        }
        else if noctets > 4 {
            return Err(error!("noctets cannot fit in u32"));
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

fn read_item_list<'a>(reader: &mut BinaryReader) -> Result<Vec<Item>, Box<dyn Error>> {
    let mut items: Vec<Item> = Vec::new();
    while reader.remaining() > 0 {
        // let old_offset = inner.offset;
        // let new_offset = inner.offset;
        let old_remaining = reader.remaining();
        items.push(read_item(reader)?);
        let new_remaining = reader.remaining();
        if new_remaining == old_remaining {
            return Err(error!("Value consumed 0 bytes"));
        }
    }
    Ok(items)
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
            return Err(error!("Value consumed 0 bytes"));
        }
    }
    Ok(ObjectIdentifier(parts))
}

pub fn read_item<'a>(reader: &mut BinaryReader) -> Result<Item, Box<dyn Error>> {
    let start = reader.abs_offset();
    let value = read_value(reader)?;
    let end = reader.abs_offset();
    Ok(Item {
        range: Range { start, end },
        value: value,
    })
}

fn read_value<'a>(reader: &mut BinaryReader) -> Result<Value, Box<dyn Error>> {
    let identifier = read_identifier(reader)?;
    let length = read_length(reader)?;
    let mut contents = reader.read_nested(length as usize)?;

    match identifier.class {
        Class::Universal => {
            match identifier.tag {
                1 => {
                    if identifier.form != Form::Primitive {
                        return Err(error!("Boolean: incorrect form"));
                    }
                    if contents.remaining() != 1 {
                        return Err(error!("Boolean: incorrect length"));
                    }
                    let byte = contents.read_u8()?;
                    if byte == 0x0 {
                        Ok(Value::Boolean(false))
                    }
                    else if byte == 0xff {
                        Ok(Value::Boolean(true))
                    }
                    else {
                        Err(error!("Boolean value must be all zeros or ones"))
                    }
                }
                2 => {
                    match identifier.form {
                        Form::Constructed => Err(error!("Integer: incorrect form")),
                        Form::Primitive => {
                            let bytes: Vec<u8> = contents.remaining_data().to_vec();
                            Ok(Value::Integer(Integer(bytes)))
                        }
                    }
                }
                3 => {
                    match identifier.form {
                        Form::Constructed => Err(error!("BitString: incorrect form")),
                        Form::Primitive => {
                            let unused_bits = contents.read_u8()?;
                            let bytes = contents.remaining_data().to_vec();
                            Ok(Value::BitString(BitString { unused_bits, bytes }))
                        }
                    }
                }
                4 => {
                    match identifier.form {
                        Form::Constructed => Err(error!("Octet string: incorrect form")),
                        Form::Primitive => {
                            let data: Vec<u8> = contents.remaining_data().to_vec();
                            Ok(Value::OctetString(data))
                        }
                    }
                }
                5 => {
                    if identifier.form != Form::Primitive {
                        return Err(error!("Null: incorrect form"));
                    }
                    if contents.remaining() != 0 {
                        return Err(error!("Null: incorrect length"));
                    }
                    Ok(Value::Null)
                }
                6 => {
                    if identifier.form != Form::Primitive {
                        return Err(error!("Object identifier: incorrect form"));
                    }
                    Ok(Value::ObjectIdentifier(read_object_identifier(&mut contents)?))
                }
                12 => {
                    match identifier.form {
                        Form::Constructed => Err(error!("UTF8String: incorrect form")),
                        Form::Primitive => {
                            let s = String::from_utf8(contents.remaining_data().to_vec())?;
                            Ok(Value::UTF8String(s))
                        }
                    }
                }
                16 => {
                    match identifier.form {
                        Form::Primitive => Err(error!("Sequence: incorrect form")),
                        Form::Constructed => Ok(Value::Sequence(read_item_list(&mut contents)?)),
                    }
                }
                17 => {
                    match identifier.form {
                        Form::Primitive => Err(error!("Set: incorrect form")),
                        Form::Constructed => Ok(Value::Set(read_item_list(&mut contents)?)),
                    }
                }
                19 => {
                    match identifier.form {
                        Form::Constructed => Err(error!("PrintableString: incorrect form")),
                        Form::Primitive => {
                            let s = String::from_utf8(contents.remaining_data().to_vec())?;
                            Ok(Value::PrintableString(s))
                        }
                    }
                }
                23 => {
                    match identifier.form {
                        Form::Constructed => Err(error!("UTCTime: incorrect form")),
                        Form::Primitive => {
                            let s = String::from_utf8(contents.remaining_data().to_vec())?;
                            Ok(Value::UTCTime(s))
                        }
                    }
                }
                24 => {
                    match identifier.form {
                        Form::Constructed => Err(error!("GeneralizedTime: incorrect form")),
                        Form::Primitive => {
                            let s = String::from_utf8(contents.remaining_data().to_vec())?;
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
