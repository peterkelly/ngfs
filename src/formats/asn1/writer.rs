use std::error::Error;
use crate::error;
use super::value::{
    Class,
    Form,
    Value,
    Item,
};

#[allow(clippy::needless_range_loop)]
fn encode_length(length: usize, out: &mut Vec<u8>) {
    if length < 128 {
        out.push(length as u8);
        return;
    }

    let nbytes_offset = out.len();
    out.push(0);

    let be_bytes = length.to_be_bytes();
    let mut skip = 0;
    while skip < be_bytes.len() && be_bytes[skip] == 0 {
        skip += 1;
    }

    let nbytes = be_bytes.len() - skip;
    if nbytes == 0 {
        out[nbytes_offset] = 1;
        out.push(0);
    }
    else {
        out[nbytes_offset] = nbytes as u8;
        for i in skip..be_bytes.len() {
            out.push(be_bytes[i]);
        }
    }
    out[nbytes_offset] |= 0x80;
}

fn encode_identifier(
    class: Class,
    form: Form,
    tag: u32,
    out: &mut Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    if tag > 30 {
        return Err(error!("Unsupported ASN1 value: tag {} is > 30", tag));
    }
    let class: u8 = match class {
        Class::Universal => 0,
        Class::Application => 1,
        Class::ContextSpecific => 2,
        Class::Private => 3,
    };
    let form: u8 = match form {
        Form::Primitive => 0,
        Form::Constructed => 1,
    };
    let tag: u8 = tag as u8;
    let byte: u8 = (class << 6) | (form << 5) | tag;
    out.push(byte);
    Ok(())
}

fn encode_raw(
    out: &mut Vec<u8>,
    class: Class,
    form: Form,
    tag: u32,
    data: &[u8],
) -> Result<(), Box<dyn Error>> {
    encode_identifier(class, form, tag, out)?;
    encode_length(data.len(), out);
    out.extend_from_slice(data);
    Ok(())
}

fn write_var_u64(mut value: u64, data: &mut Vec<u8>) {
    let mut temp: Vec<u8> = Vec::new();
    let mut highbit: u8 = 0;
    while value >= 128 {
        temp.push(((value & 0x7f) as u8) | highbit);
        highbit = 0x80;
        value >>= 7;
    }
    temp.push((value as u8) | highbit);
    temp.reverse();
    data.extend_from_slice(&temp);
}

fn encode_item_list(items: &[Item], data: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
    for item in items {
        encode_item(item, data)?;
    }
    Ok(())
}

pub fn encode_item(item: &Item, out: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
    match &item.value {
        Value::Boolean(_)            => {
            encode_raw(out, Class::Universal, Form::Primitive, 1, &[0])
        }
        Value::Integer(inner)            => {
            encode_raw(out, Class::Universal, Form::Primitive, 2, &inner.0)
        }
        Value::BitString(inner)          => {
            let mut data: Vec<u8> = Vec::new();
            data.push(inner.unused_bits);
            data.extend_from_slice(&inner.bytes);

            encode_raw(out, Class::Universal, Form::Primitive, 3, &data)
        }
        Value::OctetString(inner)        => {
            encode_raw(out, Class::Universal, Form::Primitive, 4, inner)
        }
        Value::Null                  => {
            encode_raw(out, Class::Universal, Form::Primitive, 5, &[])
        }
        Value::ObjectIdentifier(oid)   => {
            let mut data: Vec<u8> = Vec::new();

            if oid.0.len() >= 2 {
                let first = oid.0[0];
                let second = oid.0[1];
                let component0 = first * 40 + second;
                write_var_u64(component0, &mut data);
            }

            for i in 2..oid.0.len() {
                write_var_u64(oid.0[i], &mut data);
            }

            encode_raw(out, Class::Universal, Form::Primitive, 6, &data)
        }
        Value::PrintableString(s)    => {
            encode_raw(out, Class::Universal, Form::Primitive, 19, s.as_bytes())
        }
        Value::UTF8String(s)         => {
            encode_raw(out, Class::Universal, Form::Primitive, 12, s.as_bytes())
        }
        Value::UTCTime(s)            => {
            encode_raw(out, Class::Universal, Form::Primitive, 23, s.as_bytes())
        }
        Value::GeneralizedTime(s)    => {
            encode_raw(out, Class::Universal, Form::Primitive, 23, s.as_bytes())
        }
        Value::Sequence(items)           => {
            let mut data: Vec<u8> = Vec::new();
            encode_item_list(items, &mut data)?;
            encode_raw(out, Class::Universal, Form::Constructed, 16, &data)
        }
        Value::Set(items)                => {
            let mut data: Vec<u8> = Vec::new();
            encode_item_list(items, &mut data)?;
            encode_raw(out, Class::Universal, Form::Constructed, 17, &data)
        }
        Value::Application(tag, child)     => {
            let mut data: Vec<u8> = Vec::new();
            encode_item(child, &mut data)?;
            encode_raw(out, Class::Application, Form::Constructed, *tag, &data)
        }
        Value::ContextSpecific(tag, child) => {
            let mut data: Vec<u8> = Vec::new();
            encode_item(child, &mut data)?;
            encode_raw(out, Class::ContextSpecific, Form::Constructed, *tag, &data)
        }
        Value::Private(tag, child)         => {
            let mut data: Vec<u8> = Vec::new();
            encode_item(child, &mut data)?;
            encode_raw(out, Class::Private, Form::Constructed, *tag, &data)
        }
        Value::Unknown(_, _)         => {
            Err("Unknown: not implemented".into())
        }
    }
}
