use std::fmt;
use bytes::BufMut;

pub enum DecoderResult<T> {
    Finished(T),
    Overflow,
    Pending,
}

pub struct U64Decoder {
    res: u64,
    shift: u32,
}

impl U64Decoder {
    pub fn new() -> U64Decoder {
        U64Decoder {
            res: 0,
            shift: 0,
        }
    }

    pub fn input(&mut self, b: u8) -> DecoderResult<u64> {
        match ((b & 0x7f) as u64).checked_shl(self.shift) {
            None => DecoderResult::Overflow,
            Some(x) => {
                self.res |= x;
                self.shift += 7;
                if (b & 0x80) == 0 {
                    DecoderResult::Finished(self.res)
                }
                else {
                    DecoderResult::Pending
                }
            }
        }
    }
}

pub fn encode_usize<T>(value: usize, out: &mut T) where T : BufMut {
    encode_u64(value as u64, out);
}

pub fn encode_u64<T>(mut value: u64, out: &mut T) where T : BufMut {
    loop {
        let seven = value & 0x7f;
        value = value >> 7;
        if value != 0 {
            out.put_u8((seven | 0x80) as u8);
        }
        else {
            out.put_u8(seven as u8);
            break;
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum DecodeError {
    ValueTooLarge(u8),
    MissingFinalByte,
    MisplacedFinalByte,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for DecodeError {}

pub fn decode_u64(data: &[u8]) -> Result<u64, DecodeError> {
    let mut res: u64 = 0;
    let mut shift = 0;
    for (i, b) in data.iter().enumerate() {
        let seven_bits = b & 0x7f;
        let last = (b & 0x80) == 0;

        if shift >= 64 {
            return Err(DecodeError::ValueTooLarge(64));
        }
        if shift == 63 && *b > 1 {
            return Err(DecodeError::ValueTooLarge(64));
        }

        res |= (seven_bits as u64) << shift;

        shift += 7;
        if last {
            if i + 1 == data.len() {
                return Ok(res);
            }
            else {
                return Err(DecodeError::MisplacedFinalByte);
            }
        }
    }
    return Err(DecodeError::MissingFinalByte);
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use super::super::util::BinaryData;
    use rand::rngs::StdRng;
    use rand::{SeedableRng, RngCore};
    use super::{encode_u64, decode_u64, DecodeError};
    // use super::super::protobuf::VarInt;
    #[test]
    fn decode_empty() {
        assert_eq!(decode_u64(&[]), Err(DecodeError::MissingFinalByte));
    }

    #[test]
    fn decode_one_nonfinal() {
        assert_eq!(decode_u64(&[0x80]), Err(DecodeError::MissingFinalByte));
    }

    #[test]
    fn decode_normal() {
        assert_eq!(decode_u64(&[0xe3, 0xe7, 0xdb, 0x01]), Ok(0x36f3e3));
    }

    #[test]
    fn decode_multiple_nonfinal() {
        assert_eq!(decode_u64(&[0xe3, 0xe7, 0xdb, 0x81]), Err(DecodeError::MissingFinalByte));
    }

    #[test]
    fn decode_u64_max() {
        assert_eq!(decode_u64(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]), Ok(u64::MAX));
    }

    #[test]
    fn decode_one_too_many() {
        assert_eq!(decode_u64(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02]),
            Err(DecodeError::ValueTooLarge(64)));
    }

    #[test]
    fn decode_extra_byte() {
        assert_eq!(decode_u64(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]),
            Err(DecodeError::ValueTooLarge(64)));
    }

    #[test]
    fn enc_dec_1bits() -> Result<(), Box<dyn Error>> {
        let mut value: u64 = 0;
        println!("{:<64} {:<16} {:<20}", "value (binary)", "value (hex)", "encoded (hex)");
        for bits in 0..64 {
            value |= 1 << bits;

            let mut encoded: Vec<u8> = Vec::new();
            encode_u64(value, &mut encoded);

            println!("{:0>64b} {:0>16x} {:>20}",
                value,
                value,
                format!("{:?}", BinaryData(&encoded))
                );

            let decoded: u64 = decode_u64(&encoded)?;
            assert!(value == decoded);
        }
        Ok(())
    }

    #[test]
    fn enc_dec_random() -> Result<(), Box<dyn Error>> {
        let mut rng = StdRng::seed_from_u64(0);
        let mut mask: u64 = 0;
        println!("{:<64} {:<16} {:<20}", "value (binary)", "value (hex)", "encoded (hex)");
        for bits in 0..64 {
            mask |= 1 << bits;

            for _ in 0..16 {
                let value = rng.next_u64() & mask;

                let mut encoded: Vec<u8> = Vec::new();
                encode_u64(value, &mut encoded);
                println!("{:0>64b} {:0>16x} {:>20}",
                    value,
                    value,
                    format!("{:?}", BinaryData(&encoded))
                    );

                let decoded1: u64 = decode_u64(&encoded)?;
                assert!(value == decoded1);
            }
        }

        Ok(())
    }
}
