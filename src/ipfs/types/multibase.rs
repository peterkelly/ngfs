use std::iter::FromIterator;
use std::error::Error;
use std::fmt;


#[derive(Debug, Clone)]
pub enum DecodeError {
    EmptyString,
    InvalidLength(usize),
    InvalidChar(usize, u8),
    UnsupportedEncoding(char),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DecodeError::EmptyString => {
                write!(f, "Empty string")
            }
            DecodeError::InvalidLength(len) => {
                write!(f, "Invalid length: {}", len)
            }
            DecodeError::InvalidChar(offset, c) => {
                write!(f, "Invalid character at offset {}: '{}'", offset, c)
            }
            DecodeError::UnsupportedEncoding(c) => {
                match c {
                    '1' => {
                        write!(f, "Unknown encoding format: {} (looks like a base58-encoded \
                                   identity multihash from a peer id)", c)
                    }
                    'Q' => {
                        write!(f, "Unknown encoding format: {} (looks like a base58-encoded \
                                   sha2-256 multihash from a peer id or CIDv0)", c)
                    }
                    _ => {
                        write!(f, "Unknown encoding format: {}", c)
                    }
                }
            }
        }
    }
}

impl Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

const BASE16_LOWER: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];

const BASE16_UPPER: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'];

const BASE32_UPPER: [char; 32] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7'];

const BASE32_LOWER: [char; 32] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
    'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '2', '3', '4', '5', '6', '7'];

const BASE58_BTC: [char; 58] = [
    '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
    'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p',
    'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];

const BASE58_FLICKR: [char; 58] = [
    '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
    'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'];

const BASE64_ALPHABET: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
    'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
    'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
    'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'];

const BASE64_URL_ALPHABET: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
    'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
    'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
    'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'];

// https://github.com/multiformats/multibase
#[derive(Clone, Copy, Debug)]
pub enum Base {
    // Identity,          // 0x00, 8-bit binary (encoder and decoder keeps data unmodified), default
    // Base2,             // 0,    binary (01010101),                                        candidate
    // Base8,             // 7,    octal,                                                    draft
    // Base10,            // 9,    decimal,                                                  draft
    Base16,            // f,    hexadecimal,                                              default
    Base16Upper,       // F,    hexadecimal,                                              default
    // Base32hex,         // v,    rfc4648 no padding - highest char,                        candidate
    // Base32hexupper,    // V,    rfc4648 no padding - highest char,                        candidate
    // Base32hexpad,      // t,    rfc4648 with padding,                                     candidate
    // Base32hexpadupper, // T,    rfc4648 with padding,                                     candidate
    Base32,            // b,    rfc4648 no padding,                                       default
    Base32Upper,       // B,    rfc4648 no padding,                                       default
    Base32Pad,         // c,    rfc4648 with padding,                                     candidate
    Base32PadUpper,    // C,    rfc4648 with padding,                                     candidate
    // Base32z,           // h,    z-base-32 (used by Tahoe-LAFS),                           draft
    Base58Flickr,      // Z,    base58 flicker,                                           candidate
    Base58BTC,         // z,    base58 bitcoin,                                           default
    Base64,            // m,    rfc4648 no padding,                                       default
    Base64Pad,         // M,    rfc4648 with padding - MIME encoding,                     candidate
    Base64URL,         // u,    rfc4648 no padding,                                       default
    Base64URLPad,      // U,    rfc4648 with padding,                                     default
}

const AVAILABLE_BASES: &[Base] = &[
    Base::Base16,
    Base::Base16Upper,
    Base::Base32,
    Base::Base32Upper,
    Base::Base32Pad,
    Base::Base32PadUpper,
    Base::Base58Flickr,
    Base::Base58BTC,
    Base::Base64,
    Base::Base64Pad,
    Base::Base64URL,
    Base::Base64URLPad,
];

impl Base {
    pub fn available() -> &'static [Base] {
        AVAILABLE_BASES
    }

    pub fn for_code(code: char) -> Option<Base> {
        match code {
            'f' => Some(Base::Base16),
            'F' => Some(Base::Base16Upper),
            'b' => Some(Base::Base32),
            'B' => Some(Base::Base32Upper),
            'c' => Some(Base::Base32Pad),
            'C' => Some(Base::Base32PadUpper),
            'Z' => Some(Base::Base58Flickr),
            'z' => Some(Base::Base58BTC),
            'm' => Some(Base::Base64),
            'M' => Some(Base::Base64Pad),
            'u' => Some(Base::Base64URL),
            'U' => Some(Base::Base64URLPad),
            _    => None,
        }
    }

    pub fn for_name(name: &str) -> Option<Base> {
        match name {
            "base16"         => Some(Base::Base16),
            "base16upper"    => Some(Base::Base16Upper),
            "base32"         => Some(Base::Base32),
            "base32upper"    => Some(Base::Base32Upper),
            "base32pad"      => Some(Base::Base32Pad),
            "base32padupper" => Some(Base::Base32PadUpper),
            "base58flickr"   => Some(Base::Base58Flickr),
            "base58btc"      => Some(Base::Base58BTC),
            "base64"         => Some(Base::Base64),
            "base64pad"      => Some(Base::Base64Pad),
            "base64url"      => Some(Base::Base64URL),
            "base64urlpad"   => Some(Base::Base64URLPad),
            _                => None,
        }
    }

    pub fn code(&self) -> char {
        match self {
            Base::Base16         => 'f',
            Base::Base16Upper    => 'F',
            Base::Base32         => 'b',
            Base::Base32Upper    => 'B',
            Base::Base32Pad      => 'c',
            Base::Base32PadUpper => 'C',
            Base::Base58Flickr   => 'Z',
            Base::Base58BTC      => 'z',
            Base::Base64         => 'm',
            Base::Base64Pad      => 'M',
            Base::Base64URL      => 'u',
            Base::Base64URLPad   => 'U',
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Base::Base16         => "base16",
            Base::Base16Upper    => "base16upper",
            Base::Base32         => "base32",
            Base::Base32Upper    => "base32upper",
            Base::Base32Pad      => "base32pad",
            Base::Base32PadUpper => "base32padupper",
            Base::Base58Flickr   => "base58flickr",
            Base::Base58BTC      => "base58btc",
            Base::Base64         => "base64",
            Base::Base64Pad      => "base64pad",
            Base::Base64URL      => "base64url",
            Base::Base64URLPad   => "base64urlpad",
        }
    }
}

enum Case {
    Upper,
    Lower,
}

pub fn encode(data: &[u8], base: Base) -> String {
    let chars_vec = vec![base.code()];
    encode_inner(data, base, chars_vec)
}

pub fn encode_noprefix(data: &[u8], base: Base) -> String {
    let chars_vec: Vec<char> = Vec::new();
    encode_inner(data, base, chars_vec)
}

fn encode_inner(data: &[u8], base: Base, mut chars_vec: Vec<char>) -> String {
    match base {
        Base::Base16         => encode_base16(&mut chars_vec, data, &BASE16_LOWER),
        Base::Base16Upper    => encode_base16(&mut chars_vec, data, &BASE16_UPPER),
        Base::Base32         => encode_base32(&mut chars_vec, data, Case::Lower, false),
        Base::Base32Upper    => encode_base32(&mut chars_vec, data, Case::Upper, false),
        Base::Base32Pad      => encode_base32(&mut chars_vec, data, Case::Lower, true),
        Base::Base32PadUpper => encode_base32(&mut chars_vec, data, Case::Upper, true),
        Base::Base58Flickr   => encode_base58(&mut chars_vec, data, &BASE58_FLICKR),
        Base::Base58BTC      => encode_base58(&mut chars_vec, data, &BASE58_BTC),
        Base::Base64         => encode_base64(&mut chars_vec, data, &BASE64_ALPHABET, None),
        Base::Base64Pad      => encode_base64(&mut chars_vec, data, &BASE64_ALPHABET, Some('=')),
        Base::Base64URL      => encode_base64(&mut chars_vec, data, &BASE64_URL_ALPHABET, None),
        Base::Base64URLPad   => encode_base64(&mut chars_vec, data, &BASE64_URL_ALPHABET, Some('=')),
    }
    String::from_iter(chars_vec.into_iter())
}

pub fn decode(s: &str) -> Result<Vec<u8>, DecodeError> {
    let code = s.chars().next().ok_or(DecodeError::EmptyString)?;
    let base = Base::for_code(code).ok_or(DecodeError::UnsupportedEncoding(code))?;
    match s.char_indices().nth(1) {
        Some((data_index, _)) => decode_noprefix(&s[data_index..], base),
        None => Ok(Vec::new())
    }
}

pub fn decode_noprefix(s: &str, base: Base) -> Result<Vec<u8>, DecodeError> {
    match base {
        Base::Base16         => decode_basen(s.as_bytes(), 4, &BASE16_LOWER_INV, false),
        Base::Base16Upper    => decode_basen(s.as_bytes(), 4, &BASE16_UPPER_INV, false),
        Base::Base32         => decode_basen(s.as_bytes(), 5, &BASE32_LOWER_INV, false),
        Base::Base32Upper    => decode_basen(s.as_bytes(), 5, &BASE32_UPPER_INV, false),
        Base::Base32Pad      => decode_basen(s.as_bytes(), 5, &BASE32_LOWER_INV, true),
        Base::Base32PadUpper => decode_basen(s.as_bytes(), 5, &BASE32_UPPER_INV, true),
        Base::Base64         => decode_basen(s.as_bytes(), 6, &BASE64_ALPHABET_INV, false),
        Base::Base64Pad      => decode_basen(s.as_bytes(), 6, &BASE64_ALPHABET_INV, true),
        Base::Base64URL      => decode_basen(s.as_bytes(), 6, &BASE64_URL_ALPHABET_INV, false),
        Base::Base64URLPad   => decode_basen(s.as_bytes(), 6, &BASE64_URL_ALPHABET_INV, true),
        Base::Base58Flickr   => decode_base58(s.as_bytes(), &BASE58_FLICKR_INV),
        Base::Base58BTC      => decode_base58(s.as_bytes(), &BASE58_BTC_INV),
    }
}

// https://tools.ietf.org/id/draft-msporny-base58-01.html

fn encode_base58(chars_vec: &mut Vec<char>, data: &[u8], alphabet: &[char; 58]) {
    let mut bytes = Vec::from(data);
    let mut zero_counter: usize = 0;
    let mut encoding_flag: bool = false;
    let mut b58_bytes: Vec<u8> = Vec::new();
    loop {
        let mut zeros = 0;
        while zeros < bytes.len() && bytes[zeros] == 0 {
            zeros += 1;
        }

        if !encoding_flag {
            zero_counter = zeros;
            encoding_flag = true;
        }

        if zeros == bytes.len() {
            break;
        }

        let mut carry: u16 = 0;
        for i in 0..bytes.len() {
            carry = (carry << 8) | (bytes[i] as u16);
            bytes[i] = (carry / 58) as u8;
            carry %= 58;
        }
        b58_bytes.push(carry as u8);
    }

    for _ in 0..zero_counter {
        chars_vec.push(alphabet[0]);
    }
    for b in b58_bytes.into_iter().rev() {
        chars_vec.push(alphabet[b as usize]);
    }
}

fn decode_base58(encoded: &[u8], inv_alphabet: &[u8; 128]) -> Result<Vec<u8>, DecodeError> {
    let mut decoded: Vec<u8> = Vec::new();
    let mut zero_count = 0;
    while zero_count < encoded.len() && encoded[zero_count] == b'1' {
        zero_count += 1;
    }

    for (offset, ch) in encoded.iter().enumerate() {
        let mut carry: u16 = match inv_alphabet.get(*ch as usize) {
            None => return Err(DecodeError::InvalidChar(offset, *ch)),
            Some(0xff) => return Err(DecodeError::InvalidChar(offset, *ch)),
            Some(b) => *b as u16,
        };

        for b in decoded.iter_mut() {
            carry += (*b as u16) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }

        while carry > 0 {
            decoded.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    decoded.resize(decoded.len() + zero_count, 0);

    decoded.reverse();
    Ok(decoded)
}

// https://tools.ietf.org/html/rfc4648

fn encode_base16(chars_vec: &mut Vec<char>, data: &[u8], alphabet: &[char; 16]) {
    for b in data {
        chars_vec.push(alphabet[(b >> 4) as usize]);
        chars_vec.push(alphabet[(b & 0xf) as usize]);
    }
}

// https://tools.ietf.org/html/rfc4648

fn encode_base32(chars_vec: &mut Vec<char>, data: &[u8], case: Case, padding: bool) {
    let mut offset: usize = 0;

    let alphabet: &[char; 32] = match case {
        Case::Upper => &BASE32_UPPER,
        Case::Lower => &BASE32_LOWER,
    };

    let last = match data.len() % 5 {
        1 => 2,
        2 => 4,
        3 => 5,
        4 => 7,
        _ => 8,
    };

    while offset < data.len() {
        let input0: u8 = data[offset];
        let input1: u8 = match data.get(offset + 1) { Some(v) => *v, None => 0 };
        let input2: u8 = match data.get(offset + 2) { Some(v) => *v, None => 0 };
        let input3: u8 = match data.get(offset + 3) { Some(v) => *v, None => 0 };
        let input4: u8 = match data.get(offset + 4) { Some(v) => *v, None => 0 };

        let outputs: [u8; 8] = [
            input0 >> 3,
            ((input0 << 2)  & 0x1f) | (input1 >> 6),
            (input1 >> 1) & 0x1f,
            ((input1 << 4) & 0x1f) | (input2 >> 4),
            ((input2 << 1) & 0x1f) | (input3 >> 7),
            (input3 >> 2) & 0x1f,
            ((input3 << 3) & 0x1f) | (input4 >> 5),
            input4 & 0x1f,
        ];

        let include = if offset + 5 > data.len() { last } else { 8 };

        for i in 0..include {
            chars_vec.push(alphabet[outputs[i] as usize]);
        }
        if padding {
            for _ in include..8 {
                chars_vec.push('=');
            }
        }
        offset += 5;
    }
}

fn decode_basen(encoded_bytes: &[u8], pow2: u8, inv_alphabet: &[u8; 128], padding: bool) -> Result<Vec<u8>, DecodeError> {
    // println!("decode_basen: encoded_bytes.len() = {}", encoded_bytes.len());
    let mut output_bytes: Vec<u8> = Vec::new();
    let mut byte: u8 = 0;
    let mut shift: u8 = 0;

    let mut offset = 0;
    while offset < encoded_bytes.len() {
        let eb = encoded_bytes[offset];
        if padding && eb == b'=' {
            break;
        }
        match inv_alphabet.get(eb as usize) {
            None => return Err(DecodeError::InvalidChar(offset, eb)),
            Some(0xff) => return Err(DecodeError::InvalidChar(offset, eb)),
            Some(b) => {
                for i in (8 - pow2)..8 {
                    let bit = (b >> (7 - i)) & 0x1;
                    byte |= bit << (7 - shift);
                    shift = (shift + 1) % 8;
                    if shift == 0 {
                        output_bytes.push(byte);
                        byte = 0;
                    }
                }
            }
        }
        offset += 1;
    }

    Ok(output_bytes)
}

// https://tools.ietf.org/html/rfc4648

fn encode_base64(chars_vec: &mut Vec<char>, data: &[u8], alphabet: &[char; 64], padding: Option<char>) {
    let mut offset: usize = 0;

    while offset + 3 <= data.len() {
        let input0: u8 = data[offset];
        let input1: u8 = data[offset + 1];
        let input2: u8 = data[offset + 2];
        let output0: u8 = input0 >> 2;
        let output1: u8 = ((input0 << 4) & 0x30) | (input1 >> 4);
        let output2: u8 = ((input1 << 2) & 0x3c) | (input2 >> 6);
        let output3: u8 = input2 & 0x3f;
        chars_vec.push(alphabet[output0 as usize]);
        chars_vec.push(alphabet[output1 as usize]);
        chars_vec.push(alphabet[output2 as usize]);
        chars_vec.push(alphabet[output3 as usize]);
        offset += 3;
    }

    assert!((offset == data.len()) || (offset + 1 == data.len()) || (offset + 2 == data.len()));

    if offset + 1 == data.len() {
        let input0: u8 = data[offset];
        let output0: u8 = input0 >> 2;
        let output1: u8 = (input0 << 4) & 0x30;
        chars_vec.push(alphabet[output0 as usize]);
        chars_vec.push(alphabet[output1 as usize]);
        if let Some(padding_char) = padding {
            chars_vec.push(padding_char);
            chars_vec.push(padding_char);
        }
    }
    else if offset + 2 == data.len() {
        let input0: u8 = data[offset];
        let input1: u8 = data[offset + 1];
        let output0: u8 = input0 >> 2;
        let output1: u8 = ((input0 << 4) & 0x30) | (input1 >> 4);
        let output2: u8 = (input1 << 2) & 0x3c;
        chars_vec.push(alphabet[output0 as usize]);
        chars_vec.push(alphabet[output1 as usize]);
        chars_vec.push(alphabet[output2 as usize]);
        if let Some(padding_char) = padding {
            chars_vec.push(padding_char);
        }
    }
}

fn gen_inverse(name: &str, alphabet: &[char]) {
    let mut mapping: [u8; 256] = [0xff; 256];
    for (index, c) in alphabet.iter().enumerate() {
        let b = *c as u8;
        mapping[b as usize] = index as u8;
    }
    println!("const {}_INV: [u8; 128] = [", name);

    let mut index = 0;
    for hi in 0..8 {
        print!("    ");
        for lo in 0..16 {
            print!("0x{:02x}", mapping[index]);
            if lo + 1 < 16 {
                print!(", ");
            }
            index += 1;
        }

        if hi + 1 < 8 {
            println!(",");
        }
        else {
            println!("];");
        }
    }
    println!();
}

pub fn gen_inverse_all() {
    gen_inverse("BASE16_LOWER", &BASE16_LOWER);
    gen_inverse("BASE16_UPPER", &BASE16_UPPER);
    gen_inverse("BASE32_UPPER", &BASE32_UPPER);
    gen_inverse("BASE32_LOWER", &BASE32_LOWER);
    gen_inverse("BASE58_BTC", &BASE58_BTC);
    gen_inverse("BASE58_FLICKR", &BASE58_FLICKR);
    gen_inverse("BASE64_ALPHABET", &BASE64_ALPHABET);
    gen_inverse("BASE64_URL_ALPHABET", &BASE64_URL_ALPHABET);
}

// Below generated by gen_inverse_all()

const BASE16_LOWER_INV: [u8; 128] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

const BASE16_UPPER_INV: [u8; 128] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

const BASE32_UPPER_INV: [u8; 128] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

const BASE32_LOWER_INV: [u8; 128] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff];

const BASE58_BTC_INV: [u8; 128] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0xff, 0x11, 0x12, 0x13, 0x14, 0x15, 0xff,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0xff, 0x2c, 0x2d, 0x2e,
    0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0xff, 0xff, 0xff, 0xff, 0xff];

const BASE58_FLICKR_INV: [u8; 128] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0xff, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0xff,
    0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0xff, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0xff, 0xff, 0xff, 0xff, 0xff];

const BASE64_ALPHABET_INV: [u8; 128] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff];

const BASE64_URL_ALPHABET_INV: [u8; 128] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff, 0xff,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0x3f,
    0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff];

