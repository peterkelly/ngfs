use std::fmt;

pub struct BinaryData<'a>(pub &'a [u8]);

impl<'a> fmt::Display for BinaryData<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let raw = s.as_bytes();
    if raw.len() % 2 != 0 {
        return None;
    }

    let mut i = 0;
    let mut bytes: Vec<u8> = Vec::new();
    while i + 2 <= raw.len() {
        let hi = hex_from_byte(raw[i]);
        let lo = hex_from_byte(raw[i + 1]);
        match (hi, lo) {
            (Some(hi), Some(lo)) => {
                bytes.push(hi << 4 | lo);
            },
            _ => return None,
        }
        i += 2;
    }
    return Some(bytes);

    fn hex_from_byte(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
}

pub fn escape_string(s: &str) -> String {
    let mut escaped: Vec<char> = Vec::new();
    escaped.push('\"');
    for c in s.chars() {
        match c {
            '"' => {
                escaped.push('\\');
                escaped.push('"');
            }
            '\r' => {
                escaped.push('\\');
                escaped.push('r');
            }
            '\n' => {
                escaped.push('\\');
                escaped.push('n');
            }
            _ => {
                escaped.push(c);
            }
        }
    }
    escaped.push('\"');
    return escaped.into_iter().collect();
}

pub struct DebugHexDump<'a>(pub &'a [u8]);

impl<'a> fmt::Debug for DebugHexDump<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !f.alternate() {
            for i in 0..self.0.len() {
                f.write_fmt(format_args!("{:02x}", self.0[i]))?;
                if i + 1 < self.0.len() {
                    f.write_str(" ")?;
                }
            }
        }
        else {
            for i in 0..self.0.len() {
                f.write_fmt(format_args!("{:02x}", self.0[i]))?;

                if (i + 1) == self.0.len() || (i + 1) % 16 == 0 {
                    f.write_str("\n")?;
                }
                else if (i + 1) % 8 == 0 {
                    f.write_str("   ")?;
                }
                else{
                    f.write_str(" ")?;
                }
            }
        }
        Ok(())
    }
}
