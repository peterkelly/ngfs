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

impl<'a> fmt::Debug for BinaryData<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
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
            let nlines = if self.0.len() == 0 { 1 } else { (self.0.len() + 15) / 16 };
            for lineno in 0..nlines {
                let start = lineno * 16;
                write!(f, "{:08x}", start)?;
                for i in start..start + 16 {
                    if i % 8 == 0 {
                        write!(f, " ")?;
                    }
                    if i < self.0.len() {
                        write!(f, " {:02x}", self.0[i])?;
                    }
                    else {
                        write!(f, "   ")?;
                    }
                }
                self.fmt_chars(start, f)?;
                if lineno + 1 < nlines {
                    write!(f, "\n")?;
                }
            }
        }
        Ok(())
    }
}

impl<'a> DebugHexDump<'a> {
    fn fmt_chars(&self, start: usize, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let end = std::cmp::min(start + 16, self.0.len());
        write!(f, "  |")?;
        for i in start..end {
            let byte = self.0[i];
            if byte >= 32 && byte <= 126 {
                write!(f, "{}", byte as char)?;
            }
            else {
                write!(f, ".")?;
            }
        }
        write!(f, "|")?;
        Ok(())
    }
}

pub struct Indent<'a>(pub &'a dyn fmt::Debug);

impl<'a> fmt::Debug for Indent<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use std::fmt::Write;
        let mut s = String::new();
        write!(s, "{:#?}", self.0)?;
        for (i, line) in s.lines().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            write!(f, "    {}", line)?;
        }
        Ok(())
    }
}
