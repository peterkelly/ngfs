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
