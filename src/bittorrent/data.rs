use std::fmt;

pub struct BitField {
    entries: Vec<bool>,
}

impl BitField {
    pub fn new(size: usize) -> Self {
        let mut entries: Vec<bool> = Vec::new();
        for _ in 0..size {
            entries.push(false);
        }
        BitField {
            entries
        }
    }

    pub fn num_set(&self) -> usize {
        let mut count = 0;
        for have_piece in self.entries.iter() {
            if *have_piece {
                count += 1;
            }
        }
        count
    }

    pub fn num_clear(&self) -> usize {
        let mut count = 0;
        for have_piece in self.entries.iter() {
            if !*have_piece {
                count += 1;
            }
        }
        count
    }

    pub fn update_from_bytes(&mut self, bytes: &[u8]) {
        for i in 0..self.entries.len() {
            let byte_index = i / 8;
            let bit_index = i % 8;
            if byte_index >= bytes.len() {
                return;
            }
            if bytes[byte_index] & (1 << 7 - bit_index) != 0 {
                self.entries[i] = true;
            }
            else {
                self.entries[i] = false;
            }
        }
    }
}

impl fmt::Debug for BitField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "<bitfield {}/{}>", self.num_set(), self.entries.len())
    }
}

// TODO: Make this a proper test?
pub fn test_bitfield_size() {
    for piece_count in 0..36 {
        let bitfield_size = (piece_count + 7) / 8;
        println!("piece_count {} bitfield_size {}", piece_count, bitfield_size);
    }
}

// TODO: Make this a proper test?
pub fn test_bitfield_update_from_bytes() {
    let mut bitfield = BitField::new(48);
    bitfield.update_from_bytes(&[0x5a, 0xa5, 0x03, 0x0c, 0x30, 0xc0]);
    // 01011010 10100101 00000011 00001100 00110000 11000000
    for i in 0..bitfield.entries.len() {
        // println!("bitfield.entries[{}] = {}", i, bitfield.entries[i]);
        if i > 0 && i % 8 == 0 {
            print!(" ");
        }
        if bitfield.entries[i] {
            print!("1");
        }
        else {
            print!("0");
        }
    }
    println!();
}
