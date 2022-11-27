// https://en.wikipedia.org/wiki/Linear_congruential_generator#cite_note-Steele20-3
//
// Parameters from Microsoft Visual/Quick C/C++
// m = 2^32
// a = 214013
// c = 2531011

pub struct Generator {
    seed: u32,
    a: u32,
    c: u32,
}

impl Generator {
    pub fn new(seed: u32) -> Generator {
        Generator {
            a: 214013,
            c: 2531011,
            seed: seed,
        }
    }

    pub fn next_u32(&mut self) -> u32 {
        self.seed = self.a.wrapping_mul(self.seed).wrapping_add(self.c);
        self.seed
    }
}
