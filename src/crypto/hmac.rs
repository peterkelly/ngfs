use openssl::sha::Sha256;

pub const SHA256_BLOCK_SIZE: usize = 64;
pub const SHA256_DIGEST_SIZE: usize = 32;

pub struct HmacSha256 {
    k_xor_ipad: [u8; SHA256_BLOCK_SIZE],
    k_xor_opad: [u8; SHA256_BLOCK_SIZE],
    inner_hasher: Sha256,
}

impl HmacSha256 {
    pub fn new(key_slice: &[u8]) -> HmacSha256 {

        let mut key: [u8; SHA256_BLOCK_SIZE] = [0; SHA256_BLOCK_SIZE];

        if key_slice.len() > SHA256_BLOCK_SIZE {
            let mut key_hasher = Sha256::new();
            key_hasher.update(key_slice);
            let key_digest: [u8; 32] = key_hasher.finish();
            key[0..32].copy_from_slice(&key_digest);
        }
        else {
            key[0..key_slice.len()].copy_from_slice(key_slice);
        }

        let mut k_xor_ipad: [u8; SHA256_BLOCK_SIZE] = [0x36; SHA256_BLOCK_SIZE];
        let mut k_xor_opad: [u8; SHA256_BLOCK_SIZE] = [0x5c; SHA256_BLOCK_SIZE];

        for i in 0..SHA256_BLOCK_SIZE {
            k_xor_ipad[i] ^= key[i];
            k_xor_opad[i] ^= key[i];
        }

        let mut inner_hasher = Sha256::new();
        inner_hasher.update(&k_xor_ipad);

        HmacSha256 {
            k_xor_ipad,
            k_xor_opad,
            inner_hasher,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner_hasher.update(data);
    }

    pub fn finish(&mut self) -> [u8; 32] {
        let mut inner_hasher = Sha256::new();
        inner_hasher.update(&self.k_xor_ipad);
        std::mem::swap(&mut inner_hasher, &mut self.inner_hasher);

        // Compute HMAC
        let inner_digest = inner_hasher.finish();

        let mut outer_hasher = Sha256::new();
        outer_hasher.update(&self.k_xor_opad);
        outer_hasher.update(&inner_digest);
        outer_hasher.finish()
    }
}
