pub mod result;
pub mod bencoding;
pub mod util;
pub mod torrent;
pub mod protobuf;
pub mod detrand;
pub mod multibase;
pub mod cid;
pub mod p2p;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
