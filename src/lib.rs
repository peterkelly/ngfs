pub mod result;
pub mod bencoding;
pub mod util;
pub mod torrent;
pub mod protobuf;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
