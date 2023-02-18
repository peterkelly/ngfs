#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]
#![allow(non_upper_case_globals)]

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    torrent::quic::spec::test()
}
