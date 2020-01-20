#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use torrent::bencoding;

pub struct Torrent {
}

impl Torrent {
    fn parse(data: &[u8]) -> Result<bencoding::BENode, String> {
        println!("data length = {}", data.len());
        Err(String::from("Cannot parse"))
    }
}

fn test_parse(data: &[u8]) {
    // let mut parser = BEParser::new(data);
    // let res = parser.parse_node(&String::from(""));
    let res = bencoding::parse(data);
    match res {
        Ok(node) => {
            node.dump(0);
        }
        Err(e) => {
            println!("Parse failed at offset {}, path \"{}\": {}", e.offset, e.path, e.msg);
        }
    }
}

// fn main() {
//     for i in 0..=255 {
//         println!("{:02x} -- {}", i, byte_repr(i));
//     }
// }

fn main() {
    // println!("Hello World!");

    let args: Vec<String> = std::env::args().collect();
    // println!("args.len() = {}", args.len());
    // for arg in &args {
    //     let x: i32 = arg;
    //     println!("arg: {}", arg);
    // }

    if args.len() < 2 {
        eprintln!("No filename specified");
        std::process::exit(1);
    }

    let filename: &String = &args[1];
    // println!("filename = {}", filename);

    let res = std::fs::read(filename);
    match res {
        Ok(data) => {
            // let a: () = x;
            // let parser = BEParser { offset: 0, data: data.as_slice() };
            test_parse(data.as_slice());
            // let torrent = Torrent::parse(data.as_slice());
        }
        Err(err) => {
            println!("Cannot read {}: {}", filename, err);
            std::process::exit(1);
            // let b: () = x;
        }
    }
}
