#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use tokio;
use std::env;
use std::error::Error;
use std::future::Future;
use torrent::result::{GeneralError, general_error};
use torrent::multibase::decode;
use torrent::util::{BinaryData};
use torrent::protobuf::{PBufReader, VarInt};
use torrent::cid::CID;
use torrent::p2p::p2p_test;

fn get_argument<'a>(args: &'a [String], index: usize, name: &str) -> Result<&'a String, Box<dyn Error>> {
    match args.get(index) {
        Some(command) => {
            Ok(command)
        }
        None => {
            Err(GeneralError::new(&format!("Missing argument: {}", name)))
        }
    }
}


async fn cid_command(args: &[String]) -> Result<(), Box<dyn Error>> {
    let cid_str = get_argument(args, 0, "cid")?;
    let cid_bytes = decode(cid_str)?;
    let cid = CID::from_string(&cid_str)?;
    println!("{:#?}", cid);

    Ok(())
}

async fn p2p_command(args: &[String]) -> Result<(), Box<dyn Error>> {
    let server_addr = get_argument(args, 0, "server_addr")?;
    p2p_test(&server_addr).await?;
    Ok(())
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let command = get_argument(&args, 1, "command")?;
    // println!("command = {}", command);

    match command.as_str() {
        "cid" => {
            cid_command(&args[2..]).await?;
            Ok(())
        }
        "p2p" => {
            p2p_command(&args[2..]).await?;
            Ok(())
        }
        _ => {
            Err(GeneralError::new(&format!("Unknown command: {}", command)))?
        }
    }
}
