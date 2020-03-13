#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use torrent::bencoding;
use torrent::result::{Error, Result, error};
use torrent::torrent::{Torrent};
use crypto::digest::Digest;
use crypto::sha1::Sha1;

fn decode(data: &[u8]) -> Result<bencoding::Value> {
    match bencoding::parse(data) {
        Ok(v) => Ok(v),
        Err(e) => Err(Error::new(format!("Corrupt torrent: {}", e))),
    }
}

fn view_bencoding(data: &[u8]) -> Result<()> {
    let value = decode(data)?;
    value.dump(0);
    Ok(())
}

fn view_torrent(data: &[u8]) -> Result<()> {
    let torrent = Torrent::from_bytes(data)?;
    println!("Torrent loaded successfully");
    println!("    name = {}", torrent.name);
    println!("    info hash = {}", torrent.info_hash);
    for (group_index, group) in torrent.tracker_groups.iter().enumerate() {
        println!("    group {}", group_index);
        for (tracker_index, tracker) in group.members.iter().enumerate() {
            println!("        {}: {}", tracker_index, tracker.url);
        }
    }
    println!("    files");
    for file in torrent.files.iter() {
        println!("        {:<12} {}", file.length, file.path);
    }
    Ok(())
}

fn run(filename: &String) -> Result<()> {
    let data: Vec<u8> = match std::fs::read(filename) {
        Ok(data) => data,
        Err(err) => {
            return error(format!("Cannot read {}: {}", filename, err));
        }
    };

    view_bencoding(&data)?;
    println!("-----------");
    view_torrent(data.as_slice())?;
    Ok(())
}

type CommandFun = &'static dyn Fn(&[String]) -> Result<()>;

struct Command {
    name: String,
    f: CommandFun,
}

impl Command {
    fn new(name: &str, f: CommandFun) -> Command {
        Command { name: String::from(name), f: f }
    }
}

fn filename_arg(args: &[String], index: usize) -> Result<&String> {
    Ok(args.get(0).ok_or_else(|| Error::new("No filename specified"))?)
}

fn read_file_from_arg(args: &[String], index: usize) -> Result<Vec<u8>> {
    let filename = filename_arg(args, index)?;
    // Ok(std::fs::read(filename)?)
    std::fs::read(filename).map_err(|e| Error::new(&format!("{}: {}", filename, e)).into())
}

fn trackers(args: &[String]) -> Result<()> {
    let data = read_file_from_arg(args, 0)?;
    let torrent = Torrent::from_bytes(&data)?;
    for (group_index, group) in torrent.tracker_groups.iter().enumerate() {
        for (tracker_index, tracker) in group.members.iter().enumerate() {
            println!("{}", tracker.url);
        }
        if group_index + 1 < torrent.tracker_groups.len() {
            println!("");
        }
    }
    Ok(())
}

fn files(args: &[String]) -> Result<()> {
    let data = read_file_from_arg(args, 0)?;
    let torrent = Torrent::from_bytes(&data)?;
    for file in torrent.files.iter() {
        println!("{}", file.path);
    }
    Ok(())
}

fn info(args: &[String]) -> Result<()> {
    let data = read_file_from_arg(args, 0)?;
    let torrent = Torrent::from_bytes(&data)?;
    println!("Info hash: {}", torrent.info_hash);
    println!("Name: {}", torrent.name);

    // let mut group_count = 0;
    let mut tracker_count = 0;

    let group_count = torrent.tracker_groups.len();
    for group in torrent.tracker_groups.iter() {
        // group_count += 1;
        tracker_count += group.members.len();
    }
    println!("Tracker groups: {}", group_count);
    println!("Trackers: {}", tracker_count);
    println!("Piece length: {}", torrent.piece_length);
    println!("Pieces: {}", torrent.pieces.len());
    println!("Files: {}", torrent.files.len());

    Ok(())
}

fn hash(args: &[String]) -> Result<()> {
    let filename = filename_arg(args, 0)?;
    let data = read_file_from_arg(args, 0)?;
    let torrent = Torrent::from_bytes(&data)?;
    println!("{} {}", filename, torrent.info_hash);
    Ok(())
}

fn raw(args: &[String]) -> Result<()> {
    let data = read_file_from_arg(args, 0)?;
    view_bencoding(&data)
}

fn full(args: &[String]) -> Result<()> {
    // let data = read_file_from_arg(args, 0)?;
    let filename = filename_arg(args, 0)?;
    run(filename)
    // Ok(())
}

fn build_commands() -> Vec<Command> {
    let mut commands = Vec::<Command>::new();
    commands.push(Command::new("trackers", &trackers));
    commands.push(Command::new("files", &files));
    commands.push(Command::new("info", &info));
    commands.push(Command::new("hash", &hash));
    commands.push(Command::new("raw", &raw));
    commands.push(Command::new("full", &full));
    return commands;
}

fn print_usage(commands: &Vec<Command>) {
    // println!("Usage: view [OPTIONS] COMMAND [ARGS]...");
    // println!("");
    // println!("Options:");
    // println!("  --help  Show this message and exit.");
    // println!("");
    println!("Commands:");
    for command in commands.iter() {
        println!("  {}", command.name);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let commands = build_commands();

    let mut command_opt: Option<&Command> = None;
    if let Some(name) = args.get(1) {
        for c in commands.iter() {
            if name == &c.name {
                command_opt = Some(c);
                break;
            }
        }
    }

    match command_opt {
        Some(command) => {
            match (&command.f)(&args[2..]) {
                Ok(_) => {},
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            }
        }
        None => {
            print_usage(&commands);
            std::process::exit(1);
        }
    }
}
