use std::time::Instant;
use clap::Parser;

mod rust;
use crate::rust::attack;


/// Parse the input string to hexadecimal.
fn hex_parser(s: &str) -> Result<u32, String> {
    match u32::from_str_radix(s.trim_start_matches("0x"), 16) {
        Ok(val) => Ok(val),
        Err(e) => Err(format!("Failed to parse hexadecimal number '{}': {}", s, e)),
    }
}


/// CLI Arguments for the Meet-in-the-Middle attack on PRESENT24
#[derive(Parser, Debug)]
/// Help message
#[command(
    name = "MitM Attack",
    about = "PRESENT24 Meet-In-The-Middle attack",
    override_usage = "cargo run [--release] [-- [--P <HEX>] [--cipher1 <HEX>] [--plain2 <HEX>] [--c <HEX>]]"
)]
struct Args {
    #[arg(short='P', long, value_parser=hex_parser, help="First plaintext (in hex format)")]
    plain1: Option<u32>,

    #[arg(short='C', long, value_parser=hex_parser, help="First cypher (in hex format)")]
    cipher1: Option<u32>,

    #[arg(short='p', long, value_parser=hex_parser, help="Second plaintext (in hex format)")]
    plain2: Option<u32>,

    #[arg(short='c', long, value_parser=hex_parser, help="Second cypher (in hex format)")]
    cipher2: Option<u32>,
}

fn main() {
    let args = Args::parse();

    // CLI inputs or default values of plaintext and ciphertext pairs for the MitM.
    let plain1 = args.plain1.unwrap_or(0xd41330);
    let cipher1 = args.cipher1.unwrap_or(0x2f4a58);
    let plain2 = args.plain2.unwrap_or(0x9d0af2);
    let cipher2 = args.cipher2.unwrap_or(0x57c9d6);

    println!("Starting MitM attack.");
    let start = Instant::now();
    attack::mitm_attack_present24(plain1, cipher1, plain2, cipher2);
    let duration = start.elapsed();
    println!("Total Meet-in-the-Middle attack time: {:.1?}", duration);
}
