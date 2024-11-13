use std::time::Instant;
use clap::Parser;

mod rust;
use crate::rust::attack;


/// CLI Arguments for the Meet-in-the-Middle attack on PRESENT24
#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    plain1: Option<u32>,

    #[arg(short, long)]
    cipher1: Option<u32>,

    #[arg(short, long)]
    plain2: Option<u32>,

    #[arg(short, long)]
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
    println!("Durée totale de l'attaque : {:.1?}", duration);
}
