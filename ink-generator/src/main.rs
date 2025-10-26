use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::io::Cursor;
use byteorder::{BigEndian, ReadBytesExt};

/// Generates an ink! 6 verifier smart contract from a Noir VK
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the Noir VK file
    #[arg(short, long)]
    vk: PathBuf,
    /// Path to write the generated lib.rs file
    #[arg(short, long)]
    output: PathBuf,
}

fn main() {
    let args = Args::parse();

    println!("Starting generator...");
    println!("      -> Reading VK from: {:?}", args.vk);
    println!("      -> Writing contract to: {:?}", args.output);

    // Read the vk file
    // let vk_bytes = fs::read(args.vk).expect("Failed to read VK file");

    // Parse the VK bytes
    // let (alpha_g1, beta_g2, ..) = parse_vk(&vk_bytes);

    // Generate the contract code
    // let contract_code = generate_contract_code(alpha_g1, beta_g2, ...);

    // Placeholder
    let contract_code = generate_contract_code();

    // Write the code to the output file
    fs::write(&args.output, contract_code).expect("Failed to write output file");

    println!("Success! ink! v6 verifier contract generated at {:?}", args.output);
}

//Placeholder function
fn generate_contract_code() -> String {
    let template = include_str!("../templates/verifier.rs.template");

    template.to_string()
}
