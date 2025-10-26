use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::io::Cursor;
use byteorder::{BigEndian, ReadBytesExt};

// A field is 32 bytes
const FIELD_SIZE: usize = 32;
// The VK length
const HONK_VK_FIELDS: usize = 112;
const VK_TOTAL_BYTES: usize = FIELD_SIZE * HONK_VK_FIELDS;

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

/// The VK is just a falt array of 112 field elements
#[derive(Debug)]
struct VerificationKey {
    fields: Vec<[u8; 32]>,
}

fn main() {
    let args = Args::parse();

    println!("Starting Honk verifier generator...");
    println!("      -> Reading VK from: {:?}", args.vk);
    // println!("      -> Writing contract to: {:?}", args.output);

    // Read the vk file
    let vk_bytes = fs::read(args.vk).expect("Failed to read VK file");
    println!("      ->Read {} bytes.", vk_bytes.len());

    // Parse the VK bytes
    let vk = parse_vk(&vk_bytes).expect("Failed to parse VK file");
    println!("      -> Successfully parsed VK with {} field elements.", vk.fields.len());

    // Generate the contract code
    let contract_code = generate_contract_code(&vk);

    // Write the code to the output file
    fs::write(args.output.clone(), contract_code).expect("Failed to write output file");

    println!("Success! ink! v6 verifier contract generated at {:?}", args.output);
}

/// Parses the flat Barretenberg Honk vk file
fn parse_vk(vk_bytes: &[u8]) -> Result<VerificationKey, io::Error> {
    if vk_bytes.len() != VK_TOTAL_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Invalid VK file size. Expected {} bytes, but got {}",
                VK_TOTAL_BYTES,
                vk_bytes.len()
            ),
        ));
    }

    // slice the file into 32-byte field elements
    let fields: Vec<[u8; 32]> = vk_bytes
        .chunks_exact(FIELD_SIZE)
        .map(|chunk| {
            // Convert slice &[u8] to fixed-size array [u8; 32]
            chunk.try_into().expect("Chunk size is guaranteed to be 32")
        })
        .collect();

    Ok(VerificationKey { fields })
}

/// inject the VK fields into the ink! template
fn generate_contract_code(vk: &VerificationKey) -> String {
    let template = include_str!("../templates/verifier.rs.template");

    // Format the VK fields
    let vk_fields_string = vk
        .fields
        .iter()
        .map(|field| {
            // Format each 32-byte array: "[0x..., 0x..., ...]"
            format!("[{}]", bytes_to_rust_hex_string(field))
        })
        .collect::<Vec<String>>()
        .join(",\n    ");

    // Inject the VK length
    let template = template.replace("%%VK_LEN%%", &HONK_VK_FIELDS.to_string());

    // Inject the VK fields
    let template = template.replace("%%VK_FIELDS%%", &vk_fields_string);

    template
}

// Helper function to turn a byte array into a hex string
fn bytes_to_rust_hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("0x{:02x}", b)).collect::<Vec<String>>().join(", ")
}
