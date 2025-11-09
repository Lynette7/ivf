use clap::Parser;
use std::fs;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;

// A field is 32 bytes
const FIELD_SIZE: usize = 32;

/// Generates an ink! v6 verifier smart contract from a Noir VK
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

/// The VK is just a falt array of field elements
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
    let vk_bytes = fs::read(&args.vk).expect("Failed to read VK file");
    println!("      -> Read {} bytes.", vk_bytes.len());

    // Parse the VK bytes (flexible size)
    let vk = parse_vk(&vk_bytes).expect("Failed to parse VK file");
    println!(
        "      -> Successfully parsed VK with {} field elements.",
        vk.fields.len()
    );
    
    // Show first few elements for debugging
    println!("\n        VK Structure:");
    if vk.fields.len() >= 3 {
        println!("         Circuit size: 0x{}", hex_encode_last_bytes(&vk.fields[0], 4));
        println!("         Log size:     0x{}", hex_encode_last_bytes(&vk.fields[1], 4));
        println!("         Pub inputs:   0x{}", hex_encode_last_bytes(&vk.fields[2], 4));
    }

    // Generate the contract code
    let contract_code = generate_contract_code(&vk);

    // Write the code to the output file
    fs::write(&args.output, contract_code).expect("Failed to write output file");

    println!(
        "Success! ink! v6 verifier contract generated at {:?}",
        args.output
    );
    println!("   VK Length: {} field elements", vk.fields.len());
}

/// Parses the flat Barretenberg Honk vk file (flexible size)
fn parse_vk(vk_bytes: &[u8]) -> Result<VerificationKey, Error> {
    if vk_bytes.len() % FIELD_SIZE != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "Invalid VK file size. Must be multiple of {} bytes, got {}",
                FIELD_SIZE,
                vk_bytes.len()
            ),
        ));
    }

    // Calculate number of field elements
    let num_fields = vk_bytes.len() / FIELD_SIZE;
    
    if num_fields < 3 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("VK too small. Expected at least 3 field elements, got {}", num_fields),
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

    // Inject the VK length (actual number of field elements)
    let template = template.replace("%%VK_LEN%%", &vk.fields.len().to_string());

    // Inject the VK fields
    let template = template.replace("%%VK_FIELDS%%", &vk_fields_string);

    template
}

// Helper function to turn a byte array into a hex string
fn bytes_to_rust_hex_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("0x{:02x}", b))
        .collect::<Vec<String>>()
        .join(", ")
}

// Helper to show last N bytes as hex (for big-endian integers)
fn hex_encode_last_bytes(bytes: &[u8; 32], n: usize) -> String {
    let start = 32 - n;
    bytes[start..].iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}
