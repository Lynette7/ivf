#![cfg_attr(not(feature = "std"), no_std)]

use ink::prelude::format;
use primitive_types::U256;
use ink::prelude::string::String;

// Type alias for field elements
pub type Fr = U256;

// Field element size
const FIELD_SIZE: usize = 32;
// From: uint256 constant N = 32; [cite: 1]
pub const N: u32 = 32;
// From: uint256 constant LOG_N = 5; [cite: 1]
pub const LOG_N: u32 = 5;
// From: uint256 constant NUMBER_OF_PUBLIC_INPUTS = 4; [cite: 2]
pub const NUMBER_OF_PUBLIC_INPUTS: u32 = 4;

// From: struct Honk.G1Point [cite: 51]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct G1Point {
    pub x: Fr,
    pub y: Fr,
}

// From: struct Honk.G1ProofPoint [cite: 52]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct G1ProofPoint {
    pub x_0: Fr,
    pub x_1: Fr,
    pub y_0: Fr,
    pub y_1: Fr,
}

// From: struct Honk.VerificationKey [cite: 53-63]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VerificationKey {
    pub circuit_size: Fr,
    pub log_circuit_size: Fr,
    pub public_inputs_size: Fr,
    pub ql: G1Point,
    pub qr: G1Point,
    pub qo: G1Point,
    pub q4: G1Point,
    pub qm: G1Point,
    pub qc: G1Point,
    pub q_arith: G1Point,
    pub q_delta_range: G1Point,
    pub q_elliptic: G1Point,
    pub q_aux: G1Point,
    pub q_lookup: G1Point,
    pub q_poseidon2_external: G1Point,
    pub q_poseidon2_internal: G1Point,
    pub s1: G1Point,
    pub s2: G1Point,
    pub s3: G1Point,
    pub s4: G1Point,
    pub t1: G1Point,
    pub t2: G1Point,
    pub t3: G1Point,
    pub t4: G1Point,
    pub id1: G1Point,
    pub id2: G1Point,
    pub id3: G1Point,
    pub id4: G1Point,
    pub lagrange_first: G1Point,
    pub lagrange_last: G1Point,
}

/// Parse VK bytes into structured VerificationKey
pub fn parse_vk_structured(vk_bytes: &[u8]) -> Result<VerificationKey, String> {
    if vk_bytes.len() != 128 * FIELD_SIZE {
        return Err(format!("Invalid VK size: {}", vk_bytes.len()));
    }

    let mut offset = 0;

    // Helper to read next field element
    let read_fr = |offset: &mut usize| -> U256 {
        let bytes: [u8; 32] = vk_bytes[*offset..*offset + 32]
            .try_into()
            .expect("slice with incorrect length");
        *offset += 32;
        U256::from_big_endian(&bytes)
    };

    // Helper to read next G1 point
    let read_g1 = |offset: &mut usize| -> G1Point {
        G1Point {
            x: read_fr(offset),
            y: read_fr(offset),
        }
    };

    Ok(VerificationKey {
        circuit_size: read_fr(&mut offset),
        log_circuit_size: read_fr(&mut offset),
        public_inputs_size: read_fr(&mut offset),
        ql: read_g1(&mut offset),
        qr: read_g1(&mut offset),
        qo: read_g1(&mut offset),
        q4: read_g1(&mut offset),
        qm: read_g1(&mut offset),
        qc: read_g1(&mut offset),
        q_arith: read_g1(&mut offset),
        q_delta_range: read_g1(&mut offset),
        q_elliptic: read_g1(&mut offset),
        q_aux: read_g1(&mut offset),
        q_lookup: read_g1(&mut offset),
        q_poseidon2_external: read_g1(&mut offset),
        q_poseidon2_internal: read_g1(&mut offset),
        s1: read_g1(&mut offset),
        s2: read_g1(&mut offset),
        s3: read_g1(&mut offset),
        s4: read_g1(&mut offset),
        t1: read_g1(&mut offset),
        t2: read_g1(&mut offset),
        t3: read_g1(&mut offset),
        t4: read_g1(&mut offset),
        id1: read_g1(&mut offset),
        id2: read_g1(&mut offset),
        id3: read_g1(&mut offset),
        id4: read_g1(&mut offset),
        lagrange_first: read_g1(&mut offset),
        lagrange_last: read_g1(&mut offset),
    })
}
