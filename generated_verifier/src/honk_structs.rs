#![cfg_attr(not(feature = "std"), no_std)]

use ink::prelude::vec::Vec;
use primitive_types::U256;

// Type alias for field elements
pub type Fr = U256;

// From: uint256 constant N = 32; [cite: 1]
pub const N: u32 = 32;
// From: uint256 constant LOG_N = 5; [cite: 1]
pub const LOG_N: u32 = 5;
// From: uint256 constant NUMBER_OF_PUBLIC_INPUTS = 4; [cite: 2]
pub const NUMBER_OF_PUBLIC_INPUTS: u32 = 4;

// From: struct Honk.G1Point [cite: 51]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct G1Point {
    pub x: Fr,
    pub y: Fr,
}

// From: struct Honk.G1ProofPoint [cite: 52]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct G1ProofPoint {
    pub x_0: Fr,
    pub x_1: Fr,
    pub y_0: Fr,
    pub y_1: Fr,
}

// From: struct Honk.VerificationKey [cite: 53-63]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
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
