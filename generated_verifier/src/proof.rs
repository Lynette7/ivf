#![cfg_attr(not(feature = "std"), no_std)]

use crate::field::Fr;
use crate::honk_structs::{G1Point, G1ProofPoint};

/// UltraHonk proof structure
/// Contains commitments, evaluations, and opening proofs
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct Proof {
    // Witness commitments
    pub w_l: G1Point,
    pub w_r: G1Point,
    pub w_o: G1Point,
    pub w_4: G1Point,
    // Permutation commitment
    pub z_perm: G1Point,
    // Quotient commitments
    pub t_lo: G1Point,
    pub t_mid: G1Point,
    pub t_hi: G1Point,
    // Evaluations (field elements)
    pub a_eval: Fr,
    pub b_eval: Fr,
    pub c_eval: Fr,
    pub d_eval: Fr,
    pub s_eval: Fr,
    pub z_eval: Fr,
    pub z_lookup_eval: Fr,
    // Opening proof point
    pub opening_proof: G1ProofPoint,
}
