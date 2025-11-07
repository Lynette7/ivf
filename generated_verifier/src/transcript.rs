#![cfg_attr(not(feature = "std"), no_std)]

use ink::prelude::vec::Vec;
use primitive_types::U256;
use crate::field::{Fr, to_bytes_be};
use crate::honk_structs::*;


// Circuit constants
const CONST_PROOF_SIZE_LOG_N: usize = 28;
const NUMBER_OF_SUBRELATIONS: usize = 26;
const BATCHED_RELATION_PARTIAL_LENGTH: usize = 8;
const NUMBER_OF_ENTITIES: usize = 40;
const NUMBER_UNSHIFTED: usize = 35;
const NUMBER_TO_BE_SHIFTED: usize = 5;
const NUMBER_OF_ALPHAS: usize = 25;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof {
    pub w1: G1ProofPoint,
    pub w2: G1ProofPoint,
    pub w3: G1ProofPoint,
    pub w4: G1ProofPoint,
    pub z_perm: G1ProofPoint,
    pub lookup_read_counts: G1ProofPoint,
    pub lookup_read_tags: G1ProofPoint,
    pub lookup_inverses: G1ProofPoint,
    pub sumcheck_univariates: [[Fr; BATCHED_RELATION_PARTIAL_LENGTH]; CONST_PROOF_SIZE_LOG_N],
    pub sumcheck_evaluations: [Fr; NUMBER_OF_ENTITIES],
    pub gemini_fold_comms: [G1ProofPoint; CONST_PROOF_SIZE_LOG_N - 1],
    pub gemini_a_evaluations: [Fr; CONST_PROOF_SIZE_LOG_N],
    pub shplonk_q: G1ProofPoint,
    pub kzg_quotient: G1ProofPoint,
}

impl Default for Proof {
    fn default() -> Self {
        Proof {
            w1: G1ProofPoint::default(),
            w2: G1ProofPoint::default(),
            w3: G1ProofPoint::default(),
            w4: G1ProofPoint::default(),
            z_perm: G1ProofPoint::default(),
            lookup_read_counts: G1ProofPoint::default(),
            lookup_read_tags: G1ProofPoint::default(),
            lookup_inverses: G1ProofPoint::default(),
            sumcheck_univariates: [[U256::zero(); BATCHED_RELATION_PARTIAL_LENGTH]; CONST_PROOF_SIZE_LOG_N],
            sumcheck_evaluations: [U256::zero(); NUMBER_OF_ENTITIES],
            gemini_fold_comms: [G1ProofPoint::default(); CONST_PROOF_SIZE_LOG_N - 1],
            gemini_a_evaluations: [U256::zero(); CONST_PROOF_SIZE_LOG_N],
            shplonk_q: G1ProofPoint::default(),
            kzg_quotient: G1ProofPoint::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Transcript {
    pub relation_parameters: RelationParameters,
    pub alphas: [Fr; NUMBER_OF_ALPHAS as usize],
    pub gate_challenges: [Fr; CONST_PROOF_SIZE_LOG_N as usize],
    pub sumcheck_u_challenges: [Fr; CONST_PROOF_SIZE_LOG_N as usize],
    pub rho: Fr,
    pub gemini_r: Fr,
    pub shplonk_nu: Fr,
    pub shplonk_z: Fr,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelationParameters {
    pub eta: Fr,
    pub eta_two: Fr,
    pub eta_three: Fr,
    pub beta: Fr,
    pub gamma: Fr,
    pub public_inputs_delta: Fr,
}

/// Split a 256-bit challenge into two 128-bit challenges
fn split_challenge(challenge: Fr) -> (Fr, Fr) {
    let lo_mask = U256::from_dec_str(
        "340282366920938463463374607431768211455" // 2^128 - 1
    ).unwrap();
    
    let lo = challenge & lo_mask;
    let hi = challenge >> 128;
    
    (lo, hi)
}

/// Hash using SHA256 (via precompile)
fn hash_to_field(data: &[u8]) -> Fr {
    // In actual implementation, call SHA256 precompile
    // For now, simplified
    use ink::env::hash::{HashOutput, Sha2x256};
    let mut output = <Sha2x256 as HashOutput>::Type::default();
    ink::env::hash_bytes::<Sha2x256>(data, &mut output);
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&output[..32]);
    U256::from_big_endian(&hash_bytes)
}

impl Transcript {
    /// Generate complete transcript from proof and public inputs
    pub fn generate(
        proof: &Proof,
        public_inputs: &[Vec<u8>],
        circuit_size: Fr,
        public_inputs_size: Fr,
        pub_inputs_offset: Fr,
    ) -> Self {
        let mut prev_challenge = U256::zero();
        
        // Generate eta challenges
        let (eta, eta_two, eta_three, prev) = 
            Self::generate_eta_challenge(proof, public_inputs, circuit_size, public_inputs_size, pub_inputs_offset);
        prev_challenge = prev;
        
        // Generate beta and gamma
        let (beta, gamma, prev) = Self::generate_beta_gamma(prev_challenge, proof);
        prev_challenge = prev;
        
        let relation_parameters = RelationParameters {
            eta,
            eta_two,
            eta_three,
            beta,
            gamma,
            public_inputs_delta: U256::zero(), // Computed later
        };
        
        // Generate alphas
        let (alphas, prev) = Self::generate_alphas(prev_challenge, proof);
        prev_challenge = prev;
        
        // Generate gate challenges
        let (gate_challenges, prev) = Self::generate_gate_challenges(prev_challenge);
        prev_challenge = prev;
        
        // Generate sumcheck challenges
        let (sumcheck_u_challenges, prev) = Self::generate_sumcheck_challenges(proof, prev_challenge);
        prev_challenge = prev;
        
        // Generate rho
        let (rho, prev) = Self::generate_rho(proof, prev_challenge);
        prev_challenge = prev;
        
        // Generate gemini_r
        let (gemini_r, prev) = Self::generate_gemini_r(proof, prev_challenge);
        prev_challenge = prev;
        
        // Generate shplonk challenges
        let (shplonk_nu, prev) = Self::generate_shplonk_nu(proof, prev_challenge);
        prev_challenge = prev;
        
        let (shplonk_z, _) = Self::generate_shplonk_z(proof, prev_challenge);
        
        Self {
            relation_parameters,
            alphas,
            gate_challenges,
            sumcheck_u_challenges,
            rho,
            gemini_r,
            shplonk_nu,
            shplonk_z,
        }
    }
    
    fn generate_eta_challenge(
        proof: &Proof,
        public_inputs: &[Vec<u8>],
        circuit_size: Fr,
        public_inputs_size: Fr,
        pub_inputs_offset: Fr,
    ) -> (Fr, Fr, Fr, Fr) {
        let mut data = Vec::new();
        
        // Add circuit parameters
        data.extend_from_slice(&to_bytes_be(circuit_size));
        data.extend_from_slice(&to_bytes_be(public_inputs_size));
        data.extend_from_slice(&to_bytes_be(pub_inputs_offset));
        
        // Add public inputs
        for input in public_inputs {
            data.extend_from_slice(input);
        }
        
        // Add w1, w2, w3 commitments
        data.extend_from_slice(&to_bytes_be(proof.w1.x_0));
        data.extend_from_slice(&to_bytes_be(proof.w1.x_1));
        data.extend_from_slice(&to_bytes_be(proof.w1.y_0));
        data.extend_from_slice(&to_bytes_be(proof.w1.y_1));
        
        data.extend_from_slice(&to_bytes_be(proof.w2.x_0));
        data.extend_from_slice(&to_bytes_be(proof.w2.x_1));
        data.extend_from_slice(&to_bytes_be(proof.w2.y_0));
        data.extend_from_slice(&to_bytes_be(proof.w2.y_1));
        
        data.extend_from_slice(&to_bytes_be(proof.w3.x_0));
        data.extend_from_slice(&to_bytes_be(proof.w3.x_1));
        data.extend_from_slice(&to_bytes_be(proof.w3.y_0));
        data.extend_from_slice(&to_bytes_be(proof.w3.y_1));
        
        let challenge = hash_to_field(&data);
        let (eta, eta_two) = split_challenge(challenge);
        
        let next_challenge = hash_to_field(&to_bytes_be(challenge));
        let (eta_three, _) = split_challenge(next_challenge);
        
        (eta, eta_two, eta_three, next_challenge)
    }
    
    fn generate_beta_gamma(prev_challenge: Fr, proof: &Proof) -> (Fr, Fr, Fr) {
        let mut data = Vec::new();
        data.extend_from_slice(&to_bytes_be(prev_challenge));
        
        // Add lookup commitments
        data.extend_from_slice(&to_bytes_be(proof.lookup_read_counts.x_0));
        data.extend_from_slice(&to_bytes_be(proof.lookup_read_counts.x_1));
        data.extend_from_slice(&to_bytes_be(proof.lookup_read_counts.y_0));
        data.extend_from_slice(&to_bytes_be(proof.lookup_read_counts.y_1));
        
        data.extend_from_slice(&to_bytes_be(proof.lookup_read_tags.x_0));
        data.extend_from_slice(&to_bytes_be(proof.lookup_read_tags.x_1));
        data.extend_from_slice(&to_bytes_be(proof.lookup_read_tags.y_0));
        data.extend_from_slice(&to_bytes_be(proof.lookup_read_tags.y_1));
        
        data.extend_from_slice(&to_bytes_be(proof.w4.x_0));
        data.extend_from_slice(&to_bytes_be(proof.w4.x_1));
        data.extend_from_slice(&to_bytes_be(proof.w4.y_0));
        data.extend_from_slice(&to_bytes_be(proof.w4.y_1));
        
        let challenge = hash_to_field(&data);
        let (beta, gamma) = split_challenge(challenge);
        
        (beta, gamma, challenge)
    }
    
    fn generate_alphas(prev_challenge: U256, proof: &Proof) -> ([Fr; NUMBER_OF_ALPHAS as usize], Fr) {
        let mut alphas = [U256::zero(); NUMBER_OF_ALPHAS as usize];
        let mut challenge = prev_challenge;
        
        let mut data = Vec::new();
        data.extend_from_slice(&to_bytes_be(challenge));
        data.extend_from_slice(&to_bytes_be(proof.lookup_inverses.x_0));
        data.extend_from_slice(&to_bytes_be(proof.lookup_inverses.x_1));
        data.extend_from_slice(&to_bytes_be(proof.lookup_inverses.y_0));
        data.extend_from_slice(&to_bytes_be(proof.lookup_inverses.y_1));
        data.extend_from_slice(&to_bytes_be(proof.z_perm.x_0));
        data.extend_from_slice(&to_bytes_be(proof.z_perm.x_1));
        data.extend_from_slice(&to_bytes_be(proof.z_perm.y_0));
        data.extend_from_slice(&to_bytes_be(proof.z_perm.y_1));
        
        challenge = hash_to_field(&data);
        (alphas[0], alphas[1]) = split_challenge(challenge);
        
        for i in (2..NUMBER_OF_ALPHAS as usize).step_by(2) {
            challenge = hash_to_field(&to_bytes_be(challenge));
            (alphas[i], alphas[i + 1]) = split_challenge(challenge);
        }
        
        (alphas, challenge)
    }
    
    fn generate_gate_challenges(mut prev_challenge: U256) -> ([Fr; CONST_PROOF_SIZE_LOG_N as usize], Fr) {
        let mut challenges = [U256::zero(); CONST_PROOF_SIZE_LOG_N as usize];
        
        for i in 0..CONST_PROOF_SIZE_LOG_N as usize {
            prev_challenge = hash_to_field(&to_bytes_be(prev_challenge));
            (challenges[i], _) = split_challenge(prev_challenge);
        }
        
        (challenges, prev_challenge)
    }
    
    fn generate_sumcheck_challenges(proof: &Proof, mut prev_challenge: U256) -> ([Fr; CONST_PROOF_SIZE_LOG_N as usize], Fr) {
        let mut challenges = [U256::zero(); CONST_PROOF_SIZE_LOG_N as usize];
        
        for i in 0..CONST_PROOF_SIZE_LOG_N as usize {
            let mut data = Vec::new();
            data.extend_from_slice(&to_bytes_be(prev_challenge));
            
            // Add univariate evaluations for this round
            for j in 0..BATCHED_RELATION_PARTIAL_LENGTH as usize {
                data.extend_from_slice(&to_bytes_be(proof.sumcheck_univariates[i][j]));
            }
            
            prev_challenge = hash_to_field(&data);
            (challenges[i], _) = split_challenge(prev_challenge);
        }
        
        (challenges, prev_challenge)
    }
    
    fn generate_rho(proof: &Proof, prev_challenge: Fr) -> (Fr, Fr) {
        let mut data = Vec::new();
        data.extend_from_slice(&to_bytes_be(prev_challenge));
        
        for eval in &proof.sumcheck_evaluations {
            data.extend_from_slice(&to_bytes_be(*eval));
        }
        
        let challenge = hash_to_field(&data);
        let (rho, _) = split_challenge(challenge);
        
        (rho, challenge)
    }
    
    fn generate_gemini_r(proof: &Proof, prev_challenge: Fr) -> (Fr, Fr) {
        let mut data = Vec::new();
        data.extend_from_slice(&to_bytes_be(prev_challenge));
        
        for comm in &proof.gemini_fold_comms {
            data.extend_from_slice(&to_bytes_be(comm.x_0));
            data.extend_from_slice(&to_bytes_be(comm.x_1));
            data.extend_from_slice(&to_bytes_be(comm.y_0));
            data.extend_from_slice(&to_bytes_be(comm.y_1));
        }
        
        let challenge = hash_to_field(&data);
        let (gemini_r, _) = split_challenge(challenge);
        
        (gemini_r, challenge)
    }
    
    fn generate_shplonk_nu(proof: &Proof, prev_challenge: Fr) -> (Fr, Fr) {
        let mut data = Vec::new();
        data.extend_from_slice(&to_bytes_be(prev_challenge));
        
        for eval in &proof.gemini_a_evaluations {
            data.extend_from_slice(&to_bytes_be(*eval));
        }
        
        let challenge = hash_to_field(&data);
        let (nu, _) = split_challenge(challenge);
        
        (nu, challenge)
    }
    
    fn generate_shplonk_z(proof: &Proof, prev_challenge: Fr) -> (Fr, Fr) {
        let mut data = Vec::new();
        data.extend_from_slice(&to_bytes_be(prev_challenge));
        data.extend_from_slice(&to_bytes_be(proof.shplonk_q.x_0));
        data.extend_from_slice(&to_bytes_be(proof.shplonk_q.x_1));
        data.extend_from_slice(&to_bytes_be(proof.shplonk_q.y_0));
        data.extend_from_slice(&to_bytes_be(proof.shplonk_q.y_1));
        
        let challenge = hash_to_field(&data);
        let (z, _) = split_challenge(challenge);
        
        (z, challenge)
    }
}
