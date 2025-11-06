#![cfg_attr(not(feature = "std"), no_std)]

use ink::prelude::vec::Vec;
use primitive_types::U256;
use crate::field::Fr;
use crate::honk_structs::*;

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
    let hash = ink::env::hash_bytes::<ink::env::hash::Sha2x256>(data);
    U256::from_big_endian(hash.as_ref())
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
        let mut prev_challenge = Fr::zero();
        
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
            public_inputs_delta: Fr::zero(), // Computed later
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
        data.extend_from_slice(&circuit_size.to_be_bytes());
        data.extend_from_slice(&public_inputs_size.to_be_bytes());
        data.extend_from_slice(&pub_inputs_offset.to_be_bytes());
        
        // Add public inputs
        for input in public_inputs {
            data.extend_from_slice(input);
        }
        
        // Add w1, w2, w3 commitments
        data.extend_from_slice(&proof.w1.x_0.to_be_bytes());
        data.extend_from_slice(&proof.w1.x_1.to_be_bytes());
        data.extend_from_slice(&proof.w1.y_0.to_be_bytes());
        data.extend_from_slice(&proof.w1.y_1.to_be_bytes());
        
        data.extend_from_slice(&proof.w2.x_0.to_be_bytes());
        data.extend_from_slice(&proof.w2.x_1.to_be_bytes());
        data.extend_from_slice(&proof.w2.y_0.to_be_bytes());
        data.extend_from_slice(&proof.w2.y_1.to_be_bytes());
        
        data.extend_from_slice(&proof.w3.x_0.to_be_bytes());
        data.extend_from_slice(&proof.w3.x_1.to_be_bytes());
        data.extend_from_slice(&proof.w3.y_0.to_be_bytes());
        data.extend_from_slice(&proof.w3.y_1.to_be_bytes());
        
        let challenge = hash_to_field(&data);
        let (eta, eta_two) = split_challenge(challenge);
        
        let next_challenge = hash_to_field(&challenge.to_be_bytes());
        let (eta_three, _) = split_challenge(next_challenge);
        
        (eta, eta_two, eta_three, next_challenge)
    }
    
    fn generate_beta_gamma(prev_challenge: Fr, proof: &Proof) -> (Fr, Fr, Fr) {
        let mut data = Vec::new();
        data.extend_from_slice(&prev_challenge.to_be_bytes());
        
        // Add lookup commitments
        data.extend_from_slice(&proof.lookup_read_counts.x_0.to_be_bytes());
        data.extend_from_slice(&proof.lookup_read_counts.x_1.to_be_bytes());
        data.extend_from_slice(&proof.lookup_read_counts.y_0.to_be_bytes());
        data.extend_from_slice(&proof.lookup_read_counts.y_1.to_be_bytes());
        
        data.extend_from_slice(&proof.lookup_read_tags.x_0.to_be_bytes());
        data.extend_from_slice(&proof.lookup_read_tags.x_1.to_be_bytes());
        data.extend_from_slice(&proof.lookup_read_tags.y_0.to_be_bytes());
        data.extend_from_slice(&proof.lookup_read_tags.y_1.to_be_bytes());
        
        data.extend_from_slice(&proof.w4.x_0.to_be_bytes());
        data.extend_from_slice(&proof.w4.x_1.to_be_bytes());
        data.extend_from_slice(&proof.w4.y_0.to_be_bytes());
        data.extend_from_slice(&proof.w4.y_1.to_be_bytes());
        
        let challenge = hash_to_field(&data);
        let (beta, gamma) = split_challenge(challenge);
        
        (beta, gamma, challenge)
    }
    
    fn generate_alphas(prev_challenge: Fr, proof: &Proof) -> ([Fr; NUMBER_OF_ALPHAS as usize], Fr) {
        let mut alphas = [Fr::zero(); NUMBER_OF_ALPHAS as usize];
        let mut challenge = prev_challenge;
        
        let mut data = Vec::new();
        data.extend_from_slice(&challenge.to_be_bytes());
        data.extend_from_slice(&proof.lookup_inverses.x_0.to_be_bytes());
        data.extend_from_slice(&proof.lookup_inverses.x_1.to_be_bytes());
        data.extend_from_slice(&proof.lookup_inverses.y_0.to_be_bytes());
        data.extend_from_slice(&proof.lookup_inverses.y_1.to_be_bytes());
        data.extend_from_slice(&proof.z_perm.x_0.to_be_bytes());
        data.extend_from_slice(&proof.z_perm.x_1.to_be_bytes());
        data.extend_from_slice(&proof.z_perm.y_0.to_be_bytes());
        data.extend_from_slice(&proof.z_perm.y_1.to_be_bytes());
        
        challenge = hash_to_field(&data);
        (alphas[0], alphas[1]) = split_challenge(challenge);
        
        for i in (2..NUMBER_OF_ALPHAS as usize).step_by(2) {
            challenge = hash_to_field(&challenge.to_be_bytes());
            (alphas[i], alphas[i + 1]) = split_challenge(challenge);
        }
        
        (alphas, challenge)
    }
    
    fn generate_gate_challenges(mut prev_challenge: Fr) -> ([Fr; CONST_PROOF_SIZE_LOG_N as usize], Fr) {
        let mut challenges = [Fr::zero(); CONST_PROOF_SIZE_LOG_N as usize];
        
        for i in 0..CONST_PROOF_SIZE_LOG_N as usize {
            prev_challenge = hash_to_field(&prev_challenge.to_be_bytes());
            (challenges[i], _) = split_challenge(prev_challenge);
        }
        
        (challenges, prev_challenge)
    }
    
    fn generate_sumcheck_challenges(proof: &Proof, mut prev_challenge: Fr) -> ([Fr; CONST_PROOF_SIZE_LOG_N as usize], Fr) {
        let mut challenges = [Fr::zero(); CONST_PROOF_SIZE_LOG_N as usize];
        
        for i in 0..CONST_PROOF_SIZE_LOG_N as usize {
            let mut data = Vec::new();
            data.extend_from_slice(&prev_challenge.to_be_bytes());
            
            // Add univariate evaluations for this round
            for j in 0..BATCHED_RELATION_PARTIAL_LENGTH as usize {
                data.extend_from_slice(&proof.sumcheck_univariates[i][j].to_be_bytes());
            }
            
            prev_challenge = hash_to_field(&data);
            (challenges[i], _) = split_challenge(prev_challenge);
        }
        
        (challenges, prev_challenge)
    }
    
    fn generate_rho(proof: &Proof, prev_challenge: Fr) -> (Fr, Fr) {
        let mut data = Vec::new();
        data.extend_from_slice(&prev_challenge.to_be_bytes());
        
        for eval in &proof.sumcheck_evaluations {
            data.extend_from_slice(&eval.to_be_bytes());
        }
        
        let challenge = hash_to_field(&data);
        let (rho, _) = split_challenge(challenge);
        
        (rho, challenge)
    }
    
    fn generate_gemini_r(proof: &Proof, prev_challenge: Fr) -> (Fr, Fr) {
        let mut data = Vec::new();
        data.extend_from_slice(&prev_challenge.to_be_bytes());
        
        for comm in &proof.gemini_fold_comms {
            data.extend_from_slice(&comm.x_0.to_be_bytes());
            data.extend_from_slice(&comm.x_1.to_be_bytes());
            data.extend_from_slice(&comm.y_0.to_be_bytes());
            data.extend_from_slice(&comm.y_1.to_be_bytes());
        }
        
        let challenge = hash_to_field(&data);
        let (gemini_r, _) = split_challenge(challenge);
        
        (gemini_r, challenge)
    }
    
    fn generate_shplonk_nu(proof: &Proof, prev_challenge: Fr) -> (Fr, Fr) {
        let mut data = Vec::new();
        data.extend_from_slice(&prev_challenge.to_be_bytes());
        
        for eval in &proof.gemini_a_evaluations {
            data.extend_from_slice(&eval.to_be_bytes());
        }
        
        let challenge = hash_to_field(&data);
        let (nu, _) = split_challenge(challenge);
        
        (nu, challenge)
    }
    
    fn generate_shplonk_z(proof: &Proof, prev_challenge: Fr) -> (Fr, Fr) {
        let mut data = Vec::new();
        data.extend_from_slice(&prev_challenge.to_be_bytes());
        data.extend_from_slice(&proof.shplonk_q.x_0.to_be_bytes());
        data.extend_from_slice(&proof.shplonk_q.x_1.to_be_bytes());
        data.extend_from_slice(&proof.shplonk_q.y_0.to_be_bytes());
        data.extend_from_slice(&proof.shplonk_q.y_1.to_be_bytes());
        
        let challenge = hash_to_field(&data);
        let (z, _) = split_challenge(challenge);
        
        (z, challenge)
    }
}
