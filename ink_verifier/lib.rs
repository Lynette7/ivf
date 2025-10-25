#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod verifier {
    use ink::prelude::vec::Vec;
    use ink::storage::Lazy;
    use ink::env::call::{build_call, ExecutionInput, Selector};
    use ink::env::DefaultEnvironment;

    // Import Arkworks types
    use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
    use ark_plonk::{Proof, VerifierKey};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use arf_ff::{Field, PrimeField};
    use ark_ec::AffineRepr;

    #[ink(storage)]
    pub struct Verifier {
        /// The serialized Plonk VerifierKey
        vk_bytes: Lazy<Vec<u8>>,
    }

    impl Verifier {
        #[ink(constructor)]
        pub fn new(vk_bytes: Vec<u8>) -> Self {
            Self {
                vk_bytes: Lazy::new(vk_bytes),
            }
        }

        /// Verifies a Plonk proof
        #[ink(message)]
        pub fn verify(&self, proof_bytes: Vec<u8>, public_inputs_bytes: Vec<Vec<u8>>,) -> bool {
            // Deserialize vk
            let vk = VerifierKey::<Bn254>::deserialize_uncompressed(
                &*self.vk_bytes.get_or_default()
            ).expect("Failed to deserialize VK");

            // Deserialize proof
            let proof = Proof::<Bn254>::deserialize_uncompressed(&*proof_bytes)
                .expect("Failed to deserialize proof");

            // Deserialize public inputs
            let public_inputs: Vec<Fr> = public_inputs_bytes
                .iter()
                .map(|pi| Fr::deserialize_uncompressed(&**pi)
                            .expect("Failed to deserialize public input"))
                .collect();

            // Run the actual verification logic
            // For this we use precompiles so it is affordable
            Self::execute_verification_logic(&vk, &proof, &public_inputs)
        }

        fn execute_verification_logic(vk: &VerifierKey<Bn254>, proof: &Proof<Bn254>, &public_inputs: &Vec<Fr>,) -> bool {
            // TODO
            true
        }
    }
}
