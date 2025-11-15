#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod proof_client {
    use ink::prelude::vec::Vec;
    use ink::env::call::{build_call, ExecutionInput, Call};
    use ink::env::DefaultEnvironment;
    use ink::primitives::H160;

    /// Error type mirroring the verifier's error type
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[ink::scale_derive(Encode, Decode, TypeInfo)]
    pub enum VerifierError {
        InvalidProofFormat,
        InvalidPublicInputsLength,
        InvalidPublicInputFormat,
        SumcheckFailed,
        SumcheckEvaluationMismatch,
        ShpleminiFailed,
        PairingCheckFailed,
        PrecompileCallFailed,
        InvalidFieldElement,
        DivisionByZero,
        InvalidVerificationKey,
        Other,
    }

    /// Stored proof submission
    #[derive(Debug, Clone)]
    #[ink::scale_derive(Encode, Decode, TypeInfo)]
    #[cfg_attr(
        feature = "std",
        derive(ink::storage::traits::StorageLayout)
    )]
    pub struct ProofSubmission {
        pub submitter: H160,
        pub timestamp: Timestamp,
        pub proof_hash: [u8; 32],
        pub verified: bool,
    }

    #[ink(storage)]
    pub struct ProofClient {
        /// Address of the verifier contract
        verifier_address: H160,
        /// Counter for total submissions
        total_submissions: u64,
        /// Mapping of submission ID to proof details
        submissions: ink::storage::Mapping<u64, ProofSubmission>,
        /// Owner of the contract
        owner: H160,
    }

    /// Events
    #[ink(event)]
    pub struct ProofSubmitted {
        #[ink(topic)]
        submission_id: u64,
        #[ink(topic)]
        submitter: H160,
        verified: bool,
    }

    #[ink(event)]
    pub struct ProofVerified {
        #[ink(topic)]
        submission_id: u64,
        success: bool,
    }

    /// Errors
    #[derive(Debug, PartialEq, Eq)]
    #[ink::scale_derive(Encode, Decode, TypeInfo)]
    pub enum Error {
        /// Verification failed
        VerificationFailed,
        /// Call to verifier contract failed
        VerifierCallFailed,
        /// Submission not found
        SubmissionNotFound,
        /// Not authorized
        Unauthorized,
        /// Invalid proof data
        InvalidProofData,
    }

    pub type Result<T> = core::result::Result<T, Error>;

    impl ProofClient {
        /// Constructor
        #[ink(constructor)]
        pub fn new(verifier_address: H160) -> Self {
            Self {
                verifier_address,
                total_submissions: 0,
                submissions: ink::storage::Mapping::default(),
                owner: Self::env().caller(),
            }
        }

        /// Submit a proof for verification
        #[ink(message)]
        pub fn submit_proof(
            &mut self,
            proof: Vec<u8>,
            public_inputs: Vec<Vec<u8>>,
        ) -> Result<u64> {
            let caller = self.env().caller();
            
            // Validate proof data
            if proof.is_empty() {
                return Err(Error::InvalidProofData);
            }

            // Call the verifier contract
            let verified = self.call_verifier(proof.clone(), public_inputs)?;

            // Create submission record
            let submission_id = self.total_submissions;
            self.total_submissions += 1;

            let proof_hash = self.hash_proof(&proof);
            let timestamp = self.env().block_timestamp();

            let submission = ProofSubmission {
                submitter: caller,
                timestamp,
                proof_hash,
                verified,
            };

            self.submissions.insert(submission_id, &submission);

            // Emit events
            self.env().emit_event(ProofSubmitted {
                submission_id,
                submitter: caller,
                verified,
            });

            if verified {
                self.env().emit_event(ProofVerified {
                    submission_id,
                    success: true,
                });
            }

            Ok(submission_id)
        }

        /// Get submission details
        #[ink(message)]
        pub fn get_submission(&self, submission_id: u64) -> Option<ProofSubmission> {
            self.submissions.get(submission_id)
        }

        /// Get total submissions count
        #[ink(message)]
        pub fn get_total_submissions(&self) -> u64 {
            self.total_submissions
        }

        /// Get verifier address
        #[ink(message)]
        pub fn get_verifier_address(&self) -> H160 {
            self.verifier_address
        }

        /// Update verifier address (only owner)
        #[ink(message)]
        pub fn set_verifier_address(&mut self, new_address: H160) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::Unauthorized);
            }
            self.verifier_address = new_address;
            Ok(())
        }

        /// Call the verifier contract
        fn call_verifier(
            &self,
            proof: Vec<u8>,
            public_inputs: Vec<Vec<u8>>,
        ) -> Result<bool> {
            // Build the cross-contract call
            let result = build_call::<DefaultEnvironment>()
                .call(self.verifier_address)
                .exec_input(
                    ExecutionInput::new(ink::env::call::Selector::new(ink::selector_bytes!("verify")))
                        .push_arg(proof)
                        .push_arg(public_inputs)
                )
                .returns::<core::result::Result<bool, VerifierError>>()
                .try_invoke();

            match result {
                Ok(Ok(Ok(verified))) => Ok(verified),
                Ok(Ok(Err(_verifier_error))) => Err(Error::VerificationFailed),
                Ok(Err(_)) => Err(Error::VerifierCallFailed),
                Err(_) => Err(Error::VerifierCallFailed),
            }
        }

        /// Hash the proof for storage
        fn hash_proof(&self, proof: &[u8]) -> [u8; 32] {
            let mut output = [0u8; 32];
            ink::env::hash_bytes::<ink::env::hash::Sha2x256>(proof, &mut output);
            output
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn test_new() {
            let accounts = ink::env::test::default_accounts::<DefaultEnvironment>();
            let client = ProofClient::new(accounts.alice);
            assert_eq!(client.get_verifier_address(), accounts.alice);
            assert_eq!(client.get_total_submissions(), 0);
        }

        #[ink::test]
        fn test_submit_proof_invalid_data() {
            let accounts = ink::env::test::default_accounts::<DefaultEnvironment>();
            let mut client = ProofClient::new(accounts.alice);
            
            let empty_proof = Vec::new();
            let public_inputs = vec![vec![0u8; 32]];
            
            let result = client.submit_proof(empty_proof, public_inputs);
            assert_eq!(result, Err(Error::InvalidProofData));
        }
    }
}
