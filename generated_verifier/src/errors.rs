#![cfg_attr(not(feature = "std"), no_std)]

/// Errors that can occur during verification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[ink::scale_derive(Encode, Decode, TypeInfo)]
pub enum VerifierError {
    /// Proof has invalid length or format
    InvalidProofFormat,
    
    /// Public inputs length doesn't match verification key
    InvalidPublicInputsLength,
    
    /// Public input has invalid length (should be 32 bytes)
    InvalidPublicInputFormat,
    
    /// Sumcheck verification failed
    SumcheckFailed,
    
    /// Final sumcheck evaluation doesn't match expected value
    SumcheckEvaluationMismatch,
    
    /// Shplemini (opening proof) verification failed
    ShpleminiFailed,
    
    /// Pairing check failed
    PairingCheckFailed,
    
    /// Precompile call failed
    PrecompileCallFailed,
    
    /// Invalid field element (>= modulus)
    InvalidFieldElement,
    
    /// Division by zero
    DivisionByZero,
    
    /// Invalid verification key
    InvalidVerificationKey,
    
    /// Generic error
    Other,
}

/// Result type for verifier operations
pub type VerifierResult<T> = Result<T, VerifierError>;