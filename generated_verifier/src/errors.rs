#![cfg_attr(not(feature = "std"), no_std)]

use ink::prelude::string::String;

/// Errors that can occur during verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifierError {
    /// Proof has invalid length or format
    InvalidProofFormat,
    
    /// Public inputs length doesn't match verification key
    InvalidPublicInputsLength { expected: u32, got: usize },
    
    /// Public input has invalid length (should be 32 bytes)
    InvalidPublicInputFormat { index: usize },
    
    /// Sumcheck verification failed at a specific round
    SumcheckFailed { round: usize },
    
    /// Final sumcheck evaluation doesn't match expected value
    SumcheckEvaluationMismatch,
    
    /// Shplemini (opening proof) verification failed
    ShpleminiFailed,
    
    /// Pairing check failed
    PairingCheckFailed,
    
    /// Precompile call failed
    PrecompileCallFailed { precompile: &'static str },
    
    /// Invalid field element (>= modulus)
    InvalidFieldElement,
    
    /// Division by zero
    DivisionByZero,
    
    /// Generic error with message
    Other(String),
}

impl VerifierError {
    /// Create a generic error from a string
    pub fn other(msg: &str) -> Self {
        Self::Other(String::from(msg))
    }
}

/// Result type for verifier operations
pub type VerifierResult<T> = Result<T, VerifierError>;