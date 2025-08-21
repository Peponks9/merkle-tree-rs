use thiserror::Error;

/// Error types for Merkle tree operations
#[derive(Error, Debug, Clone, PartialEq)]
pub enum MerkleError {
    #[error("Empty data provided")]
    EmptyData,

    #[error("Invalid index: {index}, tree size: {size}")]
    InvalidIndex { index: usize, size: usize },

    #[error("Invalid proof: {reason}")]
    InvalidProof { reason: String },

    #[error("Hash function error: {message}")]
    HashError { message: String },

    #[error("Serialization error: {message}")]
    SerializationError { message: String },

    #[error("Tree construction failed: {reason}")]
    TreeConstructionError { reason: String },
}

/// Result type for Merkle tree operations
pub type Result<T> = std::result::Result<T, MerkleError>;
