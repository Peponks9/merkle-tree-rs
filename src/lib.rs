//! # Merkle Tree Library
//!
//! A production-ready Merkle tree library in Rust with proof generation/verification,
//! generic hash support, and comprehensive testing.
//!
//! ## Features
//!
//! - Generic hash function support (SHA-256, SHA-3, BLAKE3, etc.)
//! - Efficient proof generation and verification
//! - Binary and sparse Merkle tree implementations
//! - Serialization support with serde
//! - Comprehensive error handling
//! - Performance optimized
//!
//! ## Usage
//!
//! ```rust
//! use merkle_tree::{MerkleTree, Sha256Hasher};
//!
//! let data = vec![b"hello", b"world", b"merkle", b"tree"];
//! let tree = MerkleTree::new(data, Sha256Hasher::new())?;
//! let root = tree.root();
//!
//! // Generate proof for the first element
//! let proof = tree.generate_proof(0)?;
//!
//! // Verify the proof
//! assert!(tree.verify_proof(&proof, b"hello", root));
//! ```

pub mod error;
pub mod hasher;
pub mod merkle_tree;
pub mod proof;
pub mod sparse;

pub use error::{MerkleError, Result};
pub use hasher::{Blake3Hasher, Hasher, Sha256Hasher, Sha3Hasher};
pub use merkle_tree::MerkleTree;
pub use proof::{MerkleProof, ProofDirection};
pub use sparse::SparseMerkleTree;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_functionality() {
        let data = vec![b"hello", b"world"];
        let tree = MerkleTree::new(data, Sha256Hasher::new()).unwrap();
        assert!(tree.root().len() > 0);
    }
}
