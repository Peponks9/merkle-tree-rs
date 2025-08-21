use crate::error::{MerkleError, Result};
use blake3;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

/// Trait for hash functions used in Merkle trees
pub trait Hasher: Clone + Send + Sync {
    /// Hash a single input
    fn hash(&self, data: &[u8]) -> Vec<u8>;
    
    /// Hash two inputs together (for internal nodes)
    fn hash_pair(&self, left: &[u8], right: &[u8]) -> Vec<u8> {
        let mut combined = Vec::with_capacity(left.len() + right.len());
        combined.extend_from_slice(left);
        combined.extend_from_slice(right);
        self.hash(&combined)
    }
    
    /// Get the output size of the hash function
    fn output_size(&self) -> usize;
    
    /// Get the name of the hash function
    fn name(&self) -> &'static str;
}

/// SHA-256 hasher implementation
#[derive(Clone, Debug)]
pub struct Sha256Hasher;

impl Sha256Hasher {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Sha256Hasher {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
    
    fn output_size(&self) -> usize {
        32 // SHA-256 produces 32-byte hashes
    }
    
    fn name(&self) -> &'static str {
        "SHA-256"
    }
}

/// SHA-3 hasher implementation
#[derive(Clone, Debug)]
pub struct Sha3Hasher;

impl Sha3Hasher {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Sha3Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Sha3Hasher {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
    
    fn output_size(&self) -> usize {
        32 // SHA3-256 produces 32-byte hashes
    }
    
    fn name(&self) -> &'static str {
        "SHA3-256"
    }
}

/// BLAKE3 hasher implementation
#[derive(Clone, Debug)]
pub struct Blake3Hasher;

impl Blake3Hasher {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Blake3Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Blake3Hasher {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        blake3::hash(data).as_bytes().to_vec()
    }
    
    fn output_size(&self) -> usize {
        32 // BLAKE3 produces 32-byte hashes
    }
    
    fn name(&self) -> &'static str {
        "BLAKE3"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hasher() {
        let hasher = Sha256Hasher::new();
        let hash1 = hasher.hash(b"hello");
        let hash2 = hasher.hash(b"hello");
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
        assert_eq!(hasher.output_size(), 32);
        assert_eq!(hasher.name(), "SHA-256");
    }

    #[test]
    fn test_sha3_hasher() {
        let hasher = Sha3Hasher::new();
        let hash1 = hasher.hash(b"hello");
        let hash2 = hasher.hash(b"hello");
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
        assert_eq!(hasher.output_size(), 32);
        assert_eq!(hasher.name(), "SHA3-256");
    }

    #[test]
    fn test_blake3_hasher() {
        let hasher = Blake3Hasher::new();
        let hash1 = hasher.hash(b"hello");
        let hash2 = hasher.hash(b"hello");
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
        assert_eq!(hasher.output_size(), 32);
        assert_eq!(hasher.name(), "BLAKE3");
    }

    #[test]
    fn test_hash_pair() {
        let hasher = Sha256Hasher::new();
        let left = hasher.hash(b"left");
        let right = hasher.hash(b"right");
        let combined = hasher.hash_pair(&left, &right);
        assert_eq!(combined.len(), 32);
    }

    #[test]
    fn test_different_hashers_produce_different_results() {
        let data = b"test data";
        
        let sha256_hash = Sha256Hasher::new().hash(data);
        let sha3_hash = Sha3Hasher::new().hash(data);
        let blake3_hash = Blake3Hasher::new().hash(data);
        
        assert_ne!(sha256_hash, sha3_hash);
        assert_ne!(sha256_hash, blake3_hash);
        assert_ne!(sha3_hash, blake3_hash);
    }
}
