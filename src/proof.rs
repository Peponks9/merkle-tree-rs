use crate::error::{MerkleError, Result};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Direction of a proof step (left or right sibling)
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ProofDirection {
    Left,
    Right,
}

/// A single step in a Merkle proof
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProofStep {
    pub hash: Vec<u8>,
    pub direction: ProofDirection,
}

/// Merkle proof for a specific leaf
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub steps: Vec<ProofStep>,
}

impl MerkleProof {
    /// Create a new Merkle proof
    pub fn new(leaf_index: usize, steps: Vec<ProofStep>) -> Self {
        Self { leaf_index, steps }
    }

    /// Get the number of steps in the proof
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Check if the proof is empty
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Verify the proof against a root hash and leaf data
    pub fn verify<H>(&self, hasher: &H, leaf_data: &[u8], root: &[u8]) -> bool
    where
        H: crate::hasher::Hasher,
    {
        let leaf_hash = hasher.hash(leaf_data);
        self.verify_with_leaf_hash(hasher, &leaf_hash, root)
    }

    /// Verify the proof with a pre-computed leaf hash
    pub fn verify_with_leaf_hash<H>(&self, hasher: &H, leaf_hash: &[u8], root: &[u8]) -> bool
    where
        H: crate::hasher::Hasher,
    {
        let computed_root = self.compute_root(hasher, leaf_hash);
        computed_root == root
    }

    /// Compute the root hash from the proof and leaf hash
    pub fn compute_root<H>(&self, hasher: &H, leaf_hash: &[u8]) -> Vec<u8>
    where
        H: crate::hasher::Hasher,
    {
        let mut current_hash = leaf_hash.to_vec();

        for step in &self.steps {
            current_hash = match step.direction {
                ProofDirection::Left => hasher.hash_pair(&step.hash, &current_hash),
                ProofDirection::Right => hasher.hash_pair(&current_hash, &step.hash),
            };
        }

        current_hash
    }

    /// Convert proof to hex representation for debugging
    pub fn to_hex(&self) -> String {
        let steps_hex: Vec<String> = self
            .steps
            .iter()
            .map(|step| {
                format!(
                    "{}:{}",
                    match step.direction {
                        ProofDirection::Left => "L",
                        ProofDirection::Right => "R",
                    },
                    hex::encode(&step.hash)
                )
            })
            .collect();

        format!(
            "index:{}, steps:[{}]",
            self.leaf_index,
            steps_hex.join(", ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::{Hasher, Sha256Hasher};

    #[test]
    fn test_proof_creation() {
        let steps = vec![
            ProofStep {
                hash: vec![1, 2, 3],
                direction: ProofDirection::Left,
            },
            ProofStep {
                hash: vec![4, 5, 6],
                direction: ProofDirection::Right,
            },
        ];

        let proof = MerkleProof::new(0, steps);
        assert_eq!(proof.leaf_index, 0);
        assert_eq!(proof.len(), 2);
        assert!(!proof.is_empty());
    }

    #[test]
    fn test_empty_proof() {
        let proof = MerkleProof::new(0, vec![]);
        assert!(proof.is_empty());
        assert_eq!(proof.len(), 0);
    }

    #[test]
    fn test_proof_to_hex() {
        let steps = vec![
            ProofStep {
                hash: vec![0x01, 0x02],
                direction: ProofDirection::Left,
            },
            ProofStep {
                hash: vec![0x03, 0x04],
                direction: ProofDirection::Right,
            },
        ];

        let proof = MerkleProof::new(1, steps);
        let hex_repr = proof.to_hex();
        assert!(hex_repr.contains("index:1"));
        assert!(hex_repr.contains("L:0102"));
        assert!(hex_repr.contains("R:0304"));
    }

    #[test]
    fn test_compute_root() {
        let hasher = Sha256Hasher::new();
        let leaf_hash = hasher.hash(b"leaf");
        let sibling_hash = hasher.hash(b"sibling");

        let steps = vec![ProofStep {
            hash: sibling_hash.clone(),
            direction: ProofDirection::Right,
        }];

        let proof = MerkleProof::new(0, steps);
        let root = proof.compute_root(&hasher, &leaf_hash);

        // The computed root should be the hash of leaf_hash + sibling_hash
        let expected_root = hasher.hash_pair(&leaf_hash, &sibling_hash);
        assert_eq!(root, expected_root);
    }

    #[test]
    fn test_verify_with_leaf_hash() {
        let hasher = Sha256Hasher::new();
        let leaf_hash = hasher.hash(b"leaf");
        let sibling_hash = hasher.hash(b"sibling");
        let root = hasher.hash_pair(&leaf_hash, &sibling_hash);

        let steps = vec![ProofStep {
            hash: sibling_hash,
            direction: ProofDirection::Right,
        }];

        let proof = MerkleProof::new(0, steps);
        assert!(proof.verify_with_leaf_hash(&hasher, &leaf_hash, &root));

        // Test with wrong root
        let wrong_root = hasher.hash(b"wrong");
        assert!(!proof.verify_with_leaf_hash(&hasher, &leaf_hash, &wrong_root));
    }

    #[test]
    fn test_verify() {
        let hasher = Sha256Hasher::new();
        let leaf_data = b"leaf";
        let leaf_hash = hasher.hash(leaf_data);
        let sibling_hash = hasher.hash(b"sibling");
        let root = hasher.hash_pair(&leaf_hash, &sibling_hash);

        let steps = vec![ProofStep {
            hash: sibling_hash,
            direction: ProofDirection::Right,
        }];

        let proof = MerkleProof::new(0, steps);
        assert!(proof.verify(&hasher, leaf_data, &root));

        // Test with wrong leaf data
        assert!(!proof.verify(&hasher, b"wrong", &root));
    }
}
