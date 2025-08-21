use crate::error::{MerkleError, Result};
use crate::hasher::Hasher;
use crate::proof::{MerkleProof, ProofDirection, ProofStep};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A node in the Merkle tree
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
struct MerkleNode {
    hash: Vec<u8>,
    left: Option<Box<MerkleNode>>,
    right: Option<Box<MerkleNode>>,
}

impl MerkleNode {
    fn new_leaf(hash: Vec<u8>) -> Self {
        Self {
            hash,
            left: None,
            right: None,
        }
    }

    fn new_internal(hash: Vec<u8>, left: MerkleNode, right: MerkleNode) -> Self {
        Self {
            hash,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
        }
    }

    fn is_leaf(&self) -> bool {
        self.left.is_none() && self.right.is_none()
    }
}

/// Binary Merkle tree implementation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MerkleTree<H: Hasher> {
    root: Option<MerkleNode>,
    leaves: Vec<Vec<u8>>,
    hasher: H,
}

impl<H: Hasher> MerkleTree<H> {
    /// Create a new Merkle tree from the given data
    pub fn new<T: AsRef<[u8]>>(data: Vec<T>, hasher: H) -> Result<Self> {
        if data.is_empty() {
            return Err(MerkleError::EmptyData);
        }

        let leaves: Vec<Vec<u8>> = data.iter().map(|d| hasher.hash(d.as_ref())).collect();
        let root = Self::build_tree(&leaves, &hasher)?;

        Ok(Self {
            root: Some(root),
            leaves,
            hasher,
        })
    }

    /// Create a new Merkle tree from pre-hashed leaves
    pub fn from_leaves(leaves: Vec<Vec<u8>>, hasher: H) -> Result<Self> {
        if leaves.is_empty() {
            return Err(MerkleError::EmptyData);
        }

        let root = Self::build_tree(&leaves, &hasher)?;

        Ok(Self {
            root: Some(root),
            leaves,
            hasher,
        })
    }

    /// Get the root hash of the tree
    pub fn root(&self) -> &[u8] {
        self.root.as_ref().map(|r| r.hash.as_slice()).unwrap_or(&[])
    }

    /// Get the number of leaves in the tree
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Get the leaf hash at the given index
    pub fn get_leaf(&self, index: usize) -> Result<&[u8]> {
        self.leaves
            .get(index)
            .map(|leaf| leaf.as_slice())
            .ok_or(MerkleError::InvalidIndex {
                index,
                size: self.leaves.len(),
            })
    }

    /// Generate a Merkle proof for the leaf at the given index
    pub fn generate_proof(&self, index: usize) -> Result<MerkleProof> {
        if index >= self.leaves.len() {
            return Err(MerkleError::InvalidIndex {
                index,
                size: self.leaves.len(),
            });
        }

        let root = self
            .root
            .as_ref()
            .ok_or(MerkleError::TreeConstructionError {
                reason: "Tree has no root".to_string(),
            })?;

        let mut steps = Vec::new();
        self.collect_proof_steps(root, index, 0, self.leaves.len(), &mut steps)?;

        // Reverse the steps since we collected them from root to leaf,
        // but verification needs them from leaf to root
        steps.reverse();

        Ok(MerkleProof::new(index, steps))
    }

    /// Verify a Merkle proof for the given leaf data
    pub fn verify_proof(&self, proof: &MerkleProof, leaf_data: &[u8], root: &[u8]) -> bool {
        proof.verify(&self.hasher, leaf_data, root)
    }

    /// Verify a Merkle proof against this tree's root
    pub fn verify_proof_against_root(&self, proof: &MerkleProof, leaf_data: &[u8]) -> bool {
        self.verify_proof(proof, leaf_data, self.root())
    }

    /// Get all leaf hashes
    pub fn leaves(&self) -> &[Vec<u8>] {
        &self.leaves
    }

    /// Get the hasher used by this tree
    pub fn hasher(&self) -> &H {
        &self.hasher
    }

    /// Build the tree from leaf hashes
    fn build_tree(leaves: &[Vec<u8>], hasher: &H) -> Result<MerkleNode> {
        if leaves.is_empty() {
            return Err(MerkleError::EmptyData);
        }

        if leaves.len() == 1 {
            return Ok(MerkleNode::new_leaf(leaves[0].clone()));
        }

        let mut current_level: Vec<MerkleNode> = leaves
            .iter()
            .map(|leaf| MerkleNode::new_leaf(leaf.clone()))
            .collect();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    let left = chunk[0].clone();
                    let right = chunk[1].clone();
                    let combined_hash = hasher.hash_pair(&left.hash, &right.hash);
                    next_level.push(MerkleNode::new_internal(combined_hash, left, right));
                } else {
                    // Odd number of nodes - duplicate the last one
                    let node = chunk[0].clone();
                    let duplicated_hash = hasher.hash_pair(&node.hash, &node.hash);
                    next_level.push(MerkleNode::new_internal(
                        duplicated_hash,
                        node.clone(),
                        node,
                    ));
                }
            }

            current_level = next_level;
        }

        Ok(current_level.into_iter().next().unwrap())
    }

    /// Collect proof steps by traversing the tree
    fn collect_proof_steps(
        &self,
        node: &MerkleNode,
        target_index: usize,
        start_index: usize,
        range_size: usize,
        steps: &mut Vec<ProofStep>,
    ) -> Result<()> {
        if node.is_leaf() {
            return Ok(());
        }

        let left_node = node.left.as_ref().unwrap();
        let right_node = node.right.as_ref().unwrap();

        let mid = start_index + (range_size + 1) / 2;

        if target_index < mid {
            // Target is in left subtree, add right sibling to proof
            steps.push(ProofStep {
                hash: right_node.hash.clone(),
                direction: ProofDirection::Right,
            });
            self.collect_proof_steps(
                left_node,
                target_index,
                start_index,
                mid - start_index,
                steps,
            )?;
        } else {
            // Target is in right subtree, add left sibling to proof
            steps.push(ProofStep {
                hash: left_node.hash.clone(),
                direction: ProofDirection::Left,
            });
            self.collect_proof_steps(
                right_node,
                target_index,
                mid,
                range_size - (mid - start_index),
                steps,
            )?;
        }

        Ok(())
    }

    /// Get tree statistics for debugging
    pub fn stats(&self) -> TreeStats {
        TreeStats {
            leaf_count: self.leaves.len(),
            tree_height: self.calculate_height(),
            hasher_name: self.hasher.name().to_string(),
            root_hash: hex::encode(self.root()),
        }
    }

    /// Calculate the height of the tree
    fn calculate_height(&self) -> usize {
        if self.leaves.is_empty() {
            return 0;
        }

        let mut height = 0;
        let mut nodes = self.leaves.len();

        while nodes > 1 {
            nodes = (nodes + 1) / 2;
            height += 1;
        }

        height
    }
}

/// Tree statistics for debugging and analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TreeStats {
    pub leaf_count: usize,
    pub tree_height: usize,
    pub hasher_name: String,
    pub root_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::{Blake3Hasher, Hasher, Sha256Hasher, Sha3Hasher};

    #[test]
    fn test_single_leaf_tree() {
        let data = vec!["hello".as_bytes()];
        let tree = MerkleTree::new(data, Sha256Hasher::new()).unwrap();
        assert_eq!(tree.len(), 1);
        assert!(!tree.is_empty());
        assert!(tree.root().len() > 0);
    }

    #[test]
    fn test_two_leaf_tree() {
        let data = vec!["hello".as_bytes(), "world".as_bytes()];
        let tree = MerkleTree::new(data, Sha256Hasher::new()).unwrap();
        assert_eq!(tree.len(), 2);

        let proof = tree.generate_proof(0).unwrap();
        assert_eq!(proof.len(), 1);
        assert!(tree.verify_proof_against_root(&proof, "hello".as_bytes()));
        assert!(!tree.verify_proof_against_root(&proof, "wrong".as_bytes()));
    }

    #[test]
    fn test_four_leaf_tree() {
        let data = vec![
            "a".as_bytes(),
            "b".as_bytes(),
            "c".as_bytes(),
            "d".as_bytes(),
        ];
        let tree = MerkleTree::new(data, Sha256Hasher::new()).unwrap();
        assert_eq!(tree.len(), 4);

        // Test proofs for all leaves
        for i in 0..4 {
            let proof = tree.generate_proof(i).unwrap();
            let leaf_data = match i {
                0 => "a".as_bytes(),
                1 => "b".as_bytes(),
                2 => "c".as_bytes(),
                3 => "d".as_bytes(),
                _ => unreachable!(),
            };
            assert!(tree.verify_proof_against_root(&proof, leaf_data));
        }
    }

    #[test]
    fn test_odd_number_of_leaves() {
        let data = vec!["a".as_bytes(), "b".as_bytes(), "c".as_bytes()];
        let tree = MerkleTree::new(data, Sha256Hasher::new()).unwrap();
        assert_eq!(tree.len(), 3);

        // Test proofs for all leaves
        for i in 0..3 {
            let proof = tree.generate_proof(i).unwrap();
            let leaf_data = match i {
                0 => "a".as_bytes(),
                1 => "b".as_bytes(),
                2 => "c".as_bytes(),
                _ => unreachable!(),
            };
            assert!(tree.verify_proof_against_root(&proof, leaf_data));
        }
    }

    #[test]
    fn test_empty_data() {
        let data: Vec<&[u8]> = vec![];
        let result = MerkleTree::new(data, Sha256Hasher::new());
        assert!(matches!(result, Err(MerkleError::EmptyData)));
    }

    #[test]
    fn test_invalid_index() {
        let data = vec![b"hello", b"world"];
        let tree = MerkleTree::new(data, Sha256Hasher::new()).unwrap();

        let result = tree.generate_proof(2);
        assert!(matches!(result, Err(MerkleError::InvalidIndex { .. })));

        let result = tree.get_leaf(2);
        assert!(matches!(result, Err(MerkleError::InvalidIndex { .. })));
    }

    #[test]
    fn test_different_hashers() {
        let data = vec!["hello".as_bytes(), "world".as_bytes()];

        let sha256_tree = MerkleTree::new(data.clone(), Sha256Hasher::new()).unwrap();
        let sha3_tree = MerkleTree::new(data.clone(), Sha3Hasher::new()).unwrap();
        let blake3_tree = MerkleTree::new(data, Blake3Hasher::new()).unwrap();

        // Different hashers should produce different roots
        assert_ne!(sha256_tree.root(), sha3_tree.root());
        assert_ne!(sha256_tree.root(), blake3_tree.root());
        assert_ne!(sha3_tree.root(), blake3_tree.root());
    }

    #[test]
    fn test_from_leaves() {
        let hasher = Sha256Hasher::new();
        let leaves = vec![
            hasher.hash("a".as_bytes()),
            hasher.hash("b".as_bytes()),
            hasher.hash("c".as_bytes()),
        ];

        let tree = MerkleTree::from_leaves(leaves, hasher).unwrap();
        assert_eq!(tree.len(), 3);

        let proof = tree.generate_proof(1).unwrap();
        assert!(proof.verify_with_leaf_hash(tree.hasher(), tree.get_leaf(1).unwrap(), tree.root()));
    }

    #[test]
    fn test_tree_stats() {
        let data = vec![
            "a".as_bytes(),
            "b".as_bytes(),
            "c".as_bytes(),
            "d".as_bytes(),
        ];
        let tree = MerkleTree::new(data, Sha256Hasher::new()).unwrap();

        let stats = tree.stats();
        assert_eq!(stats.leaf_count, 4);
        assert_eq!(stats.tree_height, 2);
        assert_eq!(stats.hasher_name, "SHA-256");
        assert!(!stats.root_hash.is_empty());
    }

    #[test]
    fn test_large_tree() {
        let data: Vec<Vec<u8>> = (0..1000)
            .map(|i| format!("item_{}", i).into_bytes())
            .collect();

        let tree = MerkleTree::new(data, Sha256Hasher::new()).unwrap();
        assert_eq!(tree.len(), 1000);

        // Test a few random proofs
        for &index in &[0, 50, 500, 999] {
            let proof = tree.generate_proof(index).unwrap();
            let leaf_data = format!("item_{}", index).into_bytes();
            assert!(tree.verify_proof_against_root(&proof, &leaf_data));
        }
    }

    #[test]
    fn test_proof_serialization() {
        let data = vec![b"hello", b"world"];
        let tree = MerkleTree::new(data, Sha256Hasher::new()).unwrap();
        let proof = tree.generate_proof(0).unwrap();

        // Test hex representation
        let hex_repr = proof.to_hex();
        assert!(hex_repr.contains("index:0"));
    }
}
