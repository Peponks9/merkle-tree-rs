use crate::error::{MerkleError, Result};
use crate::hasher::Hasher;
use crate::proof::{MerkleProof, ProofDirection, ProofStep};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Default value for empty nodes in sparse Merkle tree
pub const DEFAULT_HASH: [u8; 32] = [0u8; 32];

/// A sparse Merkle tree implementation optimized for sparse data
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SparseMerkleTree<H: Hasher> {
    /// Map from leaf index to leaf hash
    leaves: HashMap<u64, Vec<u8>>,
    /// Cached internal nodes for efficiency
    nodes: HashMap<(u64, u8), Vec<u8>>, // (index, level) -> hash
    /// Tree depth (height)
    depth: u8,
    /// Hash function
    hasher: H,
    /// Root hash cache
    root_cache: Option<Vec<u8>>,
}

impl<H: Hasher> SparseMerkleTree<H> {
    /// Create a new sparse Merkle tree with the given depth
    pub fn new(depth: u8, hasher: H) -> Result<Self> {
        if depth == 0 || depth > 64 {
            return Err(MerkleError::TreeConstructionError {
                reason: format!("Invalid depth: {}. Must be between 1 and 64", depth),
            });
        }

        Ok(Self {
            leaves: HashMap::new(),
            nodes: HashMap::new(),
            depth,
            hasher,
            root_cache: None,
        })
    }

    /// Insert or update a leaf at the given index
    pub fn update(&mut self, index: u64, value: &[u8]) -> Result<()> {
        let max_index = (1u64 << self.depth) - 1;
        if index > max_index {
            return Err(MerkleError::InvalidIndex {
                index: index as usize,
                size: (max_index + 1) as usize,
            });
        }

        let leaf_hash = self.hasher.hash(value);
        self.leaves.insert(index, leaf_hash);

        // Invalidate caches
        self.root_cache = None;
        self.nodes.clear();

        Ok(())
    }

    /// Remove a leaf at the given index
    pub fn remove(&mut self, index: u64) -> Result<bool> {
        let removed = self.leaves.remove(&index).is_some();

        if removed {
            // Invalidate caches
            self.root_cache = None;
            self.nodes.clear();
        }

        Ok(removed)
    }

    /// Get the value hash at the given index
    pub fn get(&self, index: u64) -> Option<&[u8]> {
        self.leaves.get(&index).map(|h| h.as_slice())
    }

    /// Check if a leaf exists at the given index
    pub fn contains(&self, index: u64) -> bool {
        self.leaves.contains_key(&index)
    }

    /// Get the root hash of the tree
    pub fn root(&mut self) -> &[u8] {
        if self.root_cache.is_none() {
            self.root_cache = Some(self.compute_root());
        }
        self.root_cache.as_ref().unwrap()
    }

    /// Get the number of non-empty leaves
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Get the depth of the tree
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Generate a Merkle proof for the given index
    pub fn generate_proof(&mut self, index: u64) -> Result<MerkleProof> {
        let max_index = (1u64 << self.depth) - 1;
        if index > max_index {
            return Err(MerkleError::InvalidIndex {
                index: index as usize,
                size: (max_index + 1) as usize,
            });
        }

        let mut steps = Vec::new();
        let mut current_index = index;

        for level in 0..self.depth {
            let sibling_index = current_index ^ 1; // Flip the last bit
            let sibling_hash = self.get_node_hash(sibling_index, level);

            let direction = if current_index & 1 == 0 {
                ProofDirection::Right
            } else {
                ProofDirection::Left
            };

            steps.push(ProofStep {
                hash: sibling_hash,
                direction,
            });

            current_index >>= 1; // Move to parent
        }

        Ok(MerkleProof::new(index as usize, steps))
    }

    /// Verify a proof for the given index and value
    pub fn verify_proof(&mut self, proof: &MerkleProof, index: u64, value: &[u8]) -> bool {
        if proof.leaf_index != index as usize {
            return false;
        }

        let leaf_hash = self.hasher.hash(value);
        let computed_root = proof.compute_root(&self.hasher, &leaf_hash);
        let actual_root = self.root();

        computed_root == actual_root
    }

    /// Get all non-empty leaf indices
    pub fn leaf_indices(&self) -> Vec<u64> {
        let mut indices: Vec<u64> = self.leaves.keys().cloned().collect();
        indices.sort_unstable();
        indices
    }

    /// Get all non-empty leaves as (index, hash) pairs
    pub fn leaves(&self) -> Vec<(u64, &[u8])> {
        let mut leaves: Vec<(u64, &[u8])> = self
            .leaves
            .iter()
            .map(|(&index, hash)| (index, hash.as_slice()))
            .collect();
        leaves.sort_unstable_by_key(|&(index, _)| index);
        leaves
    }

    /// Compute the root hash
    fn compute_root(&mut self) -> Vec<u8> {
        self.get_node_hash(1, self.depth)
    }

    /// Get the hash of a node at the given index and level
    fn get_node_hash(&mut self, index: u64, level: u8) -> Vec<u8> {
        if level == 0 {
            // Leaf level
            return self
                .leaves
                .get(&index)
                .cloned()
                .unwrap_or_else(|| DEFAULT_HASH.to_vec());
        }

        // Check cache first
        if let Some(hash) = self.nodes.get(&(index, level)) {
            return hash.clone();
        }

        // Compute from children
        let left_child = index << 1;
        let right_child = left_child + 1;

        let left_hash = self.get_node_hash(left_child, level - 1);
        let right_hash = self.get_node_hash(right_child, level - 1);

        let hash = self.hasher.hash_pair(&left_hash, &right_hash);

        // Cache the result
        self.nodes.insert((index, level), hash.clone());

        hash
    }

    /// Get tree statistics
    pub fn stats(&mut self) -> SparseTreeStats {
        SparseTreeStats {
            depth: self.depth,
            leaf_count: self.leaves.len(),
            max_leaves: 1u64 << self.depth,
            cached_nodes: self.nodes.len(),
            hasher_name: self.hasher.name().to_string(),
            root_hash: hex::encode(self.root()),
        }
    }

    /// Clear all data and caches
    pub fn clear(&mut self) {
        self.leaves.clear();
        self.nodes.clear();
        self.root_cache = None;
    }
}

/// Statistics for sparse Merkle tree
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SparseTreeStats {
    pub depth: u8,
    pub leaf_count: usize,
    pub max_leaves: u64,
    pub cached_nodes: usize,
    pub hasher_name: String,
    pub root_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::{Hasher, Sha256Hasher};

    #[test]
    fn test_create_sparse_tree() {
        let tree = SparseMerkleTree::new(8, Sha256Hasher::new()).unwrap();
        assert_eq!(tree.depth(), 8);
        assert_eq!(tree.len(), 0);
        assert!(tree.is_empty());
    }

    #[test]
    fn test_invalid_depth() {
        assert!(SparseMerkleTree::new(0, Sha256Hasher::new()).is_err());
        assert!(SparseMerkleTree::new(65, Sha256Hasher::new()).is_err());
    }

    #[test]
    fn test_update_and_get() {
        let mut tree = SparseMerkleTree::new(8, Sha256Hasher::new()).unwrap();

        tree.update(10, "hello".as_bytes()).unwrap();
        tree.update(20, "world".as_bytes()).unwrap();

        assert_eq!(tree.len(), 2);
        assert!(!tree.is_empty());
        assert!(tree.contains(10));
        assert!(tree.contains(20));
        assert!(!tree.contains(30));

        let hash10 = tree.get(10).unwrap();
        let expected_hash = tree.hasher.hash("hello".as_bytes());
        assert_eq!(hash10, expected_hash);
    }

    #[test]
    fn test_remove() {
        let mut tree = SparseMerkleTree::new(8, Sha256Hasher::new()).unwrap();

        tree.update(10, "hello".as_bytes()).unwrap();
        assert!(tree.contains(10));

        let removed = tree.remove(10).unwrap();
        assert!(removed);
        assert!(!tree.contains(10));

        let not_removed = tree.remove(10).unwrap();
        assert!(!not_removed);
    }

    #[test]
    fn test_root_computation() {
        let mut tree = SparseMerkleTree::new(4, Sha256Hasher::new()).unwrap();

        let empty_root = tree.root().to_vec();

        tree.update(0, "test".as_bytes()).unwrap();
        let root_with_data = tree.root().to_vec();

        // Root should change after adding data
        assert_ne!(empty_root, root_with_data);

        tree.remove(0).unwrap();
        let root_after_removal = tree.root().to_vec();

        // Root should return to original state
        assert_eq!(empty_root, root_after_removal);
    }

    #[test]
    fn test_proof_generation_and_verification() {
        let mut tree = SparseMerkleTree::new(8, Sha256Hasher::new()).unwrap();

        tree.update(10, "hello".as_bytes()).unwrap();
        tree.update(20, "world".as_bytes()).unwrap();

        let proof = tree.generate_proof(10).unwrap();
        assert!(tree.verify_proof(&proof, 10, "hello".as_bytes()));
        assert!(!tree.verify_proof(&proof, 10, "wrong".as_bytes()));

        let proof_empty = tree.generate_proof(30).unwrap();
        assert!(tree.verify_proof(&proof_empty, 30, &DEFAULT_HASH));
    }

    #[test]
    fn test_invalid_index() {
        let mut tree = SparseMerkleTree::new(4, Sha256Hasher::new()).unwrap();

        // Max index for depth 4 is 15
        assert!(tree.update(16, "test".as_bytes()).is_err());
        assert!(tree.generate_proof(16).is_err());
    }

    #[test]
    fn test_leaf_indices_and_leaves() {
        let mut tree = SparseMerkleTree::new(8, Sha256Hasher::new()).unwrap();

        tree.update(5, "five".as_bytes()).unwrap();
        tree.update(1, "one".as_bytes()).unwrap();
        tree.update(10, "ten".as_bytes()).unwrap();

        let indices = tree.leaf_indices();
        assert_eq!(indices, vec![1, 5, 10]);

        let leaves = tree.leaves();
        assert_eq!(leaves.len(), 3);
        assert_eq!(leaves[0].0, 1);
        assert_eq!(leaves[1].0, 5);
        assert_eq!(leaves[2].0, 10);
    }

    #[test]
    fn test_stats() {
        let mut tree = SparseMerkleTree::new(8, Sha256Hasher::new()).unwrap();

        tree.update(10, "hello".as_bytes()).unwrap();
        tree.update(20, "world".as_bytes()).unwrap();

        let stats = tree.stats();
        assert_eq!(stats.depth, 8);
        assert_eq!(stats.leaf_count, 2);
        assert_eq!(stats.max_leaves, 256);
        assert_eq!(stats.hasher_name, "SHA-256");
        assert!(!stats.root_hash.is_empty());
    }

    #[test]
    fn test_clear() {
        let mut tree = SparseMerkleTree::new(8, Sha256Hasher::new()).unwrap();

        tree.update(10, "hello".as_bytes()).unwrap();
        tree.update(20, "world".as_bytes()).unwrap();
        assert_eq!(tree.len(), 2);

        tree.clear();
        assert_eq!(tree.len(), 0);
        assert!(tree.is_empty());
        assert!(!tree.contains(10));
        assert!(!tree.contains(20));
    }

    #[test]
    fn test_large_sparse_tree() {
        let mut tree = SparseMerkleTree::new(20, Sha256Hasher::new()).unwrap();

        // Insert sparse data
        for i in &[0, 1000, 10000, 100000, 500000] {
            tree.update(*i, format!("value_{}", i).as_bytes()).unwrap();
        }

        assert_eq!(tree.len(), 5);

        // Test proofs for all inserted values
        for &i in &[0, 1000, 10000, 100000, 500000] {
            let proof = tree.generate_proof(i).unwrap();
            let value = format!("value_{}", i);
            assert!(tree.verify_proof(&proof, i, value.as_bytes()));
        }

        // Test proof for non-existent value
        let empty_proof = tree.generate_proof(999).unwrap();
        assert!(tree.verify_proof(&empty_proof, 999, &DEFAULT_HASH));
    }
}
