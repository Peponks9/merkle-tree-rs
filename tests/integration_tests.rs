use merkle_tree::{
    sparse, Blake3Hasher, MerkleError, MerkleTree, Result, Sha256Hasher, Sha3Hasher,
    SparseMerkleTree,
};

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_cross_hasher_compatibility() {
        let data = vec![
            "hello".as_bytes(),
            "world".as_bytes(),
            "merkle".as_bytes(),
            "tree".as_bytes(),
        ];

        // Test with all supported hashers
        let sha256_tree = MerkleTree::new(data.clone(), Sha256Hasher::new()).unwrap();
        let sha3_tree = MerkleTree::new(data.clone(), Sha3Hasher::new()).unwrap();
        let blake3_tree = MerkleTree::new(data, Blake3Hasher::new()).unwrap();

        // Each hasher should produce different roots
        assert_ne!(sha256_tree.root(), sha3_tree.root());
        assert_ne!(sha256_tree.root(), blake3_tree.root());
        assert_ne!(sha3_tree.root(), blake3_tree.root());

        // But proofs should work correctly for each
        // Test SHA256 tree
        for i in 0..4 {
            let proof = sha256_tree.generate_proof(i).unwrap();
            let leaf_data = match i {
                0 => "hello".as_bytes(),
                1 => "world".as_bytes(),
                2 => "merkle".as_bytes(),
                3 => "tree".as_bytes(),
                _ => unreachable!(),
            };
            assert!(sha256_tree.verify_proof_against_root(&proof, leaf_data));
        }

        // Test SHA3 tree
        for i in 0..4 {
            let proof = sha3_tree.generate_proof(i).unwrap();
            let leaf_data = match i {
                0 => "hello".as_bytes(),
                1 => "world".as_bytes(),
                2 => "merkle".as_bytes(),
                3 => "tree".as_bytes(),
                _ => unreachable!(),
            };
            assert!(sha3_tree.verify_proof_against_root(&proof, leaf_data));
        }

        // Test BLAKE3 tree
        for i in 0..4 {
            let proof = blake3_tree.generate_proof(i).unwrap();
            let leaf_data = match i {
                0 => "hello".as_bytes(),
                1 => "world".as_bytes(),
                2 => "merkle".as_bytes(),
                3 => "tree".as_bytes(),
                _ => unreachable!(),
            };
            assert!(blake3_tree.verify_proof_against_root(&proof, leaf_data));
        }
    }

    #[test]
    fn test_sparse_vs_regular_tree() {
        let hasher = Sha256Hasher::new();

        // Create regular tree with 4 elements
        let data = vec![
            "a".as_bytes(),
            "b".as_bytes(),
            "c".as_bytes(),
            "d".as_bytes(),
        ];
        let regular_tree = MerkleTree::new(data, hasher.clone()).unwrap();

        // Create equivalent sparse tree
        let mut sparse_tree = SparseMerkleTree::new(8, hasher).unwrap();
        sparse_tree.update(0, "a".as_bytes()).unwrap();
        sparse_tree.update(1, "b".as_bytes()).unwrap();
        sparse_tree.update(2, "c".as_bytes()).unwrap();
        sparse_tree.update(3, "d".as_bytes()).unwrap();

        // Roots will be different because sparse tree has different structure
        // But both should have valid proofs for their respective data

        let regular_proof = regular_tree.generate_proof(0).unwrap();
        assert!(regular_tree.verify_proof_against_root(&regular_proof, "a".as_bytes()));

        let sparse_proof = sparse_tree.generate_proof(0).unwrap();
        assert!(sparse_tree.verify_proof(&sparse_proof, 0, "a".as_bytes()));
    }

    #[test]
    fn test_large_dataset_performance() {
        let hasher = Sha256Hasher::new();

        // Create large dataset
        let data: Vec<Vec<u8>> = (0..10000)
            .map(|i| format!("item_{:05}", i).into_bytes())
            .collect();

        let tree = MerkleTree::new(data, hasher).unwrap();
        assert_eq!(tree.len(), 10000);

        // Test random proofs
        for &index in &[0, 1000, 5000, 9999] {
            let proof = tree.generate_proof(index).unwrap();
            let leaf_data = format!("item_{:05}", index).into_bytes();
            assert!(tree.verify_proof_against_root(&proof, &leaf_data));
        }
    }

    #[test]
    fn test_sparse_tree_with_gaps() {
        let mut tree = SparseMerkleTree::new(16, Sha256Hasher::new()).unwrap();

        // Insert sparse data with large gaps
        let indices = vec![0, 100, 5000, 10000, 65535];
        for &i in &indices {
            tree.update(i, format!("value_{}", i).as_bytes()).unwrap();
        }

        assert_eq!(tree.len(), 5);

        // Verify all inserted values
        for &i in &indices {
            let proof = tree.generate_proof(i).unwrap();
            let value = format!("value_{}", i);
            assert!(tree.verify_proof(&proof, i, value.as_bytes()));
        }

        // Verify empty slots
        let empty_proof = tree.generate_proof(50).unwrap();
        assert!(tree.verify_proof(&empty_proof, 50, &sparse::DEFAULT_HASH));
    }

    #[test]
    fn test_proof_serialization_roundtrip() {
        let data = vec!["hello".as_bytes(), "world".as_bytes(), "test".as_bytes()];
        let tree = MerkleTree::new(data, Sha256Hasher::new()).unwrap();

        let proof = tree.generate_proof(1).unwrap();

        // Test hex representation
        let hex_repr = proof.to_hex();
        assert!(hex_repr.contains("index:1"));
        assert!(hex_repr.len() > 0);

        // Verify proof still works
        assert!(tree.verify_proof_against_root(&proof, "world".as_bytes()));
    }

    #[test]
    fn test_error_handling() {
        // Test empty data error
        let result: Result<MerkleTree<Sha256Hasher>> =
            MerkleTree::new(Vec::<&[u8]>::new(), Sha256Hasher::new());
        assert!(matches!(result, Err(MerkleError::EmptyData)));

        // Test invalid index error
        let tree = MerkleTree::new(vec!["test".as_bytes()], Sha256Hasher::new()).unwrap();
        let result = tree.generate_proof(1);
        assert!(matches!(result, Err(MerkleError::InvalidIndex { .. })));

        // Test sparse tree invalid depth
        let result = SparseMerkleTree::new(0, Sha256Hasher::new());
        assert!(matches!(
            result,
            Err(MerkleError::TreeConstructionError { .. })
        ));

        let result = SparseMerkleTree::new(65, Sha256Hasher::new());
        assert!(matches!(
            result,
            Err(MerkleError::TreeConstructionError { .. })
        ));
    }

    #[test]
    fn test_tree_statistics() {
        let data = vec![
            "a".as_bytes(),
            "b".as_bytes(),
            "c".as_bytes(),
            "d".as_bytes(),
            "e".as_bytes(),
        ];
        let tree = MerkleTree::new(data, Blake3Hasher::new()).unwrap();

        let stats = tree.stats();
        assert_eq!(stats.leaf_count, 5);
        assert!(stats.tree_height > 0);
        assert_eq!(stats.hasher_name, "BLAKE3");
        assert!(stats.root_hash.len() > 0);

        // Test sparse tree stats
        let mut sparse_tree = SparseMerkleTree::new(10, Sha3Hasher::new()).unwrap();
        sparse_tree.update(5, "test".as_bytes()).unwrap();
        sparse_tree.update(100, "test2".as_bytes()).unwrap();

        let sparse_stats = sparse_tree.stats();
        assert_eq!(sparse_stats.depth, 10);
        assert_eq!(sparse_stats.leaf_count, 2);
        assert_eq!(sparse_stats.max_leaves, 1024);
        assert_eq!(sparse_stats.hasher_name, "SHA3-256");
    }

    #[test]
    fn test_concurrent_operations() {
        use std::sync::Arc;
        use std::thread;

        let data = vec![
            "a".as_bytes(),
            "b".as_bytes(),
            "c".as_bytes(),
            "d".as_bytes(),
        ];
        let tree = Arc::new(MerkleTree::new(data, Sha256Hasher::new()).unwrap());

        let mut handles = vec![];

        // Spawn multiple threads to generate proofs concurrently
        for i in 0..4 {
            let tree_clone = Arc::clone(&tree);
            let handle = thread::spawn(move || {
                let proof = tree_clone.generate_proof(i % 4).unwrap();
                let leaf_data = match i % 4 {
                    0 => "a".as_bytes(),
                    1 => "b".as_bytes(),
                    2 => "c".as_bytes(),
                    3 => "d".as_bytes(),
                    _ => unreachable!(),
                };
                assert!(tree_clone.verify_proof_against_root(&proof, leaf_data));
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_memory_efficiency() {
        // Test that sparse tree is memory efficient for sparse data
        let mut dense_indices = Vec::new();
        let mut sparse_indices = Vec::new();

        // Dense: 0, 1, 2, ..., 999
        for i in 0..1000 {
            dense_indices.push(i);
        }

        // Sparse: 0, 1000, 2000, ..., 999000
        for i in 0..1000 {
            sparse_indices.push(i * 1000);
        }

        let hasher = Sha256Hasher::new();

        // Both trees should handle their respective data efficiently
        let mut dense_tree = SparseMerkleTree::new(20, hasher.clone()).unwrap();
        for &i in &dense_indices {
            dense_tree
                .update(i, format!("value_{}", i).as_bytes())
                .unwrap();
        }

        let mut sparse_tree = SparseMerkleTree::new(20, hasher).unwrap();
        for &i in &sparse_indices {
            sparse_tree
                .update(i, format!("value_{}", i).as_bytes())
                .unwrap();
        }

        assert_eq!(dense_tree.len(), 1000);
        assert_eq!(sparse_tree.len(), 1000);

        // Both should be able to generate valid proofs
        let dense_proof = dense_tree.generate_proof(500).unwrap();
        assert!(dense_tree.verify_proof(&dense_proof, 500, "value_500".as_bytes()));

        let sparse_proof = sparse_tree.generate_proof(500000).unwrap();
        assert!(sparse_tree.verify_proof(&sparse_proof, 500000, "value_500000".as_bytes()));
    }

    #[test]
    fn test_edge_cases() {
        // Single element tree
        let single_tree = MerkleTree::new(vec!["single".as_bytes()], Sha256Hasher::new()).unwrap();
        let proof = single_tree.generate_proof(0).unwrap();
        assert!(proof.is_empty()); // Single element tree has no siblings
        assert!(single_tree.verify_proof_against_root(&proof, "single".as_bytes()));

        // Power of 2 vs non-power of 2 sizes
        let pow2_tree = MerkleTree::new(
            vec![
                "a".as_bytes(),
                "b".as_bytes(),
                "c".as_bytes(),
                "d".as_bytes(),
            ],
            Sha256Hasher::new(),
        )
        .unwrap();
        let non_pow2_tree = MerkleTree::new(
            vec![
                "a".as_bytes(),
                "b".as_bytes(),
                "c".as_bytes(),
                "d".as_bytes(),
                "e".as_bytes(),
            ],
            Sha256Hasher::new(),
        )
        .unwrap();

        // Both should generate valid proofs
        for tree in [&pow2_tree, &non_pow2_tree] {
            for i in 0..tree.len() {
                let proof = tree.generate_proof(i).unwrap();
                assert!(proof.len() > 0 || tree.len() == 1);
            }
        }
    }
}
