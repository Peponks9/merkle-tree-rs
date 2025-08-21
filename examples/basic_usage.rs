use merkle_tree::{
    MerkleTree, SparseMerkleTree, Sha256Hasher, Sha3Hasher, Blake3Hasher,
    Result, sparse
};

fn main() -> Result<()> {
    println!("=== Merkle Tree Library Demo ===\n");
    
    // Basic usage example
    basic_usage_example()?;
    
    // Different hasher examples
    hasher_comparison_example()?;
    
    // Sparse Merkle tree example
    sparse_tree_example()?;
    
    // Proof verification example
    proof_verification_example()?;
    
    // Simple serialization demo
    serialization_example()?;
    
    Ok(())
}

fn basic_usage_example() -> Result<()> {
    println!("1. Basic Merkle Tree Usage");
    println!("==========================");
    
    let data = vec![
        "Transaction 1: Alice -> Bob 10 BTC".as_bytes(),
        "Transaction 2: Bob -> Charlie 5 BTC".as_bytes(), 
        "Transaction 3: Charlie -> Alice 3 BTC".as_bytes(),
        "Transaction 4: Alice -> Dave 2 BTC".as_bytes(),
    ];
    
    let tree = MerkleTree::new(data, Sha256Hasher::new())?;
    
    println!("Created tree with {} leaves", tree.len());
    println!("Tree root: {}", hex::encode(tree.root()));
    println!("Tree height: {}", tree.stats().tree_height);
    
    // Generate proof for transaction 2
    let proof = tree.generate_proof(1)?;
    println!("Generated proof for transaction 2: {} steps", proof.len());
    println!("Proof details: {}", proof.to_hex());
    
    // Verify the proof
    let is_valid = tree.verify_proof_against_root(&proof, "Transaction 2: Bob -> Charlie 5 BTC".as_bytes());
    println!("Proof verification: {}", if is_valid { "✓ Valid" } else { "✗ Invalid" });
    
    println!();
    Ok(())
}

fn hasher_comparison_example() -> Result<()> {
    println!("2. Different Hash Functions");
    println!("===========================");
    
    let data = vec!["same".as_bytes(), "data".as_bytes(), "different".as_bytes(), "hashes".as_bytes()];
    
    let sha256_tree = MerkleTree::new(data.clone(), Sha256Hasher::new())?;
    let sha3_tree = MerkleTree::new(data.clone(), Sha3Hasher::new())?;
    let blake3_tree = MerkleTree::new(data, Blake3Hasher::new())?;
    
    println!("SHA-256 root: {}", hex::encode(sha256_tree.root()));
    println!("SHA-3 root:   {}", hex::encode(sha3_tree.root()));
    println!("BLAKE3 root:  {}", hex::encode(blake3_tree.root()));
    
    println!("All roots are different, demonstrating hash function independence");
    println!();
    Ok(())
}

fn sparse_tree_example() -> Result<()> {
    println!("3. Sparse Merkle Tree");
    println!("====================");
    
    let mut sparse_tree = SparseMerkleTree::new(16, Sha256Hasher::new())?;
    
    // Insert sparse data (simulating a blockchain state tree)
    let accounts = vec![
        (1000, "Alice: 50 BTC"),
        (5000, "Bob: 25 BTC"),
        (10000, "Charlie: 100 BTC"),
        (50000, "Dave: 75 BTC"),
    ];
    
    for (index, account) in &accounts {
        sparse_tree.update(*index, account.as_bytes())?;
    }
    
    let stats = sparse_tree.stats();
    println!("Sparse tree depth: {}", stats.depth);
    println!("Non-empty leaves: {} / {} possible", stats.leaf_count, stats.max_leaves);
    println!("Root hash: {}", stats.root_hash);
    
    // Generate proof for Alice's account
    let proof = sparse_tree.generate_proof(1000)?;
    let is_valid = sparse_tree.verify_proof(&proof, 1000, b"Alice: 50 BTC");
    println!("Proof for Alice's account: {}", if is_valid { "✓ Valid" } else { "✗ Invalid" });
    
    // Prove non-existence of account at index 2000
    let non_existence_proof = sparse_tree.generate_proof(2000)?;
    let empty_valid = sparse_tree.verify_proof(&non_existence_proof, 2000, &sparse::DEFAULT_HASH);
    println!("Proof of non-existence at index 2000: {}", if empty_valid { "✓ Valid" } else { "✗ Invalid" });
    
    println!();
    Ok(())
}

fn proof_verification_example() -> Result<()> {
    println!("4. Proof Verification Scenarios");
    println!("===============================");
    
    let documents = vec![
        "Contract A: Terms and Conditions".as_bytes(),
        "Contract B: Service Agreement".as_bytes(), 
        "Contract C: Privacy Policy".as_bytes(),
        "Contract D: License Agreement".as_bytes(),
    ];
    
    let tree = MerkleTree::new(documents, Blake3Hasher::new())?;
    let root_hash = tree.root().to_vec();
    
    println!("Document tree root: {}", hex::encode(&root_hash));
    
    // Generate proof for Contract B
    let proof = tree.generate_proof(1)?;
    
    // Scenario 1: Valid proof with correct document
    let valid = tree.verify_proof(&proof, "Contract B: Service Agreement".as_bytes(), &root_hash);
    println!("Valid document verification: {}", if valid { "✓ Passed" } else { "✗ Failed" });
    
    // Scenario 2: Invalid proof with tampered document
    let invalid = tree.verify_proof(&proof, "Contract B: TAMPERED Agreement".as_bytes(), &root_hash);
    println!("Tampered document verification: {}", if invalid { "✗ Unexpectedly passed" } else { "✓ Correctly failed" });
    
    // Scenario 3: Wrong proof for different document
    let wrong_proof = tree.generate_proof(0)?; // Proof for Contract A
    let wrong = tree.verify_proof(&wrong_proof, "Contract B: Service Agreement".as_bytes(), &root_hash);
    println!("Wrong proof verification: {}", if wrong { "✗ Unexpectedly passed" } else { "✓ Correctly failed" });
    
    println!();
    Ok(())
}

#[cfg(feature = "serde")]
fn serialization_example() -> Result<()> {
    println!("5. Proof Details Demo");
    println!("====================");
    
    let data = vec!["data1".as_bytes(), "data2".as_bytes(), "data3".as_bytes()];
    let tree = MerkleTree::new(data, Sha256Hasher::new())?;
    let proof = tree.generate_proof(1)?;
    
    println!("Proof details: {}", proof.to_hex());
    
    let is_valid = tree.verify_proof_against_root(&proof, "data2".as_bytes());
    println!("Manual proof verification: {}", if is_valid { "✓ Valid" } else { "✗ Invalid" });
    
    println!();
    Ok(())
}
