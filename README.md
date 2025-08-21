# Merkle Tree Library in Rust

A production-ready Merkle tree library implemented in Rust with proof generation/verification, generic hash support, and comprehensive testing.

## Features

- **Binary Merkle Tree**: Efficient binary tree implementation for standard use cases
- **Sparse Merkle Tree**: Memory-efficient implementation for sparse data sets
- **Multiple Hash Functions**: Support for SHA-256, SHA-3, and BLAKE3
- **Proof Generation & Verification**: Complete proof system with detailed verification
- **Serialization Support**: Optional serde support for proof serialization
- **Performance Optimized**: Benchmarked and optimized
- **Comprehensive Testing**: Test suite with edge cases

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
merkle-tree-rs = "0.1.0"
```

### Basic Usage

```rust
use merkle_tree::{MerkleTree, Sha256Hasher};

// Create a tree from your data
let data = vec![b"hello", b"world", b"merkle", b"tree"];
let tree = MerkleTree::new(data, Sha256Hasher::new())?;

// Get the root hash
let root = tree.root();
println!("Root hash: {}", hex::encode(root));

// Generate a proof for the first element
let proof = tree.generate_proof(0)?;

// Verify the proof
assert!(tree.verify_proof_against_root(&proof, b"hello"));
```

### Sparse Merkle Tree

```rust
use merkle_tree::{SparseMerkleTree, Sha256Hasher};

// Create a sparse tree with depth 20 (can hold 2^20 elements)
let mut tree = SparseMerkleTree::new(20, Sha256Hasher::new())?;

// Insert sparse data
tree.update(1000, b"account_1000")?;
tree.update(50000, b"account_50000")?;

// Generate proof for existence
let proof = tree.generate_proof(1000)?;
assert!(tree.verify_proof(&proof, 1000, b"account_1000"));

// Generate proof for non-existence
let empty_proof = tree.generate_proof(2000)?;
assert!(tree.verify_proof(&empty_proof, 2000, &[0u8; 32]));
```

### Different Hash Functions

```rust
use merkle_tree::{MerkleTree, Sha256Hasher, Sha3Hasher, Blake3Hasher};

let data = vec![b"same", b"data"];

let sha256_tree = MerkleTree::new(data.clone(), Sha256Hasher::new())?;
let sha3_tree = MerkleTree::new(data.clone(), Sha3Hasher::new())?;
let blake3_tree = MerkleTree::new(data, Blake3Hasher::new())?;

// Each hasher produces different roots for the same data
assert_ne!(sha256_tree.root(), sha3_tree.root());
assert_ne!(sha256_tree.root(), blake3_tree.root());
```

## Performance

Run benchmarks:

```bash
cargo bench
```

## Testing

Run the full test suite:

```bash
# Unit tests
cargo test

# Integration tests
cargo test --test integration_tests

# All tests with coverage
cargo test --all-features
```

## Examples

Check out the examples directory:

```bash
# Basic usage example
cargo run --example basic_usage
```

## License

This project is licensed under the MIT License.
