# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-08-21

### Added

- Initial implementation of binary Merkle tree
- Sparse Merkle tree implementation
- Support for multiple hash functions (SHA-256, SHA-3, BLAKE3)
- Proof generation and verification system
- Comprehensive error handling with `thiserror`
- Optional serde support for serialization
- Extensive test suite with integration tests
- Performance benchmarks
- Complete documentation and examples
- MIT license

### Features

- Generic hash function support through `Hasher` trait
- Memory-efficient sparse tree for large address spaces
- Production-ready error handling
- Thread-safe implementations
- Optimized proof verification
- Detailed debugging support with hex representations
