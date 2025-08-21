use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use merkle_tree::{MerkleTree, SparseMerkleTree, Sha256Hasher, Sha3Hasher, Blake3Hasher};

fn bench_tree_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("tree_construction");
    
    for size in [100, 1000, 10000, 100000].iter() {
        let data: Vec<Vec<u8>> = (0..*size)
            .map(|i| format!("item_{}", i).into_bytes())
            .collect();
        
        group.bench_with_input(
            BenchmarkId::new("regular_sha256", size),
            size,
            |b, _| {
                b.iter(|| {
                    let tree = MerkleTree::new(black_box(data.clone()), Sha256Hasher::new()).unwrap();
                    black_box(tree);
                });
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("regular_blake3", size),
            size,
            |b, _| {
                b.iter(|| {
                    let tree = MerkleTree::new(black_box(data.clone()), Blake3Hasher::new()).unwrap();
                    black_box(tree);
                });
            },
        );
    }
    
    group.finish();
}

fn bench_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_generation");
    
    for size in [1000, 10000, 100000].iter() {
        let data: Vec<Vec<u8>> = (0..*size)
            .map(|i| format!("item_{}", i).into_bytes())
            .collect();
        
        let tree = MerkleTree::new(data, Sha256Hasher::new()).unwrap();
        
        group.bench_with_input(
            BenchmarkId::new("regular_tree", size),
            size,
            |b, &size| {
                b.iter(|| {
                    let index = black_box(size / 2);
                    let proof = tree.generate_proof(index).unwrap();
                    black_box(proof);
                });
            },
        );
    }
    
    group.finish();
}

fn bench_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_verification");
    
    let data: Vec<Vec<u8>> = (0..10000)
        .map(|i| format!("item_{}", i).into_bytes())
        .collect();
    
    let tree = MerkleTree::new(data, Sha256Hasher::new()).unwrap();
    let proof = tree.generate_proof(5000).unwrap();
    let leaf_data = "item_5000".as_bytes();
    let root = tree.root();
    
    group.bench_function("verify_proof", |b| {
        b.iter(|| {
            let result = tree.verify_proof(
                black_box(&proof),
                black_box(leaf_data),
                black_box(root),
            );
            black_box(result);
        });
    });
    
    group.finish();
}

fn bench_sparse_tree_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("sparse_tree");
    
    // Benchmark sparse tree updates
    group.bench_function("sparse_update_1000", |b| {
        b.iter(|| {
            let mut tree = SparseMerkleTree::new(20, Sha256Hasher::new()).unwrap();
            for i in 0..1000 {
                tree.update(black_box(i * 1000), black_box(&format!("value_{}", i).into_bytes())).unwrap();
            }
            black_box(tree);
        });
    });
    
    // Benchmark sparse tree proof generation
    let mut tree = SparseMerkleTree::new(20, Sha256Hasher::new()).unwrap();
    for i in 0..1000 {
        tree.update(i * 1000, &format!("value_{}", i).into_bytes()).unwrap();
    }
    
    group.bench_function("sparse_proof_generation", |b| {
        b.iter(|| {
            let proof = tree.generate_proof(black_box(500000)).unwrap();
            black_box(proof);
        });
    });
    
    group.finish();
}

fn bench_hasher_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("hasher_comparison");
    
    group.bench_function("sha256_tree_1000", |b| {
        let test_data: Vec<Vec<u8>> = (0..1000)
            .map(|i| format!("item_{}", i).into_bytes())
            .collect();
        b.iter(|| {
            let tree = MerkleTree::new(black_box(test_data.clone()), Sha256Hasher::new()).unwrap();
            black_box(tree);
        });
    });
    
    group.bench_function("sha3_tree_1000", |b| {
        let test_data: Vec<Vec<u8>> = (0..1000)
            .map(|i| format!("item_{}", i).into_bytes())
            .collect();
        b.iter(|| {
            let tree = MerkleTree::new(black_box(test_data.clone()), Sha3Hasher::new()).unwrap();
            black_box(tree);
        });
    });
    
    group.bench_function("blake3_tree_1000", |b| {
        let test_data: Vec<Vec<u8>> = (0..1000)
            .map(|i| format!("item_{}", i).into_bytes())
            .collect();
        b.iter(|| {
            let tree = MerkleTree::new(black_box(test_data.clone()), Blake3Hasher::new()).unwrap();
            black_box(tree);
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_tree_construction,
    bench_proof_generation,
    bench_proof_verification,
    bench_sparse_tree_operations,
    bench_hasher_comparison
);

criterion_main!(benches);
