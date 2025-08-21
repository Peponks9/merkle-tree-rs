use merkle_tree::{MerkleTree, Sha256Hasher};

fn main() {
    let data = vec![
        "a".as_bytes(),
        "b".as_bytes(),
        "c".as_bytes(),
        "d".as_bytes(),
    ];
    let tree = MerkleTree::new(data, Sha256Hasher::new()).unwrap();

    println!("Tree created with {} leaves", tree.len());

    // Test all proofs
    for i in 0..4 {
        let proof = tree.generate_proof(i).unwrap();
        let leaf_data = match i {
            0 => "a".as_bytes(),
            1 => "b".as_bytes(),
            2 => "c".as_bytes(),
            3 => "d".as_bytes(),
            _ => unreachable!(),
        };

        println!("Testing proof for index {}", i);
        println!("  Leaf data: {:?}", std::str::from_utf8(leaf_data).unwrap());
        println!("  Stored leaf hash: {:?}", tree.get_leaf(i).unwrap());

        let verify_result = tree.verify_proof_against_root(&proof, leaf_data);
        println!("  Verification result: {}", verify_result);

        if !verify_result {
            println!("  ERROR: Proof verification failed!");
            break;
        }
    }

    println!("All tests completed");
}
