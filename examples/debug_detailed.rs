use merkle_tree::{Hasher, MerkleTree, Sha256Hasher};

fn main() {
    let hasher = Sha256Hasher::new();

    // Let's manually build what the tree should look like
    let leaf_a = hasher.hash("a".as_bytes());
    let leaf_b = hasher.hash("b".as_bytes());
    let leaf_c = hasher.hash("c".as_bytes());
    let leaf_d = hasher.hash("d".as_bytes());

    println!("Manual leaf hashes:");
    println!("  a: {:?}", leaf_a);
    println!("  b: {:?}", leaf_b);
    println!("  c: {:?}", leaf_c);
    println!("  d: {:?}", leaf_d);

    // Manual tree construction
    let left_internal = hasher.hash_pair(&leaf_a, &leaf_b); // hash(a||b)
    let right_internal = hasher.hash_pair(&leaf_c, &leaf_d); // hash(c||d)
    let root = hasher.hash_pair(&left_internal, &right_internal); // hash(ab||cd)

    println!("\nManual internal nodes:");
    println!("  left_internal (a||b): {:?}", left_internal);
    println!("  right_internal (c||d): {:?}", right_internal);
    println!("  root: {:?}", root);

    // Now let's see what our tree produces
    let data = vec![
        "a".as_bytes(),
        "b".as_bytes(),
        "c".as_bytes(),
        "d".as_bytes(),
    ];
    let tree = MerkleTree::new(data, Sha256Hasher::new()).unwrap();

    println!("\nTree-generated values:");
    println!("  tree root: {:?}", tree.root());
    println!("  tree leaf 0: {:?}", tree.get_leaf(0).unwrap());
    println!("  tree leaf 1: {:?}", tree.get_leaf(1).unwrap());
    println!("  tree leaf 2: {:?}", tree.get_leaf(2).unwrap());
    println!("  tree leaf 3: {:?}", tree.get_leaf(3).unwrap());

    // Check if they match
    println!("\nComparisons:");
    println!("  Root matches: {}", root == tree.root());
    println!("  Leaf 0 matches: {}", leaf_a == tree.get_leaf(0).unwrap());

    // Test proof for leaf 0 (should need: leaf_b, right_internal)
    let proof = tree.generate_proof(0).unwrap();
    println!("\nProof for leaf 0:");
    println!("  Steps: {}", proof.len());
    for (i, step) in proof.steps.iter().enumerate() {
        println!("    Step {}: {:?} hash {:?}", i, step.direction, step.hash);
    }

    // Manual verification
    println!("\nManual verification for leaf 0:");
    let mut current = leaf_a.clone();
    println!("  Start with leaf_a: {:?}", current);

    // Step 1: Should combine with leaf_b to get left_internal
    if proof.steps.len() > 0 {
        let step1_expected = leaf_b.clone();
        let step1_actual = proof.steps[0].hash.clone();
        println!("  Step 1 - Expected sibling (leaf_b): {:?}", step1_expected);
        println!("  Step 1 - Actual sibling: {:?}", step1_actual);
        println!("  Step 1 - Match: {}", step1_expected == step1_actual);
        println!("  Step 1 - Direction: {:?}", proof.steps[0].direction);

        current = match proof.steps[0].direction {
            merkle_tree::ProofDirection::Left => hasher.hash_pair(&step1_actual, &current),
            merkle_tree::ProofDirection::Right => hasher.hash_pair(&current, &step1_actual),
        };
        println!("  After step 1: {:?}", current);
        println!("  Should be left_internal: {:?}", left_internal);
        println!("  Match: {}", current == left_internal);
    }

    // Step 2: Should combine with right_internal to get root
    if proof.steps.len() > 1 {
        let step2_expected = right_internal.clone();
        let step2_actual = proof.steps[1].hash.clone();
        println!(
            "  Step 2 - Expected sibling (right_internal): {:?}",
            step2_expected
        );
        println!("  Step 2 - Actual sibling: {:?}", step2_actual);
        println!("  Step 2 - Match: {}", step2_expected == step2_actual);
        println!("  Step 2 - Direction: {:?}", proof.steps[1].direction);

        current = match proof.steps[1].direction {
            merkle_tree::ProofDirection::Left => hasher.hash_pair(&step2_actual, &current),
            merkle_tree::ProofDirection::Right => hasher.hash_pair(&current, &step2_actual),
        };
        println!("  After step 2: {:?}", current);
        println!("  Should be root: {:?}", root);
        println!("  Match: {}", current == root);
    }
}
