// // Merkle Tree Inclusion Proof Verification in Noir
use trees::types::{MT_Creator, Modifier, MembershipProver, Calculator};
use trees::merkle::MerkleTree;
use std::hash::poseidon2::Poseidon2::hash;
//use dep::std::debug::print;

fn hasher(leaves: [Field; 2]) -> Field {
    hash(leaves, 2)
}

fn main(entry: Field, index: Field, paths: [Field; 16]) {
    let mut mt = MerkleTree::new(hasher);
    let root = mt.calculate_root(entry, index, paths);

    //print("hello");
    //print("root is: ");
    //print(root);

    // add at index 0
    mt.add(entry, index, paths);



    // prove it is in the tree (kinda redundant isn't it?)
    mt.membership(entry, index, paths);
}


#[test]
fn test_merkle_inclusion() {
     // Example: tree of depth 16 (65536 leaves)

     let leaf = 1;
     let proof = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; //root = 0x03a65988b55f946ea7c6b9e8983b6652dd6f64b749a7e2807e5a8861a0127c8f];
     let index = 1; 

     main(leaf, index, proof);
}
