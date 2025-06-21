use dep::std::hash::keccak256;

fn main(root: pub [u8; 32], key: [u8; 32], value: [u8; 32], proof: [u8; 1024]) -> pub bool {
    let mut current_hash = root;
    let mut current_key = key;
    let mut current_value = value;
    let mut current_proof = proof;
    
    // Verify the proof
    for i in 0..8 {
        let node_hash = keccak256(current_proof[i * 128..(i + 1) * 128]);
        assert(node_hash == current_hash);
        
        // Extract the next hash and update current values
        current_hash = current_proof[(i + 1) * 128 - 32..(i + 1) * 128];
        current_key = current_key[4..];
    }
    
    // Verify the final value
    current_value == value
} 