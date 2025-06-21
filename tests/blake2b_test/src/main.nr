use dep::trie::blake2b::blake2b;

fn main() {
    // Run all test functions
    test_blake2b_basic();
    test_blake2b_deterministic();
    test_blake2b_different_inputs();
    std::println("All Blake2b tests passed!");
}

#[test]
fn test_blake2b_basic() {
    // Test blake2b with a simple input
    let test_input = [0x61, 0x62, 0x63]; // "abc"
    let hash_result = blake2b(test_input);

    // Verify the hash is not all zeros (basic sanity check)
    let mut is_nonzero = false;
    for i in 0..32 {
        if hash_result[i] != 0 {
            is_nonzero = true;
        }
    }
    assert(is_nonzero);
}

#[test]
fn test_blake2b_deterministic() {
    // Test deterministic behavior - same input should produce same output
    let test_input = [0x61, 0x62, 0x63]; // "abc"
    let hash_result1 = blake2b(test_input);
    let hash_result2 = blake2b(test_input);
    assert(hash_result1 == hash_result2);
}

#[test]
fn test_blake2b_different_inputs() {
    // Test with different inputs produce different outputs
    let input1 = [0x61, 0x62, 0x63]; // "abc"
    let input2 = [0x64, 0x65, 0x66]; // "def"

    let hash1 = blake2b(input1);
    let hash2 = blake2b(input2);

    // Hashes should be different
    let mut are_different = false;
    for i in 0..32 {
        if hash1[i] != hash2[i] {
            are_different = true;
        }
    }
    assert(are_different);
}

#[test]
fn test_blake2b_storage_key() {
    // Test with 32-byte input (typical storage key)
    let key_input = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
    ];
    let key_hash = blake2b(key_input);

    // Verify the hash is not all zeros
    let mut is_nonzero = false;
    for i in 0..32 {
        if key_hash[i] != 0 {
            is_nonzero = true;
        }
    }
    assert(is_nonzero);
}
