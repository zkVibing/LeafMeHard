use dep::trie::polkadot_multi_proof::verify_multi_proof;
use dep::trie::polkadot_const::{MAX_KEY_LENGTH, MAX_PROOF_SIZE};

fn main(
    state_root: pub [u8; 32],
    compact_proof: [u8; MAX_PROOF_SIZE],
    keys: [[u8; MAX_KEY_LENGTH]; 4],
    key_lengths: [u32; 4],
    item_count: u32
) {
    // Verify key lengths are within bounds and check key/value data
    for i in 0..4 {
        if i < item_count {
            assert(key_lengths[i] <= MAX_KEY_LENGTH);

            // Verify keys and values have expected data
            if key_lengths[i] > 0 {
                assert(keys[i][0] != 0); // First byte should be non-zero for valid keys
            }
        }
    }

    // Verify that we can verify a trie multiproof against the given state root
    let result = verify_multi_proof(state_root, compact_proof);
    assert(result == true);
}
