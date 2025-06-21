// Blake2b hash function implementation
// This module provides Blake2b hashing functionality for Polkadot trie verification

/// Blake2b hash with 256-bit output (32 bytes)
/// This is the standard hash function used in Polkadot Tries
///
/// # Arguments
/// * `input` - Input data to hash
///
/// # Returns
/// 32-byte Blake2b hash
pub fn blake2b<let N: u32>(input: [u8; N]) -> [u8; 32] {
    std::hash::blake2b(input)
}
