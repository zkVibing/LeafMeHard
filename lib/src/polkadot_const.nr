/// Polkadot-specific constants for trie proof verification
/// This module contains constants specifically for Polkadot trie structure

/// Storage key constants - variable length keys
// TODO: do we have larger keys?
pub global MAX_KEY_LENGTH: u32 = 1024; // Maximum storage key length in Polkadot

/// Hash constants - fixed length hash values
pub global HASH_LENGTH: u32 = 32; // Blake2b hash output length (roots, node hashes, etc.)

/// Proof size constants - maximum size for compact proof data
// TODO: support up to 5mb
pub global MAX_PROOF_SIZE: u32 = 16384; // Maximum compact proof size (16KB to handle real-world proofs)
