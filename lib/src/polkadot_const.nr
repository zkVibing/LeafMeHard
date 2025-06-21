/// Polkadot-specific constants for trie proof verification
/// This module contains constants specifically for Polkadot trie structure

/// Storage key constants - variable length keys
pub global MAX_KEY_LENGTH: u32 = 1024; // Maximum storage key length in Polkadot (variable length up to 1024 bytes)

/// Hash constants - fixed length hash values
pub global HASH_LENGTH: u32 = 32; // Blake2b hash output length (roots, node hashes, etc.)
