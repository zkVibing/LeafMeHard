/// Polkadot Trie Proof Library
/// ==========================
///
/// This library provides comprehensive support for Polkadot trie proof verification
/// using SCALE encoding and Blake2b hashing, optimized for zero-knowledge circuits.

pub mod scale; // Complete SCALE codec implementation (all 4 modes + circuit optimization)
pub mod blake2b; // Blake2b hashing functions for Polkadot
pub mod polkadot_const; // Polkadot-specific constants and configuration
pub mod polkadot_multi_proof; // Multi-proof batch verification with shared node deduplication
