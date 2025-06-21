/// Polkadot Trie Proof Library
/// ==========================
///
/// This library provides comprehensive support for Polkadot trie proof verification
/// using SCALE encoding and Blake2b hashing, optimized for zero-knowledge circuits.
///
/// Core Modules:
/// - scale: Complete SCALE codec implementation (all 4 compact modes)
/// - blake2b: Blake2b hashing functions for Polkadot
/// - polkadot_const: Polkadot-specific constants and configuration
/// - polkadot_trie_proof: Single trie proof verification with SCALE node parsing
/// - polkadot_multi_proof: Multi-proof batch verification with shared node optimization
///
/// Utility Modules:
/// - utils: Helper functions for byte manipulation and conversions
/// - utils_test: Test utilities

// === Core Polkadot Modules ===
pub mod scale; // Complete SCALE codec implementation (all 4 modes + circuit optimization)
pub mod blake2b; // Blake2b hashing functions for Polkadot
pub mod polkadot_const; // Polkadot-specific constants and configuration

// === Proof Verification Modules ===
pub mod polkadot_trie_proof; // Enhanced single trie proof verification with SCALE parsing
pub mod polkadot_multi_proof; // Multi-proof batch verification with shared node deduplication

// === Utility Modules ===
mod utils; // Helper functions for byte operations
mod utils_test; // Utility tests
