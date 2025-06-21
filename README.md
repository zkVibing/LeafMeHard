# noir-trie-proofs

## Description

This repository contains Noir primitives necessary for Polkadot storage proof verification.

## Polkadot Trie Proof Verification

### Changes compared to Ethereum proofs

This implementation has been updated to support **variable-length storage keys** in Polkadot

1. **Blake2b Integration:**
   - Proper Blake2b hashing for Polkadot compatibility
   - Comprehensive test suite for different key patterns
   - Deterministic hash verification

2. **SCALE Codec Support:**
   - Compact integer encoding/decoding
   - Variable-length data handling
   - Nibble conversion for trie traversal

3. **Variable-Length Storage Keys:**
   - Storage keys can now be any length up to 1024 bytes
   - Keys are scale encoded

4. **Compact multi-proof support**
   - Support for compact multi-proofs, reducing proof size and improving efficiency

## Rust component

### TODO

## Testing

To run the unit tests, you can run `nargo test` in the project root.

## Benchmarks

### TODO
