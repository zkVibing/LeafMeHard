# noir-trie-proofs

## Description

This repository contains Noir primitives necessary for Polkadot storage proof verification.

## Polkadot Trie Proof Verification

### Changes compared to Ethereum proofs

This implementation has been updated to support **variable-length storage keys** in Polkadot

1. **Blake2b Integration:**
   - blake2b hash function is used in Polkadot/Kusama ecosystem

2. **SCALE Codec Support:**
   - Custom compact codec used in Polkadot/Kusama ecosystem

3. **Variable-Length Storage Keys:**
   - Storage keys can now be any length up to 1024 bytes

4. **Compact multi-proof support**
   - Support for compact multi-proofs, reducing proof size and improving efficiency

### Noir compiler

For Noir setup refer to https://noir-lang.org/docs/getting_started/quick_start.

We are currently using a fork of the Noir compiler that supports blake2b instruction.

```
noirup --repo ordian/noir --branch blake2b
```

## Rust component

We provide a Rust library and binary that can be used to download live Polkadot storage multiproofs.

`create_real_prover.py` script makes use of this binary to generate inputs (Prover.toml) for a trie proof.

## Testing

To run the unit tests, you can run `nargo test` in the project root.

To run trie verification,

```bash
# Compile and execute, generate the witness
nargo execute --package trie_test
# Generate proof using Barretenberg backend
bb prove -b ./target/trie_test.json -w ./target/trie_test.gz -o ./target
bb write_vk -b ./target/trie_test.json -o ./target
# Verify the proof
bb verify -k ./target/vk -p ./target/proof -i ./target/public_inputs
```

### Use-cases

- Kusama to Aztec bridge
- Parachain bridges to Ethereum/Aztec/L2s
- State proof compression on Polkadot/Kusama

## Benchmarks

```bash
hyperfine 'nargo compile --package trie_test'
```
