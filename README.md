# Noir Trie Proofs

A Noir implementation of Ethereum Merkle-Patricia trie proof verification.

## Storage Proof Verifier

This project implements a storage proof verifier for Ethereum's Merkle-Patricia trie in Noir. It allows for efficient verification of storage proofs within zero-knowledge circuits.

### Features
- Verify storage proofs from Ethereum's state trie
- Support for RLP decoding in Noir
- Efficient implementation optimized for ZK circuits
- Test suite with various proof depths

### Structure
- `lib/`: Core library implementation
- `tests/`: Test cases including depth-8 proofs
- `minimal_verifier/`: Minimal implementation for testing
- `aztec-starter/`: Aztec network deployment configuration

## Development

### Prerequisites
- Noir (>=0.87.9)
- Aztec CLI tools
- Node.js and npm (for testing)

### Setup
1. Install dependencies
2. Compile contracts
3. Run tests

## Testing
```bash
nargo test
```

## License
MIT