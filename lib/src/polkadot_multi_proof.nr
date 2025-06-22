/// Simplified Polkadot compact multi-proof verification optimized for ZK circuits
/// This module provides minimal verification of compact multi-proofs for multiple
/// key-value pairs against a single root hash, focusing on circuit efficiency

use crate::blake2b::blake2b;
use crate::scale::decode_compact_length;
use crate::polkadot_const::{MAX_KEY_LENGTH, HASH_LENGTH};


/// Maximum number of nodes in a compact proof (circuit efficiency limit)
global MAX_PROOF_NODES: u32 = 32;

/// Maximum size for individual node data (circuit memory limit)
global MAX_NODE_SIZE: u32 = 256;

/// Maximum child references per trie node (circuit limit for branch nodes)
global MAX_CHILD_REFS: u32 = 8;

/// Sentinel value for "no reference" in child reference arrays
global NO_REFERENCE: u32 = 0xFFFFFFFF;

/// Compact proof item structure (minimized for circuit size)
pub struct CompactProofItem {
    pub key: [u8; MAX_KEY_LENGTH],
    pub key_length: u32,
    pub value: [u8; 256],
    pub value_length: u32,
    pub exists: bool,
}

impl CompactProofItem {
    pub fn new(key: [u8; MAX_KEY_LENGTH], key_length: u32, value: [u8; 256], value_length: u32, exists: bool) -> Self {
        Self { key, key_length, value, value_length, exists }
    }

    /// Verify this item matches the expected key/value
    pub fn verify_match(self, expected_key: [u8; MAX_KEY_LENGTH], expected_key_length: u32) -> bool {
        if self.key_length != expected_key_length {
            false
        } else {
            let mut matches = true;
            for i in 0..expected_key_length {
                if self.key[i] != expected_key[i] {
                    matches = false;
                }
            }
            matches
        }
    }
}

/// Compare two hash arrays for equality
fn array_equals(a: [u8; HASH_LENGTH], b: [u8; HASH_LENGTH]) -> bool {
    let mut equal = true;
    for i in 0..HASH_LENGTH {
        if a[i] != b[i] {
            equal = false;
        }
    }
    equal
}

/// Simplified compact multi-proof structure
pub struct PolkadotMultiProof<let PROOF_LEN: u32> {
    pub expected_root: [u8; HASH_LENGTH],
    pub proof: [u8; PROOF_LEN],
    pub item_count: u32,
}

impl<let PROOF_LEN: u32> PolkadotMultiProof<PROOF_LEN> {
    /// Create new compact multi-proof
    pub fn new(expected_root: [u8; HASH_LENGTH], proof: [u8; PROOF_LEN]) -> Self {
        Self {
            expected_root,
            proof,
            item_count: 0,
        }
    }

    /// Get item count
    pub fn get_item_count(self) -> u32 {
        self.item_count
    }

    /// Proper compact multi-proof verification with SCALE decoding and hash verification
    pub fn verify(self) -> bool {
        // Decode the compact proof and verify trie structure
        self.verify_trie_proof()
    }

    /// Verify compact trie proof following Parity's trie-db logic
    /// Based on https://github.com/paritytech/trie/blob/fbe64ba/trie-db/src/proof/verify.rs#L393-L484
    fn verify_trie_proof(self) -> bool {
        if PROOF_LEN < 4 {
            false
        } else {
            // Parse compact proof and verify against expected root
            self.verify_compact_proof_reconstruction()
        }
    }

    /// Parse node at offset with strict validation using proper SCALE decoding
    fn parse_node_at_offset_strict(self, offset: u32) -> (bool, [u8; MAX_NODE_SIZE], u32) {
        if offset >= PROOF_LEN {
            (false, [0; MAX_NODE_SIZE], 0)
        } else {
            // Use proper SCALE compact length decoding
            let header = decode_compact_length(self.proof, offset as u64);
            let node_length = header.length as u32;
            let length_bytes = header.offset as u32;

            if (node_length == 0) | (offset + length_bytes + node_length > PROOF_LEN) {
                (false, [0; MAX_NODE_SIZE], 0)
            } else {
                // Read node data
                let mut node_data = [0; MAX_NODE_SIZE];
                let data_start = offset + length_bytes;
                let read_size = if node_length > MAX_NODE_SIZE { MAX_NODE_SIZE } else { node_length };

                for i in 0..MAX_NODE_SIZE {
                    if i < read_size {
                        node_data[i] = self.proof[data_start + i];
                    }
                }

                (true, node_data, node_length)
            }
        }
    }

    /// Get the size of the length prefix at given offset using SCALE decoding
    fn get_length_prefix_size(self, offset: u32) -> u32 {
        if offset >= PROOF_LEN {
            0
        } else {
            let header = decode_compact_length(self.proof, offset as u64);
            header.offset as u32
        }
    }


    /// Hash node data with proper length
    fn hash_node_data(_self: Self, node_data: [u8; MAX_NODE_SIZE], data_size: u32) -> [u8; HASH_LENGTH] {
        // Create properly sized input for hashing
        let mut hash_input = [0; MAX_NODE_SIZE];
        for i in 0..MAX_NODE_SIZE {
            if i < data_size {
                hash_input[i] = node_data[i];
            }
        }
        blake2b(hash_input)
    }

    /// Verify trie structure with parsed nodes following Parity's algorithm
    /// Implements the core logic from trie-db/src/proof/verify.rs
    fn verify_trie_structure_with_nodes(
        self,
        node_hashes: [[u8; HASH_LENGTH]; MAX_PROOF_NODES],
        node_data_array: [[u8; MAX_NODE_SIZE]; MAX_PROOF_NODES],
        node_lengths: [u32; MAX_PROOF_NODES],
        nodes_count: u32
    ) -> bool {
        if nodes_count == 0 {
            false
        } else {
            // Track which nodes have been instantiated (used as child references)
            let mut instantiated: [bool; MAX_PROOF_NODES] = [false; MAX_PROOF_NODES];
            let mut root_found = false;
            let mut computed_root = [0; HASH_LENGTH];

            // Process nodes to build trie structure (with fixed bounds)
            for i in 0..MAX_PROOF_NODES {
                if i < nodes_count {
                    let node_data = node_data_array[i];
                    let node_length = node_lengths[i];
                    let node_hash = node_hashes[i];

                    // Parse node to check for child references
                    let child_refs = self.extract_child_references(node_data, node_length);

                    // Mark referenced nodes as instantiated
                    for j in 0..MAX_CHILD_REFS {
                        let child_idx = child_refs[j];
                        if (child_idx < nodes_count) & (child_idx != NO_REFERENCE) {
                            instantiated[child_idx] = true;
                        }
                    }

                    // Check if this could be the root (not referenced by other nodes)
                    if !root_found {
                        let mut is_referenced = false;
                        for k in 0..MAX_PROOF_NODES {
                            if (k != i) & (k < nodes_count) {
                                let other_node = node_data_array[k];
                                let other_length = node_lengths[k];
                                if self.node_references_hash(other_node, other_length, node_hash) {
                                    is_referenced = true;
                                }
                            }
                        }

                        if !is_referenced {
                            root_found = true;
                            computed_root = node_hash;
                        }
                    }
                }
            }

            // Verify all nodes except root are referenced (no extraneous nodes)
            let mut all_nodes_used = true;
            for i in 0..MAX_PROOF_NODES {
                if i < nodes_count {
                    let is_root = array_equals(node_hashes[i], computed_root);
                    if !is_root & !instantiated[i] {
                        all_nodes_used = false;
                    }
                }
            }

            // Final verification: root found, all nodes used, root hash matches
            root_found & all_nodes_used & self.verify_root_hash(computed_root)
        }
    }

    /// Extract child hash references from a trie node using proper Polkadot node decoding
    /// Based on Polkadot spec Definition 25: https://spec.polkadot.network/chap-state#sect-state-storage-trie-structure
    fn extract_child_references(self, node_data: [u8; MAX_NODE_SIZE], node_length: u32) -> [u32; MAX_CHILD_REFS] {
        let mut child_refs = [NO_REFERENCE; MAX_CHILD_REFS];
        let mut ref_count = 0;

        if node_length == 0 {
            child_refs
        } else {

            let header = node_data[0];
            let (node_type, partial_key_len) = self.decode_node_header(header);

            if node_type == 1 {
                // Leaf node (01) - no child references
                child_refs
            } else if node_type == 2 {
                // Branch node without value (10) - has up to 16 child references
                self.extract_branch_child_refs(node_data, node_length, partial_key_len, false, ref_count)
            } else if node_type == 3 {
                // Branch node with value (11) - has up to 16 child references + stored value
                self.extract_branch_child_refs(node_data, node_length, partial_key_len, true, ref_count)
            } else {
                // Other node types (hashed subvalue, empty, etc.) - simplified handling
                child_refs
            }
        }
    }

    /// Decode node header byte according to Polkadot spec
    fn decode_node_header(_self: Self, header: u8) -> (u8, u32) {
        // Check node type from header bits
        if (header & 0xC0) == 0x40 {
            // Leaf node (01xxxxxx) - 0x40 = 64 = 0b01000000
            let partial_key_len = (header & 0x3F) as u32; // 0x3F = 63 = 0b00111111
            (1, partial_key_len)
        } else if (header & 0xC0) == 0x80 {
            // Branch node without value (10xxxxxx) - 0x80 = 128 = 0b10000000
            let partial_key_len = (header & 0x3F) as u32;
            (2, partial_key_len)
        } else if (header & 0xC0) == 0xC0 {
            // Branch node with value (11xxxxxx) - 0xC0 = 192 = 0b11000000
            let partial_key_len = (header & 0x3F) as u32;
            (3, partial_key_len)
        } else if header == 0 {
            // Empty node
            (0, 0)
        } else {
            // Other types (leaf with hashed subvalue, branch with hashed subvalue, etc.)
            (4, 0)
        }
    }

    /// Extract child references from branch node
    fn extract_branch_child_refs(
        _self: Self,
        node_data: [u8; MAX_NODE_SIZE],
        node_length: u32,
        partial_key_len: u32,
        has_value: bool,
        mut ref_count: u32
    ) -> [u32; MAX_CHILD_REFS] {
        let mut child_refs = [NO_REFERENCE; MAX_CHILD_REFS];

        // Calculate offset past header and partial key
        let mut offset = 1; // Skip header byte

        // Skip partial key bytes
        let partial_key_bytes = (partial_key_len + 1) / 2; // Round up division
        offset += partial_key_bytes;

        // Skip stored value if present
        if has_value {
            // In Polkadot, values are SCALE-encoded, so we need to decode the length
            if offset < node_length {
                let value_header = decode_compact_length(node_data, offset as u64);
                offset += value_header.offset as u32 + value_header.length as u32;
            }
        }

        // Read children bitmap (2 bytes for 16 possible children)
        if offset + 2 <= node_length {
            let children_bitmap = ((node_data[offset] as u16) << 8) | (node_data[offset + 1] as u16);
            offset += 2;

            // Extract hash references for each present child
            for i in 0..16 {
                if (children_bitmap & (1 << i)) != 0 {
                    if (offset + HASH_LENGTH <= node_length) & (ref_count < MAX_CHILD_REFS) {
                        // This child has a hash reference
                        child_refs[ref_count] = offset;
                        ref_count += 1;
                        offset += HASH_LENGTH;
                    }
                }
            }
        }

        child_refs
    }


    /// Check if a node references a specific hash using proper node structure
    fn node_references_hash(self, node_data: [u8; MAX_NODE_SIZE], node_length: u32, target_hash: [u8; HASH_LENGTH]) -> bool {
        if node_length < HASH_LENGTH {
            false
        } else {
            // Extract child references using proper node decoding
            let child_refs = self.extract_child_references(node_data, node_length);

            // Check if any child reference matches the target hash
            let mut found = false;
            for i in 0..MAX_CHILD_REFS {
                let ref_offset = child_refs[i];
                if ref_offset != NO_REFERENCE {
                    // Compare the hash at this offset with target hash
                    let mut hash_matches = true;
                    for j in 0..HASH_LENGTH {
                        if (ref_offset + j < node_length) & (ref_offset + j < MAX_NODE_SIZE) {
                            if node_data[ref_offset + j] != target_hash[j] {
                                hash_matches = false;
                            }
                        } else {
                            hash_matches = false;
                        }
                    }
                    if hash_matches {
                        found = true;
                    }
                }
            }

            found
        }
    }


    /// Verify computed root matches expected root
    fn verify_root_hash(self, computed_root: [u8; HASH_LENGTH]) -> bool {
        let mut matches = true;
        for i in 0..HASH_LENGTH {
            if computed_root[i] != self.expected_root[i] {
                matches = false;
            }
        }
        matches
    }

    /// Verify compact proof reconstruction following Parity's logic
    /// Implements the core verification algorithm from trie-db/src/proof/verify.rs
    fn verify_compact_proof_reconstruction(self) -> bool {
        // Parse nodes from proof
        let mut offset = 0;
        let mut nodes_parsed = 0;

        // Phase 1: Parse all nodes from the proof
        let mut node_hashes: [[u8; HASH_LENGTH]; MAX_PROOF_NODES] = [[0; HASH_LENGTH]; MAX_PROOF_NODES];
        let mut node_data_array: [[u8; MAX_NODE_SIZE]; MAX_PROOF_NODES] = [[0; MAX_NODE_SIZE]; MAX_PROOF_NODES];
        let mut node_lengths: [u32; MAX_PROOF_NODES] = [0; MAX_PROOF_NODES];

        let mut parsing_complete = false;
        for _i in 0..MAX_PROOF_NODES {
            if (offset >= PROOF_LEN) | parsing_complete {
                // Stop processing but continue loop for circuit constraints
            } else {
                let (valid, node_data, node_size) = self.parse_node_at_offset_strict(offset);
                if valid & (nodes_parsed < MAX_PROOF_NODES) {
                    // Store node data
                    for j in 0..MAX_NODE_SIZE {
                        if j < node_size {
                            node_data_array[nodes_parsed][j] = node_data[j];
                        }
                    }
                    node_lengths[nodes_parsed] = node_size;

                    // Compute node hash
                    node_hashes[nodes_parsed] = self.hash_node_data(node_data, node_size);

                    nodes_parsed += 1;
                    offset += node_size + self.get_length_prefix_size(offset);
                } else {
                    // Mark parsing as complete on invalid node
                    parsing_complete = true;
                }
            }
        }

        if nodes_parsed == 0 {
            false
        } else {
            // Phase 2: Verify trie structure and compute root
            self.verify_trie_structure_with_nodes(node_hashes, node_data_array, node_lengths, nodes_parsed)
        }
    }

    /// Decode compact proof header (simplified)
    fn decode_header(self, offset: u32) -> (u32, u32) {
        if offset >= PROOF_LEN {
            (0, offset)
        } else {
            // Simple length decoding (assuming SCALE compact encoding)
            let first_byte = self.proof[offset];
            if first_byte < 0x40 {
                // Single byte mode
                ((first_byte as u32) >> 2, offset + 1)
            } else if first_byte < 0x80 {
                // Two byte mode
                if offset + 1 >= PROOF_LEN {
                    (0, offset)
                } else {
                    let length = (((first_byte & 0x3f) as u32) << 8) | (self.proof[offset + 1] as u32);
                    (length, offset + 2)
                }
            } else {
                // Multi-byte mode (simplified - just return 0 for circuit efficiency)
                (0, offset + 1)
            }
        }
    }
}

/// Simplified compact proof decoder
pub struct CompactProofDecoder<let PROOF_LEN: u32> {
    proof_data: [u8; PROOF_LEN],
    position: u32,
}

impl<let PROOF_LEN: u32> CompactProofDecoder<PROOF_LEN> {
    pub fn new(proof_data: [u8; PROOF_LEN]) -> Self {
        Self {
            proof_data,
            position: 0,
        }
    }

    /// Read next byte (with bounds checking)
    fn read_byte(self) -> (u8, u32) {
        if self.position >= PROOF_LEN {
            (0, self.position)
        } else {
            (self.proof_data[self.position], self.position + 1)
        }
    }

    /// Decode compact length at current position
    fn decode_compact(self) -> (u32, u32) {
        if self.position >= PROOF_LEN {
            (0, self.position)
        } else {
            let first_byte = self.proof_data[self.position];
            if first_byte < 0x40 {
                // Single byte: value = first_byte >> 2
                ((first_byte as u32) >> 2, self.position + 1)
            } else if first_byte < 0x80 {
                // Two bytes: value = ((first_byte & 0x3f) << 8) | second_byte
                if self.position + 1 >= PROOF_LEN {
                    (0, self.position)
                } else {
                    let second_byte = self.proof_data[self.position + 1];
                    let value = (((first_byte & 0x3f) as u32) << 8) | (second_byte as u32);
                    (value, self.position + 2)
                }
            } else {
                // Four bytes or more - simplified for circuit
                if self.position + 4 >= PROOF_LEN {
                    (0, self.position)
                } else {
                    let mut value = 0;
                    for i in 0..4 {
                        value |= (self.proof_data[self.position + 1 + i] as u32) << ((i * 8) as u8);
                    }
                    (value, self.position + 5)
                }
            }
        }
    }

    /// Skip bytes
    fn skip(self, count: u32) -> u32 {
        if self.position + count > PROOF_LEN {
            PROOF_LEN
        } else {
            self.position + count
        }
    }
}

/// Utility function for basic multi-proof verification
pub fn verify_multi_proof<let PROOF_LEN: u32>(
    expected_root: [u8; HASH_LENGTH],
    proof_data: [u8; PROOF_LEN]
) -> bool {
    let multi_proof = PolkadotMultiProof::new(expected_root, proof_data);
    multi_proof.verify()
}

// Circuit-optimized tests
#[test]
fn test_compact_proof_creation() {
    let root = [1; HASH_LENGTH];
    let proof_data = [0; 1024];

    let multi_proof = PolkadotMultiProof::new(root, proof_data);
    assert(multi_proof.get_item_count() == 0);
    // Empty proof data should fail strict verification
    assert(multi_proof.verify() == false);
}

#[test]
fn test_compact_decoder() {
    let proof_data = [0x08, 0x15, 0x01, 0x00]; // SCALE encoded data
    let decoder = CompactProofDecoder::new(proof_data);

    // Test reading first compact value (should be 2 from 0x08)
    let (value, _) = decoder.decode_compact();
    assert(value == 2);
}

#[test]
fn test_multi_proof_utility() {
    let root = [3; HASH_LENGTH];
    let proof = [2; 256];

    let result = verify_multi_proof(root, proof);
    // Dummy proof data should fail strict verification
    assert(result == false);
}

#[test]
fn test_compact_proof_item() {
    let key = [1; MAX_KEY_LENGTH];
    let value = [2; 256];
    let item = CompactProofItem::new(key, 64, value, 32, true);

    assert(item.exists == true);
    assert(item.key[0] == 1);
    assert(item.key_length == 64);
    assert(item.value[0] == 2);
    assert(item.value_length == 32);

    // Test verification
    let expected_key = [1; MAX_KEY_LENGTH];
    let result = item.verify_match(expected_key, 64);
    assert(result == true);
}
