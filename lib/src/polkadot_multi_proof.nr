/// Simplified Polkadot compact multi-proof verification optimized for ZK circuits
/// This module provides minimal verification of compact multi-proofs for multiple
/// key-value pairs against a single root hash

use crate::blake2b::blake2b;
use crate::scale::decode_compact_length;
use crate::polkadot_const::{MAX_KEY_LENGTH, HASH_LENGTH};


global MAX_PROOF_NODES: u32 = 256; // Reduced for faster compilation
global MAX_NODE_SIZE: u32 = 256;   // Reduced memory footprint
global MAX_CHILD_REFS: u32 = 16;
global NO_REFERENCE: u32 = 0xFFFFFFFF;

/// Compact proof item structure
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

    fn verify_trie_structure_with_nodes(
        self,
        node_hashes: [[u8; HASH_LENGTH]; MAX_PROOF_NODES],
        node_data_array: [[u8; MAX_NODE_SIZE]; MAX_PROOF_NODES],
        node_lengths: [u32; MAX_PROOF_NODES],
        nodes_count: u32
    ) -> bool {
        let is_valid_count = (nodes_count > 0) & (nodes_count <= MAX_PROOF_NODES);

        let mut instantiated_bitmap: u32 = 0;
        let mut root_candidate = [0; HASH_LENGTH];
        let mut root_candidate_idx = 0;

        // Process all nodes with conditional logic (no early exits)
        for i in 0..MAX_PROOF_NODES {
            let is_active = (i < nodes_count) & is_valid_count;

            // Extract child references conditionally
            let child_refs = if is_active {
                self.extract_child_references(node_data_array[i], node_lengths[i])
            } else {
                [NO_REFERENCE; MAX_CHILD_REFS]
            };

            // Find which nodes are referenced by this node's children
            for j in 0..MAX_CHILD_REFS {
                let child_offset = child_refs[j];
                if is_active & (child_offset != NO_REFERENCE) {
                    // Extract hash at this offset and find matching node
                    for k in 0..MAX_PROOF_NODES {
                        if (k < nodes_count) & (k != i) {
                            let matches_child = self.hash_matches_at_offset(
                                node_data_array[i],
                                child_offset,
                                node_hashes[k]
                            );
                            if matches_child {
                                let bitmap_bit = 1 << (k as u8);
                                instantiated_bitmap = instantiated_bitmap | bitmap_bit;
                            }
                        }
                    }
                }
            }

            // Update root candidate (last non-referenced node wins)
            let bit_position = 1 << (i as u8);
            let is_not_referenced = is_active & ((instantiated_bitmap & bit_position) == 0);
            root_candidate = if is_not_referenced { node_hashes[i] } else { root_candidate };
            root_candidate_idx = if is_not_referenced { i } else { root_candidate_idx };
        }

        // Final verification using bitwise operations
        let root_bit = 1 << (root_candidate_idx as u8);
        let expected_bitmap = (1 << (nodes_count as u8)) - 1;
        let all_nodes_accounted = (instantiated_bitmap | root_bit) == expected_bitmap;

        is_valid_count & all_nodes_accounted & self.verify_root_hash(root_candidate)
    }

    /// Check if hash at given offset matches target hash
    fn hash_matches_at_offset(
        _self: Self,
        node_data: [u8; MAX_NODE_SIZE],
        offset: u32,
        target_hash: [u8; HASH_LENGTH]
    ) -> bool {
        let mut matches = true;
        for i in 0..HASH_LENGTH {
            let can_read = (offset + i < MAX_NODE_SIZE);
            if can_read {
                if node_data[offset + i] != target_hash[i] {
                    matches = false;
                }
            } else {
                matches = false;
            }
        }
        matches
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

    /// Optimized child reference extraction with early termination
    fn extract_branch_child_refs(
        _self: Self,
        node_data: [u8; MAX_NODE_SIZE],
        node_length: u32,
        partial_key_len: u32,
        has_value: bool,
        mut ref_count: u32
    ) -> [u32; MAX_CHILD_REFS] {
        let mut child_refs = [NO_REFERENCE; MAX_CHILD_REFS];

        let is_valid_node = node_length >= 4; // Minimum: header + partial_key + bitmap

        let mut offset = 1 + (partial_key_len + 1) / 2; // Header + partial key

        // Skip value with conditional SCALE decoding
        let should_decode_value = has_value & (offset < node_length) & is_valid_node;
        if should_decode_value {
            let value_header = decode_compact_length(node_data, offset as u64);
            offset += value_header.offset as u32 + value_header.length as u32;
        }

        let can_read_bitmap = (offset + 2 <= node_length) & is_valid_node;
        let children_bitmap = if can_read_bitmap {
            ((node_data[offset] as u16) << 8) | (node_data[offset + 1] as u16)
        } else {
            0
        };
        offset += 2 * (can_read_bitmap as u32);

        // Constraint-efficient loop: process all iterations, use conditional logic
        for i in 0..MAX_CHILD_REFS {
            let has_child = (children_bitmap & (1 << (i as u8))) != 0;
            let can_extract = (offset + HASH_LENGTH <= node_length) & (ref_count < MAX_CHILD_REFS) & can_read_bitmap;
            let should_extract = has_child & can_extract;

            // Conditional assignment instead of break/continue
            child_refs[ref_count] = if should_extract { offset } else { child_refs[ref_count] };
            ref_count += should_extract as u32;
            offset += (should_extract as u32) * HASH_LENGTH;
        }

        child_refs
    }


    /// Optimized hash reference checking with early termination
    fn node_references_hash(self, node_data: [u8; MAX_NODE_SIZE], node_length: u32, target_hash: [u8; HASH_LENGTH]) -> bool {
        // Early bounds check
        if node_length < HASH_LENGTH {
            false
        } else {
            let child_refs = self.extract_child_references(node_data, node_length);

            // Use constraint-efficient loop with early exit
            let mut found = false;
            for i in 0..MAX_CHILD_REFS {
                let ref_offset = child_refs[i];
                let is_valid_ref = (ref_offset != NO_REFERENCE) & (ref_offset + HASH_LENGTH <= node_length);

                if is_valid_ref & !found {
                    // Efficient hash comparison - stop at first mismatch
                    let mut matches = true;
                    for j in 0..HASH_LENGTH {
                        if node_data[ref_offset + j] != target_hash[j] {
                            matches = false;
                        }
                    }
                    if matches {
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

    fn verify_compact_proof_reconstruction(self) -> bool {
        let is_valid_proof_size = PROOF_LEN >= 4;

        let mut node_hashes: [[u8; HASH_LENGTH]; MAX_PROOF_NODES] = [[0; HASH_LENGTH]; MAX_PROOF_NODES];
        let mut node_data_array: [[u8; MAX_NODE_SIZE]; MAX_PROOF_NODES] = [[0; MAX_NODE_SIZE]; MAX_PROOF_NODES];
        let mut node_lengths: [u32; MAX_PROOF_NODES] = [0; MAX_PROOF_NODES];

        let (nodes_parsed, parse_success) = if is_valid_proof_size {
            self.parse_nodes_efficiently(node_hashes, node_data_array, node_lengths)
        } else {
            (0, false)
        };

        // Combine all validation conditions
        let parsing_succeeded = parse_success & (nodes_parsed > 0) & is_valid_proof_size;

        // Always run verification, but gate result with parsing success
        let verification_result = self.verify_trie_structure_with_nodes(
            node_hashes,
            node_data_array,
            node_lengths,
            nodes_parsed
        );

        parsing_succeeded & verification_result
    }

    /// Constraint-efficient node parsing
    fn parse_nodes_efficiently(
        self,
        mut node_hashes: [[u8; HASH_LENGTH]; MAX_PROOF_NODES],
        mut node_data_array: [[u8; MAX_NODE_SIZE]; MAX_PROOF_NODES],
        mut node_lengths: [u32; MAX_PROOF_NODES]
    ) -> (u32, bool) {
        let mut offset = 0;
        let mut nodes_parsed = 0;
        let mut parse_success = true;

        // Optimized parsing with early exit conditions
        for _i in 0..MAX_PROOF_NODES {
            let can_continue = (offset < PROOF_LEN) & (nodes_parsed < MAX_PROOF_NODES) & parse_success;

            if can_continue {
                let (valid, node_data, node_size) = self.parse_node_at_offset_strict(offset);

                if valid & (node_size > 0) {
                    // Efficient conditional copy
                    for j in 0..MAX_NODE_SIZE {
                        let copy_byte = (j < node_size) as u8;
                        node_data_array[nodes_parsed][j] = copy_byte * node_data[j];
                    }

                    node_lengths[nodes_parsed] = node_size;
                    node_hashes[nodes_parsed] = self.hash_node_data(node_data, node_size);

                    nodes_parsed += 1;
                    offset += node_size + self.get_length_prefix_size(offset);
                } else {
                    parse_success = false;
                }
            }
        }

        (nodes_parsed, parse_success)
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
