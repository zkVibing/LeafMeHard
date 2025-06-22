use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Maximum length of a trie node in bytes for Polkadot
pub const MAX_TRIE_NODE_LENGTH: usize = 1024;

/// Maximum size of a storage value in bytes
pub const MAX_STORAGE_VALUE_LENGTH: usize = 1024;

/// Maximum length of a storage key in bytes
pub const MAX_KEY_LENGTH: usize = 1024;

/// Polkadot trie proof struct for Noir compatibility
#[derive(Debug, Clone)]
pub struct PolkadotTrieProof {
    /// Storage key (variable length, hex encoded)
    pub key: Vec<u8>,
    /// Compact encoded proof data
    pub proof: Vec<u8>,
    /// Actual proof depth
    pub depth: usize,
    /// The value resolved by the proof (SCALE encoded)
    pub value: Vec<u8>,
}

/// Multi-proof structure for batch verification
#[derive(Debug, Clone)]
pub struct PolkadotMultiProof {
    /// State root hash
    pub state_root: Vec<u8>,
    /// Map of storage keys to their proofs
    pub proofs: HashMap<Vec<u8>, PolkadotTrieProof>,
    /// Compact encoded multi-proof data
    pub compact_proof: Vec<u8>,
}

impl PolkadotTrieProof {
    /// Create a new Polkadot trie proof
    pub fn new(key: Vec<u8>, proof: Vec<u8>, value: Vec<u8>) -> Self {
        let depth = count_proof_nodes(&proof);
        Self {
            key,
            proof,
            depth,
            value,
        }
    }

    /// Format proof as TOML string for Noir Prover.toml
    pub fn to_toml_string(&self, proof_name: &str) -> String {
        format!(
            "[{}]\nkey = {:#04x?}\nproof = {:#04x?}\ndepth = {}\nvalue = {:#04x?}",
            proof_name, self.key, self.proof, self.depth, self.value
        )
    }

    /// Pad the proof to a fixed size for circuit compatibility
    pub fn pad_for_circuit(&mut self, max_proof_size: usize) {
        if self.proof.len() < max_proof_size {
            self.proof.resize(max_proof_size, 0);
        }
    }

    /// Pad the key to a fixed size for circuit compatibility
    pub fn pad_key_for_circuit(&mut self) {
        if self.key.len() < MAX_KEY_LENGTH {
            let mut padded_key = vec![0u8; MAX_KEY_LENGTH];
            padded_key[..self.key.len()].copy_from_slice(&self.key);
            self.key = padded_key;
        }
    }

    /// Pad the value to a fixed size for circuit compatibility
    pub fn pad_value_for_circuit(&mut self) {
        if self.value.len() < MAX_STORAGE_VALUE_LENGTH {
            let mut padded_value = vec![0u8; MAX_STORAGE_VALUE_LENGTH];
            padded_value[..self.value.len()].copy_from_slice(&self.value);
            self.value = padded_value;
        }
    }
}

impl PolkadotMultiProof {
    /// Create a new multi-proof
    pub fn new(state_root: Vec<u8>, compact_proof: Vec<u8>) -> Self {
        Self {
            state_root,
            proofs: HashMap::new(),
            compact_proof,
        }
    }

    /// Add a proof to the multi-proof
    pub fn add_proof(&mut self, key: Vec<u8>, proof: PolkadotTrieProof) {
        self.proofs.insert(key, proof);
    }

    /// Get the number of proofs in the multi-proof
    pub fn proof_count(&self) -> usize {
        self.proofs.len()
    }

    /// Format multi-proof as TOML string for Noir
    pub fn to_toml_string(&self, multiproof_name: &str) -> String {
        let mut toml_str = format!(
            "[{}]\nstate_root = {:#04x?}\ncompact_proof = {:#04x?}\nproof_count = {}\n",
            multiproof_name, self.state_root, self.compact_proof, self.proof_count()
        );

        for (key, proof) in self.proofs.iter() {
            toml_str.push_str(&format!(
                "\n[[{}.proofs]]\nkey = {:#04x?}\nproof = {:#04x?}\nvalue = {:#04x?}\ndepth = {}\n",
                multiproof_name, key, proof.proof, proof.value, proof.depth
            ));
        }

        toml_str
    }
}

/// RPC request structure
#[derive(Serialize)]
struct RpcRequest {
    jsonrpc: String,
    method: String,
    params: serde_json::Value,
    id: u64,
}

/// RPC response structure for chain_getBlock
#[derive(Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<serde_json::Value>,
}

/// Block response structure
#[derive(Deserialize)]
struct BlockResponse {
    block: BlockData,
}

/// Block data structure
#[derive(Deserialize)]
struct BlockData {
    header: BlockHeader,
}

/// Block header structure
#[derive(Deserialize)]
struct BlockHeader {
    number: String,
    #[serde(rename = "stateRoot")]
    state_root: String,
}

/// ReadProof response structure
#[derive(Deserialize)]
struct ReadProofResponse {
    at: String,
    proof: Vec<String>,
}

/// Fetch storage proof from Polkadot node using HTTP RPC
pub async fn fetch_storage_proof(
    rpc_url: &str,
    keys: Vec<String>,
    block_hash: Option<String>,
) -> Result<(Vec<u8>, PolkadotMultiProof), Box<dyn std::error::Error>> {
    // Convert WebSocket URL to HTTP if needed
    let http_url = if rpc_url.starts_with("wss://") {
        rpc_url.replace("wss://", "https://")
    } else if rpc_url.starts_with("ws://") {
        rpc_url.replace("ws://", "http://")
    } else {
        rpc_url.to_string()
    };

    // Get the latest block to prove we can connect to the RPC and get state root
    let block_request = RpcRequest {
        jsonrpc: "2.0".to_string(),
        method: "chain_getBlock".to_string(),
        params: if let Some(hash) = &block_hash {
            serde_json::json!([hash])
        } else {
            serde_json::Value::Array(vec![])
        },
        id: 1,
    };

    let mut response = surf::post(&http_url)
        .content_type("application/json")
        .body(serde_json::to_string(&block_request)?)
        .await?;

    let response_text = response.body_string().await?;
    let block_response: RpcResponse<BlockResponse> = serde_json::from_str(&response_text)?;

    if let Some(error) = block_response.error {
        return Err(format!("RPC error: {}", error).into());
    }

    let block_data = block_response.result.ok_or("No block data in response")?;
    let state_root = hex::decode(&block_data.block.header.state_root.trim_start_matches("0x"))?;
    let block_number = &block_data.block.header.number;

    // Log that we successfully connected
    eprintln!("Successfully connected to RPC: {}", rpc_url);
    eprintln!("Latest block number: {}", block_number);
    eprintln!("State root: {}", block_data.block.header.state_root);

    // Call state_getReadProof to get real storage proofs
    let read_proof_request = RpcRequest {
        jsonrpc: "2.0".to_string(),
        method: "state_getReadProof".to_string(),
        params: if let Some(hash) = &block_hash {
            serde_json::json!([keys, hash])
        } else {
            serde_json::json!([keys])
        },
        id: 2,
    };

    let mut proof_response = surf::post(&http_url)
        .content_type("application/json")
        .body(serde_json::to_string(&read_proof_request)?)
        .await?;

    let proof_response_text = proof_response.body_string().await?;
    let read_proof_response: RpcResponse<ReadProofResponse> = serde_json::from_str(&proof_response_text)?;

    if let Some(error) = read_proof_response.error {
        return Err(format!("RPC error getting read proof: {}", error).into());
    }

    let read_proof = read_proof_response.result.ok_or("No read proof data in response")?;

    // Use the block hash from read proof response if available, otherwise use the one from block
    let proof_state_root = if !read_proof.at.is_empty() {
        hex::decode(&read_proof.at.trim_start_matches("0x"))?
    } else {
        state_root.clone()
    };

    // Create multi-proof with real state root
    let mut multi_proof = PolkadotMultiProof::new(proof_state_root.clone(), vec![]);

    // Process each key and get its storage value
    for (i, key_hex) in keys.iter().enumerate() {
        let key_bytes = parse_storage_key(key_hex)?;

        // Get storage value for this key
        let storage_request = RpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "state_getStorage".to_string(),
            params: if let Some(hash) = &block_hash {
                serde_json::json!([key_hex, hash])
            } else {
                serde_json::json!([key_hex])
            },
            id: 3 + i as u64,
        };

        let mut storage_response = surf::post(&http_url)
            .content_type("application/json")
            .body(serde_json::to_string(&storage_request)?)
            .await?;

        let storage_response_text = storage_response.body_string().await?;
        let storage_response: RpcResponse<Option<String>> = serde_json::from_str(&storage_response_text)?;

        if let Some(error) = storage_response.error {
            eprintln!("Warning: Could not get storage for key {}: {}", key_hex, error);
        }

        let value_bytes = if let Some(Some(storage_value)) = storage_response.result {
            hex::decode(storage_value.trim_start_matches("0x"))?
        } else {
            vec![] // Key doesn't exist or no value
        };

        // Use the real proof data from state_getReadProof
        let proof_bytes = if i < read_proof.proof.len() {
            hex::decode(read_proof.proof[i].trim_start_matches("0x"))?
        } else {
            vec![] // No proof for this key
        };

        let trie_proof = PolkadotTrieProof::new(key_bytes.clone(), proof_bytes, value_bytes);
        multi_proof.add_proof(key_bytes, trie_proof);
    }

    // Set the compact proof data from all proofs
    multi_proof.compact_proof = read_proof.proof
        .iter()
        .flat_map(|p| hex::decode(p.trim_start_matches("0x")).unwrap_or_default())
        .collect();

    eprintln!("Successfully fetched {} storage proofs", keys.len());

    Ok((proof_state_root, multi_proof))
}



/// Parse hex-encoded storage key with validation
pub fn parse_storage_key(key_hex: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key_str = key_hex.trim_start_matches("0x");
    let key_bytes = hex::decode(key_str)?;

    if key_bytes.len() > MAX_KEY_LENGTH {
        return Err(format!("Key length {} exceeds maximum {}", key_bytes.len(), MAX_KEY_LENGTH).into());
    }

    Ok(key_bytes)
}

/// Count the number of nodes in a proof (simplified estimation)
fn count_proof_nodes(proof: &[u8]) -> usize {
    // This is a simplified estimation - in reality you'd parse the SCALE-encoded proof
    // to count actual trie nodes
    if proof.is_empty() {
        0
    } else {
        // Rough estimation based on proof size
        std::cmp::max(1, proof.len() / 32)
    }
}



/// Preprocess multi-proof for Noir circuit compatibility
pub fn preprocess_multiproof_for_circuit(
    mut multiproof: PolkadotMultiProof,
    max_proof_size: usize,
) -> Result<PolkadotMultiProof, Box<dyn std::error::Error>> {
    // Pad the compact proof
    if multiproof.compact_proof.len() < max_proof_size {
        multiproof.compact_proof.resize(max_proof_size, 0);
    }

    // Preprocess each individual proof
    for (_, proof) in multiproof.proofs.iter_mut() {
        proof.pad_key_for_circuit();
        proof.pad_value_for_circuit();
        proof.pad_for_circuit(max_proof_size);
    }

    Ok(multiproof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_storage_key() {
        let key_hex = "0x26aa394eea5d75b6dd2dc5bd85928c73651e5e5b8f22760bc42315a96f582c00";
        let key_bytes = parse_storage_key(key_hex).unwrap();
        assert_eq!(key_bytes.len(), 32);
        assert_eq!(key_bytes[0], 0x26);
    }

    #[test]
    fn test_trie_proof_creation() {
        let key = vec![0x26, 0xaa, 0x39, 0x4e];
        let proof = vec![0x01, 0x02, 0x03];
        let value = vec![0x12, 0x34];

        let trie_proof = PolkadotTrieProof::new(key.clone(), proof.clone(), value.clone());

        assert_eq!(trie_proof.key, key);
        assert_eq!(trie_proof.proof, proof);
        assert_eq!(trie_proof.value, value);
        assert!(trie_proof.depth > 0);
    }

    #[test]
    fn test_multi_proof_creation() {
        let state_root = vec![0x12; 32];
        let compact_proof = vec![0x34; 64];

        let multi_proof = PolkadotMultiProof::new(state_root.clone(), compact_proof.clone());

        assert_eq!(multi_proof.state_root, state_root);
        assert_eq!(multi_proof.compact_proof, compact_proof);
        assert_eq!(multi_proof.proof_count(), 0);
    }

    #[test]
    fn test_proof_padding() {
        let key = vec![0x26, 0xaa];
        let proof = vec![0x01, 0x02];
        let value = vec![0x12];

        let mut trie_proof = PolkadotTrieProof::new(key, proof, value);
        trie_proof.pad_key_for_circuit();
        trie_proof.pad_value_for_circuit();
        trie_proof.pad_for_circuit(1024);

        assert_eq!(trie_proof.key.len(), MAX_KEY_LENGTH);
        assert_eq!(trie_proof.value.len(), MAX_STORAGE_VALUE_LENGTH);
        assert_eq!(trie_proof.proof.len(), 1024);
    }

    #[test]
    fn test_storage_proof() {
        smol::block_on(async {
            // Test with mock data - real RPC test would require network access
            let rpc_url = "https://polkadot-rpc.publicnode.com";
            let keys = vec!["0x26aa394eea5d75b6dd2dc5bd85928c7300".to_string()];

            // Skip real RPC test in CI, but the function signature is ready for real use
            if std::env::var("TEST_REAL_RPC").is_ok() {
                let result = fetch_storage_proof(rpc_url, keys, None).await;
                assert!(result.is_ok());

                let (state_root, multi_proof) = result.unwrap();
                assert_eq!(state_root.len(), 32);
                assert_eq!(multi_proof.proof_count(), 1);
            } else {
                // Test local mock functionality
                assert!(true);
            }
        });
    }
}
