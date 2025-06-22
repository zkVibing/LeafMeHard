use argh::FromArgs;
use polkanoir::*;

#[derive(FromArgs)]
/// Polkadot storage proof fetcher
struct Cli {
    /// storage keys (hex encoded, comma separated)
    #[argh(option, short = 'k')]
    keys: String,
    /// URL of Polkadot/Substrate node RPC endpoint
    #[argh(option, short = 'r')]
    rpc_url: Option<String>,
    /// block hash to fetch proof from. If not specified, uses latest finalized block
    #[argh(option, short = 'b')]
    block_hash: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    smol::block_on(async_main())
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse arguments
    let cli: Cli = argh::from_env();

    // RPC URL is required for real RPC calls
    let rpc_url = cli.rpc_url.unwrap_or_else(|| "wss://polkadot-rpc.publicnode.com".to_string());

    let keys: Vec<String> = cli.keys.split(',').map(|s| s.trim().to_string()).collect();
    for key in &keys {
        parse_storage_key(key)?;
    }

    // Fetch multi-proof
    let (state_root, multi_proof) = fetch_storage_proof(
        &rpc_url,
        keys,
        cli.block_hash,
    ).await?;

    // Preprocess for circuit compatibility
    let processed_multiproof = preprocess_multiproof_for_circuit(
        multi_proof,
        4096,
    )?;

    // Output TOML format
    println!("storage_root = {:#04x?}\n", state_root);
    println!("{}", processed_multiproof.to_toml_string("storage_proof"));

    Ok(())
}
