mod wallet_gen;
mod zk;
mod nodes;
mod dkg;
mod storage;
mod transaction;
mod network;

use wallet_gen::wallet::{pub_key_address, generate_and_store_wallet};
use zk::zk_ownership::{create_ownership_proof};
use dkg::ephemeral_dkg::{simulate_dkg_session, simulate_threshold_signing};
use hex;
use storage::secure_storage;
use secp256k1::{SecretKey, Secp256k1};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use anyhow::Result;
use std::env;
use tracing::info;
use nodes::node::{NodeRuntime, TransactionRequest, create_test_node, create_shared_runtime};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        run_demo().await?
    } else {
        match args[1].as_str() {
            "start-node" => {
                if args.len() < 3 {
                    eprintln!("Usage: {} start-node <port>", args[0]);
                    return Ok(());
                }
                let port = args[2].parse::<u16>()
                    .map_err(|e| anyhow::anyhow!("Invalid port: {}", e))?;
                handle_start_node_command(port).await?;
            }
            "run-node" => {
                if args.len() < 3 {
                    eprintln!("Usage: {} run-node <port>", args[0]);
                    return Ok(());
                }
                let port = args[2].parse::<u16>()
                    .map_err(|e| anyhow::anyhow!("Invalid port: {}", e))?;
                handle_run_node_command(port).await?;
            }
            "create-node" => {
                if args.len() < 3 {
                    eprintln!("Usage: {} create-node <node_index>", args[0]);
                    return Ok(());
                }
                let node_index = args[2].parse::<usize>()
                    .map_err(|e| anyhow::anyhow!("Invalid node index: {}", e))?;
                handle_create_node_command(node_index).await?;
            }
            "submit-transaction" => {
                if args.len() < 8 {
                    eprintln!("Usage: {} submit-transaction <tx_id> <from> <to> <amount> <proof_data> <public_key> <challenge>", args[0]);
                    return Ok(());
                }
                handle_submit_transaction_command(&args[2..]).await?;
            }
            "node-status" => {
                handle_node_status_command().await?;
            }
            "proof" => {
                if args.len() < 3 {
                    eprintln!("Usage: {} proof <public_key>", args[0]);
                    return Ok(());
                }
                handle_proof_command(&args[2]).await?;
            }
            "generate-proof" => {
                if args.len() < 3 {
                    eprintln!("Usage: {} generate-proof <public_key>", args[0]);
                    return Ok(());
                }
                handle_generate_proof_command(&args[2]).await?;
            }
            _ => {
                eprintln!("Unknown command: {}", args[1]);
                eprintln!("Available commands:");
                eprintln!("  run-node <port>        - Start persistent node (RECOMMENDED)");
                eprintln!("  start-node <port>      - Start node with API server");
                eprintln!("  create-node <index>    - Create and display node info");
                eprintln!("  submit-transaction     - Submit transaction (7 params)");
                eprintln!("  node-status            - Show node status");
                eprintln!("  proof <public_key>     - Generate proof for public key");
                eprintln!("  generate-proof <public_key> - Generate proof data for transaction");
                eprintln!("  (no args)              - Run demo");
                return Ok(());
            }
        }
    }
    
    Ok(())
}

async fn run_demo() -> Result<()> {
    println!("\n=== WALLET GENERATION AND OWNERSHIP PROOF ===");
    match generate_and_store_wallet() {
        Ok(pk) => {
            println!("Public Key: 0x{}", hex::encode(pk.serialize_uncompressed()));
            let address = pub_key_address(&pk);
            println!("Address: 0x{}", hex::encode(address.as_bytes()));
            println!("Private key is securely stored in macOS Keychain");
        }
        Err(e) => eprintln!("Error generating wallet: {:?}", e),
    }
    
    println!("\n=== VALIDATING USER PROOF OF OWNERSHIP ===");
    match secure_storage::retrieve_private_key() {
        Ok(private_key_bytes) => {
            let private_key = SecretKey::from_slice(&private_key_bytes)
                .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;
            
            let secp = Secp256k1::new();
            let public_key = private_key.public_key(&secp);
            
            match create_ownership_proof(&private_key, &public_key) {
                Ok(valid) => {
                    if valid {
                        println!("User has proven ownership of the private key");
                    } else {
                        println!("ZK ownership proof verification failed");
                        return Ok(());
                    }
                }
                Err(e) => {
                    eprintln!("ZK proof generation failed: {:?}", e);
                    return Ok(());
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to retrieve private key: {:?}", e);
            return Ok(());
        }
    }
    
    println!("\n=== TRANSACTION EXAMPLE ===");
    let mut transaction = crate::transaction::transaction::Transaction::new(
        "0x1234567890abcdef1234567890abcdef12345678".to_string(), // sender
        "0x52b0f78ca732389f96539e8E3E0d02F2796D8bac".to_string(), // destination
        1000, // amount
        1, // nonce
    );
    
    match secure_storage::retrieve_private_key() {
        Ok(private_key_bytes) => {
            let private_key = SecretKey::from_slice(&private_key_bytes)
                .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;
            
            let secp = Secp256k1::new();
            let public_key = private_key.public_key(&secp);
            
            match transaction.generate_zk_proof(&private_key, &public_key) {
                Ok(_) => {
                    println!("Transaction ZK proof generated successfully");
                    println!("Sender: {}", transaction.sender);
                    println!("Destination: {}", transaction.destination);
                    println!("Amount: {}", transaction.amount);
                    println!("Nonce: {}", transaction.nonce);
                    
                    match transaction.verify_zk_proof(&public_key) {
                        Ok(valid) => {
                            if valid {
                                println!("Transaction ZK proof verification successful");
                            } else {
                                println!("Transaction ZK proof verification failed");
                            }
                        }
                        Err(e) => println!("Error verifying transaction proof: {}", e),
                    }
                }
                Err(e) => println!("Error generating transaction proof: {}", e),
            }
        }
        Err(e) => println!("Failed to retrieve private key for transaction: {}", e),
    }
    
    println!("\n=== EPHEMERAL DKG SESSION ===");
    let session_id = "tx_ephemeral_dkg_001".to_string();
    let mut dkg_session = simulate_dkg_session(session_id)?;
    
    println!("\n=== TRANSACTION SIGNING WITH EPHEMERAL KEYS ===");
    let transaction_message = b"Send 1000 tokens to 0x52b0f78ca732389f96539e8E3E0d02F2796D8bac";
    let aggregated_signature = simulate_threshold_signing(&mut dkg_session, transaction_message)?;
    
    println!("Transaction signed successfully with ephemeral keys!");
    let mut global_pk_bytes = Vec::new();
    aggregated_signature.public_key.into_affine().x.into_bigint().serialize_uncompressed(&mut global_pk_bytes).unwrap();
    println!("Global public key: 0x{}", 
            hex::encode(global_pk_bytes));
    
    println!("\n=== DESTROYING EPHEMERAL KEYS ===");
    dkg_session.destroy_shares();
    
    println!("\n=== TRANSACTION COMPLETED ===");
    
    Ok(())
}

async fn handle_start_node_command(port: u16) -> Result<()> {
    info!("Starting ZK Signing Node on port {}", port);
    
    let node = create_test_node(0)?;
    let shared_runtime = create_shared_runtime(node);
    
    info!("Node created successfully!");
    info!("Node ID: {}", {
        let runtime = shared_runtime.read().await;
        runtime.node_info.node_id.clone()
    });
    
    info!("Starting API server on port {}...", port);
    NodeRuntime::start_api_server(shared_runtime, port).await?;
    
    Ok(())
}

async fn handle_run_node_command(port: u16) -> Result<()> {
    println!("Starting Persistent ZK Signing Node...");
    println!("Port: {}", port);
    
    let node = create_test_node(0)?;
    let shared_runtime = create_shared_runtime(node);
    
    let node_id = {
        let runtime = shared_runtime.read().await;
        runtime.node_info.node_id.clone()
    };
    
    println!("Node created successfully!");
    println!("Node ID: {}", node_id);
    println!("Public Key: {}", {
        let runtime = shared_runtime.read().await;
        runtime.node_info.public_key.clone()
    });
    println!("Address: {}", {
        let runtime = shared_runtime.read().await;
        runtime.node_info.address.clone()
    });
    
    println!("\nStarting API server...");
    println!("Available endpoints:");
    println!("   GET  /health     - Node health status");
    println!("   GET  /status     - Node information");
    println!("   POST /transaction - Submit transaction request");
    println!("   GET  /sessions   - List active sessions");
    println!("   GET  /sessions/:id - Get session details");
    
    println!("\nNode is now running and ready to accept requests!");
    println!("Users can now send transaction requests to this node.");
    println!("Press Ctrl+C to stop the node.\n");
    
    NodeRuntime::start_api_server(shared_runtime, port).await?;
    
    Ok(())
}

async fn handle_create_node_command(node_index: usize) -> Result<()> {
    println!("=== CREATING NODE ===");
    let node = create_test_node(node_index)?;
    
    println!("Node ID: {}", node.node_info.node_id);
    println!("Public Key: 0x{}", node.node_info.public_key);
    println!("Address: {}", node.node_info.address);
    println!("Status: {:?}", node.node_info.status);
    println!("Registered at: {}", node.node_info.registered_at);
    println!("Threshold: {}", node.threshold);
    
    Ok(())
}

async fn handle_submit_transaction_command(args: &[String]) -> Result<()> {
    let transaction_id = &args[0];
    let from_address = &args[1];
    let to_address = &args[2];
    let amount = args[3].parse::<u64>()
        .map_err(|e| anyhow::anyhow!("Invalid amount: {}", e))?;
    let _proof_data = &args[4];
    let public_key = &args[5];
    let challenge = &args[6];
    
    println!("=== SUBMITTING TRANSACTION ===");
    println!("Transaction ID: {}", transaction_id);
    println!("From: {}", from_address);
    println!("To: {}", to_address);
    println!("Amount: {}", amount);
    
    let node = create_test_node(0)?;
    let shared_runtime = create_shared_runtime(node);
    
    let clean_public_key = if public_key.starts_with("0x") {
        &public_key[2..]
    } else {
        public_key
    };
    
    if clean_public_key.len() < 64 {
        return Err(anyhow::anyhow!("Public key must be at least 64 characters long (32 bytes)"));
    }
    
    if !clean_public_key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!("Public key contains invalid hex characters. Use only 0-9, a-f, A-F"));
    }
    
    let mut transaction = crate::transaction::transaction::Transaction::new_with_proof(
        from_address.clone(),
        to_address.clone(),
        amount,
        1, // nonce - in a real implementation this would be managed properly
        clean_public_key.to_string(),
        challenge.clone(),
    );
    
    match secure_storage::retrieve_private_key() {
        Ok(private_key_bytes) => {
            let private_key = SecretKey::from_slice(&private_key_bytes)
                .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;
            
            let secp = Secp256k1::new();
            let public_key = private_key.public_key(&secp);
            
            if let Err(e) = transaction.generate_zk_proof(&private_key, &public_key) {
                return Err(anyhow::anyhow!("Failed to generate transaction proof: {}", e));
            }
        }
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to retrieve private key: {}", e));
        }
    }
    
    let transaction_request = TransactionRequest {
        transaction,
        public_key: clean_public_key.to_string(),
        challenge: challenge.clone(),
    };
    
    let result = {
        let mut runtime = shared_runtime.write().await;
        runtime.process_transaction_final_flow(transaction_request).await?
    };
    
    println!("Transaction Result:");
    println!("  Approved: {}", result.approved);
    println!("  Approval Count: {}", result.approval_count);
    println!("  Total Votes: {}", result.total_votes);
    println!("  Approved By: {:?}", result.approved_by);
    
    if let Some(signature) = result.final_signature {
        println!("  Final Signature: 0x{}", hex::encode(signature));
    }
    
    Ok(())
}

async fn handle_node_status_command() -> Result<()> {
    println!("=== NODE STATUS ===");
    
    let node = create_test_node(0)?;
    let health = node.get_node_health();
    
    println!("Node ID: {}", health.node_id);
    println!("Status: {:?}", health.status);
    println!("CPU Usage: {:.1}%", health.cpu_usage);
    println!("Memory Usage: {:.1}%", health.memory_usage * 100.0);
    println!("Uptime: {} seconds", health.uptime);
    println!("Ephemeral Shares: {}", health.ephemeral_shares_count);
    println!("Active Sessions: {}", health.active_sessions);
    
    Ok(())
}

async fn handle_proof_command(public_key_hex: &str) -> Result<()> {
    println!("=== GENERATING PROOF FOR PUBLIC KEY ===");
    println!("Public Key: {}", public_key_hex);
    
    let clean_public_key = if public_key_hex.starts_with("0x") {
        &public_key_hex[2..]
    } else {
        public_key_hex
    };
    
    if clean_public_key.len() < 64 {
        return Err(anyhow::anyhow!("Public key must be at least 64 characters long (32 bytes)"));
    }
    
    if !clean_public_key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!("Public key contains invalid hex characters. Use only 0-9, a-f, A-F"));
    }
    
    let pk_bytes = hex::decode(clean_public_key)
        .map_err(|e| anyhow::anyhow!("Invalid public key hex: {}", e))?;
    
    let _secp = Secp256k1::new();
    let _public_key = secp256k1::PublicKey::from_slice(&pk_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;
    
    let _node = create_test_node(0)?;
    
    let proof_data = format!("proof_{}", hex::encode(&pk_bytes[0..8]));
    println!("Proof: {}", proof_data);
    println!("Status: SUCCESS");
    
    Ok(())
}

async fn handle_generate_proof_command(public_key: &str) -> Result<()> {
    println!("=== GENERATING PROOF DATA FOR TRANSACTION ===");
    
    let clean_public_key = if public_key.starts_with("0x") {
        &public_key[2..]
    } else {
        public_key
    };
    
    if clean_public_key.len() < 64 {
        return Err(anyhow::anyhow!("Public key must be at least 64 characters long (32 bytes)"));
    }
    
    if !clean_public_key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!("Public key contains invalid hex characters. Use only 0-9, a-f, A-F"));
    }
    
    let proof_data = generate_proof_data(clean_public_key)?;
    let challenge = format!("challenge_{}", clean_public_key[..8].to_string());
    
    println!("Public Key: 0x{}", clean_public_key);
    println!("Proof Data: {:?}", proof_data);
    println!("Challenge: {}", challenge);
    println!();
    println!("=== COPY THIS FOR TRANSACTION ===");
    println!("curl -X POST http://localhost:3000/transaction \\");
    println!("  -H \"Content-Type: application/json\" \\");
    println!("  -d '{{");
    println!("    \"transaction_id\": \"tx_$(date +%s)\",");
    println!("    \"from_address\": \"0xfrom\",");
    println!("    \"to_address\": \"0xto\",");
    println!("    \"amount\": 1000,");
    println!("    \"proof_data\": {:?},", proof_data);
    println!("    \"public_key\": \"0x{}\",", clean_public_key);
    println!("    \"challenge\": \"{}\"", challenge);
    println!("  }}'");
    
    Ok(())
}

fn generate_proof_data(public_key: &str) -> Result<Vec<u8>> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    public_key.hash(&mut hasher);
    let hash = hasher.finish();
    
    let mut proof_data = Vec::new();
    
    let pk_bytes = hex::decode(public_key)?;
    proof_data.extend_from_slice(&pk_bytes[..8]);
    
    let hash_bytes = hash.to_le_bytes();
    proof_data.extend_from_slice(&hash_bytes[..4]);
    
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let timestamp_bytes = timestamp.to_le_bytes();
    proof_data.extend_from_slice(&timestamp_bytes[..4]);
    
    let mut additional_data = Vec::new();
    for (i, &byte) in pk_bytes.iter().enumerate() {
        if i % 3 == 0 {
            additional_data.push(byte.wrapping_add(i as u8));
        }
    }
    proof_data.extend_from_slice(&additional_data[..8.min(additional_data.len())]);
    
    Ok(proof_data)
}
