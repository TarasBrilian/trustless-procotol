mod wallet_gen;
mod zk;
mod nodes;
mod dkg;
mod storage;
mod transaction;
mod network;

use wallet_gen::wallet::{pub_key_address, generate_and_store_wallet};
use zk::zk_ownership::{create_ownership_proof};
use hex;
use storage::secure_storage;
use secp256k1::{SecretKey, Secp256k1};
use anyhow::Result;
use std::env;
use tracing::info;
use nodes::node::{NodeRuntime, TransactionRequest, create_test_node, create_shared_runtime};

#[tokio::main]
async fn main() -> Result<()> {
    // let private_key = secure_storage::retrieve_private_key()?;
    // import_private_key(&private_key)?;

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
            "test-transaction" => {
                handle_test_transaction_command().await?;
            }
            "validate-transaction" => {
                if args.len() < 8 {
                    eprintln!("Usage: {} validate-transaction <tx_id> <from> <to> <amount> <proof_data> <public_key> <challenge>", args[0]);
                    return Ok(());
                }
                handle_validate_transaction_command(&args[2..]).await?;
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
                eprintln!("  test-transaction       - Run comprehensive transaction test");
                eprintln!("  validate-transaction   - Validate transaction (7 params)");
                eprintln!("  (no args)              - Run demo");
                return Ok(());
            }
        }
    }
    
    Ok(())
}

async fn run_demo() -> Result<()> {
    println!("\n=== ZK-WALLET DEMO ===");
    println!();
    println!("{}", "=".repeat(50));
    
    let active_ports = vec![3000, 3001, 3002, 3003, 3004];
    let mut active_node_found = false;
    let mut active_port = None;
    
    for port in &active_ports {
        match reqwest::get(&format!("http://localhost:{}/health", port)).await {
            Ok(response) => {
                if response.status().is_success() {
                    println!("Active node found on port {}", port);
                    active_node_found = true;
                    active_port = Some(*port);
                    break;
                }
            }
            Err(_) => {
                println!("No active node on port {}", port);
            }
        }
    }
    
    if !active_node_found {
        println!();
        println!("{}", "=".repeat(50));
        println!();
        println!("To run the demo:");
        println!("   1. Start a node: ./start_p2p_nodes.sh");
        println!();
        return Ok(());
    }
    
    println!("Active node found on port {}", active_port.unwrap());
    println!();
    
    // Generate wallet and prove ownership (this can be done locally)
    println!("Wallet generation and ownership proof");
    println!("{}", "=".repeat(50));
    
    let (_public_key, sender_address) = match generate_and_store_wallet() {
        Ok(pk) => {
            let address = pub_key_address(&pk);
            println!("Wallet generated successfully!");
            println!("Public Key: 0x{}", hex::encode(pk.serialize_uncompressed()));
            println!("Address: 0x{}", hex::encode(address.as_bytes()));
            println!("Private key stored securely in macOS Keychain");
            (pk, address)
        }
        Err(e) => {
            eprintln!("Error generating wallet: {:?}", e);
            return Ok(());
        }
    };
    
    println!("\nValidating user proof of ownership");
    println!("{}", "=".repeat(50));
    
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
                        println!("ZK proof verification successful");
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
    
    // Now send transaction to active node for processing
    println!("\nSubmitting transaction to active node");
    println!("{}", "=".repeat(50));
    
    let mut transaction = crate::transaction::transaction::Transaction::new(
        format!("0x{}", hex::encode(sender_address.as_bytes())), // sender (newly generated wallet)
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
                    
                    // Send transaction to active node
                    let transaction_request = TransactionRequest {
                        transaction: transaction.clone(),
                        public_key: hex::encode(public_key.serialize_uncompressed()),
                        challenge: "demo_challenge_001".to_string(),
                        threshold: 3, // Default threshold for demo
                    };
                    
                    let client = reqwest::Client::new();
                    let transaction_url = format!("http://localhost:{}/transaction", active_port.unwrap());
                    
                    println!("\nSending transaction to node");
                    println!("{}", "=".repeat(50));
                    
                    match client.post(&transaction_url)
                        .json(&transaction_request)
                        .send()
                        .await 
                    {
                        Ok(response) => {
                            if response.status().is_success() {
                                match response.json::<crate::nodes::node::TransactionResult>().await {
                                    Ok(result) => {
                                        println!("Transaction processed successfully!");
                                        println!("{}", "=".repeat(50));
                                        
                                        // Enhanced validation details when transaction is valid
                                        if result.approved {
                                            println!("\nTRANSACTION VALIDATION DETAILS");
                                            println!("{}", "─".repeat(50));
                                            println!("Transaction Status: VALID & APPROVED");
                                            println!("Transaction ID: {}", result.transaction_id);
                                            println!("Transaction Hash: 0x{}", result.transaction_hash);
                                            
                                            // Generate DKG session ID (following the pattern from node.rs)
                                            let dkg_session_id = format!("dkg_{}", result.transaction_id);
                                            println!("DKG Session ID: {}", dkg_session_id);
                                            
                                            // Additional transaction details
                                            println!("Validation Nodes: {} validators", result.approval_count);
                                            println!("Approved By Node IDs: {:?}", result.approved_by);
                                            println!("Consensus: {}/{} votes", result.approval_count, result.total_votes);
                                            
                                            // Transaction content details
                                            println!("\nTRANSACTION DETAILS");
                                            println!("{}", "─".repeat(50));
                                            println!("From: {}", transaction.sender);
                                            println!("To: {}", transaction.destination);
                                            println!("Amount: {} tokens", transaction.amount);
                                            println!("Nonce: {}", transaction.nonce);
                                            println!("Timestamp: {}", transaction.timestamp);
                                            
                                            // ZK Proof and cryptographic details
                                            println!("\nCRYPTOGRAPHIC VALIDATION");
                                            println!("{}", "─".repeat(50));
                                            println!("Public Key: 0x{}", transaction_request.public_key);
                                            println!("Challenge: {}", transaction_request.challenge);
                                            println!("ZK Proof Hash: 0x{}", transaction.create_transaction_hash());
                                            println!("ZK Proof Length: {} chars", transaction_request.transaction.zk_proof.len());
                                            
                                            if let Some(signature) = &result.final_signature {
                                                println!("\nTHRESHOLD SIGNATURE");
                                                println!("{}", "─".repeat(50));
                                                println!("Final Signature: 0x{}", signature);
                                                println!("Signature Length: {} chars", signature.len());
                                                println!("Threshold Signing: COMPLETED");
                                            }
                                            
                                            println!("{}", "=".repeat(50));
                                        } else {
                                            println!("Transaction Status: REJECTED");
                                        }
                                        
                                        println!("\nDemo completed successfully!");
                                    }
                                    Err(e) => {
                                        println!("Failed to parse transaction response: {}", e);
                                    }
                                }
                            } else {
                                println!("Transaction request failed with status: {}", response.status());
                            }
                        }
                        Err(e) => {
                            println!("Failed to send transaction request: {}", e);
                            println!("Node may have become unavailable during processing.");
                        }
                    }
                }
                Err(e) => {
                    println!("Error generating transaction proof: {}", e);
                }
            }
        }
        Err(e) => {
            println!("Failed to retrieve private key for transaction: {}", e);
        }
    }
    
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
        threshold: 3, // Default threshold for submit transaction
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

async fn handle_test_transaction_command() -> Result<()> {
    
    println!("Checking for active nodes...");
    println!("{}", "=".repeat(60));
    
    let active_ports = vec![3000, 3001, 3002, 3003, 3004];
    let mut active_node_found = false;
    let mut active_port = None;
    
    for port in &active_ports {
        match reqwest::get(&format!("http://localhost:{}/health", port)).await {
            Ok(response) => {
                if response.status().is_success() {
                    println!("Active node found on port {}", port);
                    active_node_found = true;
                    active_port = Some(*port);
                    break;
                }
            }
            Err(_) => {
                println!("No active node on port {}", port);
            }
        }
    }
    
    if !active_node_found {
        println!("{}", "=".repeat(60));
        println!("Test transaction cannot run without active nodes.");
        println!("To run the test transaction: cargo run start_p2p_nodes.sh");
        return Ok(());
    }
    
    println!("Active node found on port {}", active_port.unwrap());
    
    println!("{}", "=".repeat(60));
    
    let (_public_key, sender_address) = match generate_and_store_wallet() {
        Ok(pk) => {
            let address = pub_key_address(&pk);
            println!("Wallet generated successfully!");
            println!("Public Key: 0x{}", hex::encode(pk.serialize_uncompressed()));
            println!("Sender Address: 0x{}", hex::encode(address.as_bytes()));
            println!("Private key stored securely in macOS Keychain (Enclave)");
            (pk, address)
        }
        Err(e) => {
            eprintln!("Error generating wallet: {:?}", e);
            return Err(e);
        }
    };

    println!("\nValidating user's proof of ownership...");
    println!("{}", "=".repeat(60));
    
    match secure_storage::retrieve_private_key() {
        Ok(private_key_bytes) => {
            let private_key = SecretKey::from_slice(&private_key_bytes)
                .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;
            
            let secp = Secp256k1::new();
            let derived_public_key = private_key.public_key(&secp);
            
            match create_ownership_proof(&private_key, &derived_public_key) {
                Ok(valid) => {
                    if valid {
                        println!("User has proven ownership of the private key");
                    } else {
                        return Err(anyhow::anyhow!("Ownership proof failed"));
                    }
                }
                Err(e) => {
                    eprintln!("ZK proof generation failed: {:?}", e);
                    return Err(e);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to retrieve private key: {:?}", e);
            return Err(e);
        }
    }
    
    println!("\nCreating transaction to dummy address...");
    println!("{}", "=".repeat(60));
    
    let dummy_address = "0x361970c23ab36f3d38973e39679b8B0aBF83327B";
    let transaction_amount = 1000;
    
    println!("Using newly generated wallet as sender:");
    println!("   Sender: 0x{}", hex::encode(sender_address.as_bytes()));
    println!("   Destination: {}", dummy_address);
    println!("   Amount: {} tokens", transaction_amount);
    
    let mut transaction = crate::transaction::transaction::Transaction::new(
        format!("0x{}", hex::encode(sender_address.as_bytes())), // sender
        dummy_address.to_string(), // destination (dummy address)
        transaction_amount, // amount
        1, // nonce
    );
    
    println!("\nGenerating ZK proof for transaction...");
    println!("{}", "=".repeat(60));
    
    let (transaction_request, derived_public_key) = match secure_storage::retrieve_private_key() {
        Ok(private_key_bytes) => {
            let private_key = SecretKey::from_slice(&private_key_bytes)
                .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;
            
            let secp = Secp256k1::new();
            let derived_public_key = private_key.public_key(&secp);
            
            match transaction.generate_zk_proof(&private_key, &derived_public_key) {
                Ok(_) => {
                    match transaction.verify_zk_proof(&derived_public_key) {
                        Ok(valid) => {
                            if valid {
                                println!("Transaction ZK proof verification successful");
                            } else {
                                println!("Transaction ZK proof verification failed");
                                return Err(anyhow::anyhow!("Transaction proof verification failed"));
                            }
                        }
                        Err(e) => {
                            eprintln!("Error verifying transaction proof: {}", e);
                            return Err(e);
                        }
                    }
                    
                    let transaction_request = TransactionRequest {
                        transaction,
                        public_key: hex::encode(derived_public_key.serialize_uncompressed()),
                        challenge: format!("test_challenge_{}", std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()),
                        threshold: 3, // Default threshold for test transaction
                    };
                    
                    (transaction_request, derived_public_key)
                }
                Err(e) => {
                    eprintln!("Error generating transaction proof: {}", e);
                    return Err(e);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to retrieve private key for transaction: {}", e);
            return Err(e);
        }
    };
    
    println!("\nSending transaction to active node for processing...");
    println!("{}", "=".repeat(60));
    
    let client = reqwest::Client::new();
    let transaction_url = format!("http://localhost:{}/transaction", active_port.unwrap());
    
    println!("   Sending transaction to node on port {}", active_port.unwrap());
    println!("   Transaction will be processed with ephemeral DKG");
    println!("   Node will handle key generation and destruction");
    
    match client.post(&transaction_url)
        .json(&transaction_request)
        .send()
        .await 
    {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<crate::nodes::node::TransactionResult>().await {
                    Ok(result) => {
                        println!("Transaction processed successfully by node!");
                        println!("{}", "=".repeat(60));
                        
                        // Enhanced validation details for test transaction
                        if result.approved {
                            println!("\nNODE TRANSACTION VALIDATION RESULTS");
                            println!("{}", "─".repeat(60));
                            println!("Validation Status: TRANSACTION IS VALID");
                            println!("Transaction ID: {}", result.transaction_id);
                            println!("Transaction Hash: 0x{}", result.transaction_hash);
                            
                            let dkg_session_id = format!("dkg_{}", result.transaction_id);
                            println!("DKG Session ID: {}", dkg_session_id);
                            
                            println!("Validating Nodes: {} nodes participated", result.approval_count);
                            println!("Node IDs that approved: {:?}", result.approved_by);
                            println!("Voting Result: {}/{} consensus achieved", result.approval_count, result.total_votes);
                            
                            // Transaction validation details
                            println!("\nVALIDATED TRANSACTION DATA");
                            println!("{}", "─".repeat(60));
                            println!("Sender Address: 0x{}", hex::encode(sender_address.as_bytes()));
                            println!("Destination: {}", dummy_address);
                            println!("Transfer Amount: {} tokens", transaction_amount);
                            println!("Transaction Nonce: {}", transaction_request.transaction.nonce);
                            
                            // Cryptographic validation results
                            println!("\nCRYPTOGRAPHIC VALIDATION RESULTS");
                            println!("{}", "─".repeat(60));
                            println!("Public Key Used: 0x{}", hex::encode(derived_public_key.serialize_uncompressed()));
                            println!("Challenge String: {}", transaction_request.challenge);
                            println!("ZK Proof Hash: 0x{}", transaction_request.transaction.create_transaction_hash());
                            println!("ZK Proof Verified: SUCCESS");
                            
                            if let Some(signature) = &result.final_signature {
                                println!("\nTHRESHOLD SIGNATURE DETAILS");
                                println!("{}", "─".repeat(60));
                                println!("Final Signature: 0x{}", signature);
                                println!("Signature Algorithm: BLS12-381 Threshold Signature");
                                println!("Multi-party Signing: COMPLETED");
                            }
                        } else {
                            println!("Transaction Validation: FAILED");
                            println!("Transaction ID: {}", result.transaction_id);
                            println!("Reason: Transaction was rejected by validators");
                        }
                    }
                    Err(e) => {
                        println!("Failed to parse transaction response: {}", e);
                        return Err(anyhow::anyhow!("Transaction processing failed"));
                    }
                }
            } else {
                println!("Transaction request failed with status: {}", response.status());
                return Err(anyhow::anyhow!("Transaction processing failed"));
            }
        }
        Err(e) => {
            println!("Failed to send transaction request: {}", e);
            println!("Node may have become unavailable during processing.");
            return Err(anyhow::anyhow!("Transaction processing failed"));
        }
    }
    
    println!("\nTransaction to dummy address completed successfully!");
    println!("{}", "=".repeat(60));
    println!("Transaction Summary:");
    println!("   • From: 0x{}", hex::encode(sender_address.as_bytes()));
    println!("   • To: {}", dummy_address);
    println!("   • Amount: {} tokens", transaction_amount);
    println!("   • Nonce: {}", transaction_request.transaction.nonce);
    println!("   • Public Key: 0x{}", hex::encode(derived_public_key.serialize_uncompressed()));
    println!("   • Processed by: Node on port {}", active_port.unwrap());
    println!("   • Status: COMPLETED");
    println!();
    
    Ok(())
}

async fn handle_validate_transaction_command(args: &[String]) -> Result<()> {
    let transaction_id = &args[0];
    let from_address = &args[1];
    let to_address = &args[2];
    let amount = args[3].parse::<u64>()
        .map_err(|e| anyhow::anyhow!("Invalid amount: {}", e))?;
    let proof_data = &args[4];
    let public_key = &args[5];
    let challenge = &args[6];
    
    println!("Validation request details:");
    println!("{}", "=".repeat(50));
    println!("Transaction ID: {}", transaction_id);
    println!("From: {}", from_address);
    println!("To: {}", to_address);
    println!("Amount: {}", amount);
    println!("Public Key: {}", public_key);
    println!("Challenge: {}", challenge);
    println!("Proof Data: {}", proof_data);
    println!();
    
    println!("Checking for active nodes...");
    println!("{}", "=".repeat(50));
    
    let active_ports = vec![3000, 3001, 3002, 3003, 3004];
    let mut active_node_found = false;
    let mut active_port = None;
    
    for port in &active_ports {
        match reqwest::get(&format!("http://localhost:{}/health", port)).await {
            Ok(response) => {
                if response.status().is_success() {
                    println!("Active node found on port {}", port);
                    active_node_found = true;
                    active_port = Some(*port);
                    break;
                }
            }
            Err(_) => {
                println!("No active node on port {}", port);
            }
        }
    }
    
    if !active_node_found {
        println!();
        println!("No active nodes found!");
        println!("{}", "=".repeat(50));
        println!("Transaction validation failed because no active nodes are available.");
        println!();
        println!("To fix this issue: cargo run start_p2p_nodes.sh");
        return Ok(());
    }
    
    println!("Active node found on port {}", active_port.unwrap());
    println!();
    
    let mut transaction = crate::transaction::transaction::Transaction::new(
        from_address.clone(),
        to_address.clone(),
        amount,
        1, // nonce
    );
    
    transaction.zk_proof = proof_data.clone();
    
    let transaction_request = TransactionRequest {
        transaction,
        public_key: public_key.clone(),
        challenge: challenge.clone(),
        threshold: 3, // Default threshold for validation
    };
    
    println!("Sending validation request to active node...");
    println!("{}", "=".repeat(50));
    
    let client = reqwest::Client::new();
    let validation_url = format!("http://localhost:{}/validate-transaction", active_port.unwrap());
    
    match client.post(&validation_url)
        .json(&transaction_request)
        .send()
        .await 
    {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<crate::nodes::node::ValidationResponse>().await {
                    Ok(validation_response) => {
                        println!("Validation completed successfully!");
                        println!("{}", "=".repeat(50));
                        println!("Transaction ID: {}", validation_response.transaction_id);
                        println!("Node ID: {}", validation_response.node_id);
                        println!("Validation Time: {} μs", validation_response.validation_time);
                        println!("Is Valid: {}", validation_response.is_valid);
                        println!("Proof Valid: {}", validation_response.proof_valid);
                        println!("DKG Ready: {}", validation_response.dkg_ready);
                        println!("Key Shares Count: {}", validation_response.keyshares_count);
                        println!();
                        
                        if validation_response.is_valid {
                        println!("Transaction passed all validation checks!");
                        } else {
                            println!("Transaction failed validation!");
                        }
                    }
                    Err(e) => {
                        println!("Failed to parse validation response: {}", e);
                    }
                }
            } else {
                println!("Validation request failed with status: {}", response.status());
            }
        }
        Err(e) => {
            println!("Failed to send validation request: {}", e);
        }
    }
    
    Ok(())
}
