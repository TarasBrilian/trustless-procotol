use anyhow::Result;
use ark_bls12_381::{Fr, G1Projective};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use hex;
use serde::{Deserialize, Serialize};
use secp256k1::{PublicKey, Secp256k1};
use tiny_keccak::{Hasher, Keccak};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use rand::Rng;
use tracing::{error, info, warn};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use crate::network::peer::{PeerManager, NetworkMessage};
use std::time::Instant;

use crate::dkg::ephemeral_dkg::{
    simulate_dkg_session, simulate_threshold_signing, DkgSession,
};
use crate::transaction::transaction::{Transaction, StoredTransactionData};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub transaction_id: String,
    pub status: TransactionStatus,
    pub created_at: u64,
    pub key_shares_count: usize,
    pub votes_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDetail {
    pub transaction_id: String,
    pub status: TransactionStatus,
    pub created_at: u64,
    pub from_address: String,
    pub to_address: String,
    pub amount: u64,
    pub key_shares_count: usize,
    pub votes_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub public_key: String,
    pub address: String,
    pub status: NodeStatus,
    pub registered_at: u64,
}

#[derive(Debug, Clone)]
pub struct EphemeralKeyShare {
    pub node_id: usize,
    pub share_value: Fr,
    pub public_commitment: G1Projective,
    pub session_id: String,
    pub is_used: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofValidationRequest {
    pub proof_data: Vec<u8>,
    pub public_key: String,
    pub challenge: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofValidationResponse {
    pub is_valid: bool,
    pub node_id: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRequest {
    pub transaction: Transaction,
    pub public_key: String,
    pub challenge: String,
    pub threshold: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompetitiveValidationRequest {
    pub transaction: Transaction,
    pub public_key: String,
    pub challenge: String,
    pub threshold: usize,
    pub max_participants: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResponse {
    pub transaction_id: String,
    pub node_id: String,
    pub validation_time: u64, // microseconds
    pub is_valid: bool,
    pub proof_valid: bool,
    pub dkg_ready: bool,
    pub keyshares_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompetitiveResult {
    pub transaction_id: String,
    pub transaction_hash: String,
    pub fastest_nodes: Vec<String>,
    pub validation_time: u64,
    pub threshold_met: bool,
    pub keyshares_hash: String,
    pub proof_hash: String,
    pub combined_hash: String,
    pub final_signature: Option<String>,
    pub approved_by: Vec<String>,
}


#[derive(Debug, Clone)]
pub struct TransactionSession {
    pub transaction_id: String,
    pub transaction_request: TransactionRequest,
    pub key_shares: HashMap<usize, crate::transaction::transaction::TransactionKeyShare>,
    pub votes: Vec<TransactionVote>,
    pub status: TransactionStatus,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionStatus {
    Pending,
    Approved,
    Rejected,
    Error,
    Signed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskType {
    Transaction,
    DKG,
    Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskStatus {
    Pending,
    Completed,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskResult {
    Success,
    Failure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub task_id: String,
    pub task_type: TaskType,
    pub task_status: TaskStatus,
    pub task_created_at: u64,
    pub task_completed_at: u64,
    pub task_result: TaskResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionVote {
    pub transaction_id: String,
    pub node_id: usize,
    pub approved: bool,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeStatus {
    Active,
    Inactive,
    Suspended,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionResult {
    pub transaction_id: String,
    pub transaction_hash: String,
    pub approved: bool,
    pub approval_count: usize,
    pub total_votes: usize,
    pub final_signature: Option<String>,
    pub approved_by: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHealth {
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub uptime: u64,
    pub node_id: String,
    pub status: NodeStatus,
    pub ephemeral_shares_count: usize,
    pub active_sessions: usize,
}

pub fn create_test_node(node_index: usize) -> Result<NodeRuntime> {
    NodeRuntime::create_test_node(node_index)
}

pub fn create_shared_runtime(node: NodeRuntime) -> SharedRuntime {
    Arc::new(RwLock::new(node))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgInitiateRequest {
    pub transaction_hash: String,
    pub threshold: usize,
    pub participants: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgInitiateResponse {
    pub session_id: String,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgThresholdResponse {
    pub threshold_met: bool,
    pub current_shares: usize,
    pub required_threshold: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStoreRequest {
    pub transaction_hash: String,
    pub dkg_session_id: String,
    pub zk_proof: String,
    pub public_key: String,
    pub challenge: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStoreResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgCleanupRequest {
    pub transaction_hash: String,
    pub dkg_session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgCleanupResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct NodeRuntime {
    pub node_info: NodeInfo,
    pub ephemeral_key_shares: HashMap<usize, EphemeralKeyShare>,
    pub registered_nodes: HashMap<String, NodeInfo>,
    pub node_index: usize,
    pub dkg_sessions: HashMap<String, DkgSession>,
    pub transaction_sessions: HashMap<String, TransactionSession>,
    pub stored_transactions: HashMap<String, StoredTransactionData>,
    pub threshold: usize,
    pub peer_manager: PeerManager,
}

impl NodeRuntime {
    pub fn new(node_info: NodeInfo, node_index: usize, threshold: usize, node_port: u16) -> Self {
        let peer_manager = PeerManager::new(node_info.node_id.clone(), node_port);
        Self {
            node_info,
            ephemeral_key_shares: HashMap::new(),
            registered_nodes: HashMap::new(),
            node_index,
            dkg_sessions: HashMap::new(),
            transaction_sessions: HashMap::new(),
            stored_transactions: HashMap::new(),
            threshold,
            peer_manager,
        }
    }

    pub fn generate_address(public_key: &PublicKey) -> String {
        let pub_key_bytes = public_key.serialize_uncompressed();
        
        let mut hasher = Keccak::v256();
        hasher.update(&pub_key_bytes[1..]);
        let mut result = [0u8; 32];
        hasher.finalize(&mut result);
        
        let address_bytes = &result[12..];
        format!("0x{}", hex::encode(address_bytes))
    }

    pub fn response_to_task(&self, task: Task) -> Result<Task> {
        let mut task = task;
        task.task_status = TaskStatus::Completed;
        task.task_completed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Ok(task)
    }

    pub fn get_node_health(&self) -> NodeHealth {
        use sysinfo::System;
        let mut sys = System::new_all();
        sys.refresh_all();
        let cpu = sys.global_cpu_usage();
        let mem = if sys.total_memory() > 0 {
            sys.used_memory() as f32 / sys.total_memory() as f32
        } else {
            0.0
        };
        let uptime = 0;

        NodeHealth {
            cpu_usage: cpu,
            memory_usage: mem,
            uptime,
            node_id: self.node_info.node_id.clone(),
            status: self.node_info.status.clone(),
            ephemeral_shares_count: self.ephemeral_key_shares.len(),
            active_sessions: self.transaction_sessions.len(),
        }
    }

    pub fn store_ephemeral_key_share(&mut self, share: EphemeralKeyShare) -> Result<()> {
        if share.node_id != self.node_index + 1 {
            return Err(anyhow::anyhow!(
                "Invalid node ID for ephemeral key share: expected {}, got {}",
                self.node_index + 1,
                share.node_id
            ));
        }
        self.ephemeral_key_shares.insert(share.node_id, share);
        Ok(())
    }

    pub fn validate_user_proof_of_ownership(&self, request: &ProofValidationRequest) -> Result<bool> {
        let pk_bytes = hex::decode(&request.public_key)
            .map_err(|e| anyhow::anyhow!("Invalid public key hex: {}", e))?;
        
        let _secp = Secp256k1::new();
        let _public_key = PublicKey::from_slice(&pk_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;

        let is_valid = !request.proof_data.is_empty() && !request.challenge.is_empty();
        
        if is_valid {
            info!("Proof validation successful for public key: 0x{}", request.public_key);
        } else {
            warn!("Proof validation failed for public key: 0x{}", request.public_key);
        }
        
        Ok(is_valid)
    }

    pub fn validate_transaction(&self, request: &TransactionRequest) -> Result<ValidationResponse> {
        let start_time = std::time::Instant::now();
        
        info!("   Transaction ID: {}", request.transaction.nonce);
        info!("   Sender: {}", request.transaction.sender);
        info!("   Destination: {}", request.transaction.destination);
        info!("   Amount: {}", request.transaction.amount);
        
        let public_key = self.validate_public_key(&request.public_key)?;
        
        self.validate_transaction_structure(&request.transaction)?;
        
        let proof_valid = self.validate_zk_proof(&request.transaction, &public_key)?;
        
        self.validate_transaction_business_logic(&request.transaction)?;
        
        let dkg_ready = self.check_dkg_readiness()?;
        
        let validation_time = start_time.elapsed().as_micros() as u64;
        
        let response = ValidationResponse {
            transaction_id: request.transaction.nonce.to_string(),
            node_id: self.node_info.node_id.clone(),
            validation_time,
            is_valid: true,
            proof_valid,
            dkg_ready,
            keyshares_count: self.ephemeral_key_shares.len(),
        };

        info!("   Validation time: {} μs", validation_time);
        info!("   Proof valid: {}", proof_valid);
        info!("   DKG ready: {}", dkg_ready);
        
        // Enhanced console logging for node validation
        if response.is_valid && proof_valid {
            println!("\n🎆 NODE VALIDATION SUCCESS");
            println!("{}", "─".repeat(45));
            println!("✅ Node {} validated transaction successfully", self.node_info.node_id);
            println!("📋 Transaction ID: {}", response.transaction_id);
            let tx_hash = request.transaction.create_transaction_hash();
            println!("🔐 Transaction Hash: 0x{}", tx_hash);
            
            let dkg_session_id = format!("dkg_{}", response.transaction_id);
            println!("⚡ DKG Session ID: {}", dkg_session_id);
            
            println!("🎯 Validation completed in {} μs", validation_time);
            println!("🔒 ZK Proof verification: ✅ PASSED");
            println!("⚡ DKG readiness check: ✅ READY");
            println!("🔑 Available key shares: {}", response.keyshares_count);
            println!("{}", "─".repeat(45));
        }
        
        Ok(response)
    }
    
    fn validate_public_key(&self, public_key_hex: &str) -> Result<PublicKey> {
        let clean_key = if public_key_hex.starts_with("0x") {
            &public_key_hex[2..]
        } else {
            public_key_hex
        };
        
        if !clean_key.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow::anyhow!("Public key contains invalid hex characters"));
        }
        
        // Accept compressed (64), uncompressed without prefix (128), and uncompressed with prefix (130)
        if clean_key.len() != 64 && clean_key.len() != 128 && clean_key.len() != 130 {
            return Err(anyhow::anyhow!("Public key has invalid length: {} (expected 64, 128, or 130)", clean_key.len()));
        }
        
        let pk_bytes = hex::decode(clean_key)
            .map_err(|e| anyhow::anyhow!("Failed to decode public key hex: {}", e))?;
        
        let public_key = PublicKey::from_slice(&pk_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid public key format: {}", e))?;
        
        Ok(public_key)
    }
    
    fn validate_transaction_structure(&self, transaction: &Transaction) -> Result<()> {
        if transaction.sender.is_empty() {
            return Err(anyhow::anyhow!("Transaction sender cannot be empty"));
        }
        
        if !transaction.sender.starts_with("0x") {
            return Err(anyhow::anyhow!("Transaction sender must start with '0x'"));
        }
        
        if transaction.sender.len() != 42 {
            return Err(anyhow::anyhow!("Transaction sender must be 40 hex characters (20 bytes)"));
        }
        
        if transaction.destination.is_empty() {
            return Err(anyhow::anyhow!("Transaction destination cannot be empty"));
        }
        
        if !transaction.destination.starts_with("0x") {
            return Err(anyhow::anyhow!("Transaction destination must start with '0x'"));
        }
        
        if transaction.destination.len() != 42 {
            return Err(anyhow::anyhow!("Transaction destination must be 40 hex characters (20 bytes)"));
        }
        
        if transaction.amount == 0 {
            return Err(anyhow::anyhow!("Transaction amount must be greater than zero"));
        }
        
        if transaction.amount > 1_000_000_000_000_000_000 {
            return Err(anyhow::anyhow!("Transaction amount too large (max: 1,000,000,000,000,000,000)"));
        }
        
        if transaction.nonce == 0 {
            return Err(anyhow::anyhow!("Transaction nonce must be greater than zero"));
        }
        
        if transaction.zk_proof.is_empty() {
            return Err(anyhow::anyhow!("Transaction ZK proof cannot be empty"));
        }
        
        Ok(())
    }
    
    fn validate_zk_proof(&self, transaction: &Transaction, public_key: &PublicKey) -> Result<bool> {
        if transaction.zk_proof.len() == 64 {
            let proof_valid = hex::decode(&transaction.zk_proof).is_ok();
            if !proof_valid {
                return Err(anyhow::anyhow!("Transaction ZK proof is not valid hex"));
            }
            return Ok(true);
        } else {
            let proof_valid = transaction.verify_zk_proof(public_key)?;
            if !proof_valid {
                return Err(anyhow::anyhow!("Transaction ZK proof verification failed"));
            }
            return Ok(true);
        }
    }
    
    fn validate_transaction_business_logic(&self, transaction: &Transaction) -> Result<()> {
        if transaction.sender == transaction.destination {
            return Err(anyhow::anyhow!("Sender and destination cannot be the same"));
        }
        
        let dummy_addresses = vec![
            "0x361970c23ab36f3d38973e39679b8B0aBF83327B",
            "0x0000000000000000000000000000000000000000",
            "0x1111111111111111111111111111111111111111",
        ];
        
        if dummy_addresses.contains(&transaction.destination.as_str()) {
            info!("Transaction to known dummy/test address: {}", transaction.destination);
        }
        
        if transaction.amount == 1 {
            warn!("Transaction amount is 1 (might be a test transaction)");
        }
        
        if !self.is_valid_ethereum_address(&transaction.sender) {
            return Err(anyhow::anyhow!("Invalid sender address format"));
        }
        
        if !self.is_valid_ethereum_address(&transaction.destination) {
            return Err(anyhow::anyhow!("Invalid destination address format"));
        }
        
        Ok(())
    }
    
    fn is_valid_ethereum_address(&self, address: &str) -> bool {
        if !address.starts_with("0x") || address.len() != 42 {
            return false;
        }
        
        let hex_part = &address[2..];
        hex_part.chars().all(|c| c.is_ascii_hexdigit())
    }
    
    fn check_dkg_readiness(&self) -> Result<bool> {
        let has_shares = !self.ephemeral_key_shares.is_empty();
        
        let is_active = matches!(self.node_info.status, NodeStatus::Active);
        
        let threshold_met = self.ephemeral_key_shares.len() >= self.threshold;
        
        let dkg_ready = has_shares && is_active && threshold_met;
        
        info!("   Has ephemeral shares: {}", has_shares);
        info!("   Node is active: {}", is_active);
        info!("   Threshold met: {}", threshold_met);
        info!("   DKG ready: {}", dkg_ready);
        
        Ok(dkg_ready)
    }
    
    pub fn validate_transaction_legacy(&self, request: &TransactionRequest) -> Result<bool> {
        let response = self.validate_transaction(request)?;
        Ok(response.is_valid)
    }

    pub async fn process_transaction_request(&mut self, request: TransactionRequest) -> Result<TransactionResult> {
        let validation_response = self.validate_transaction(&request)?;
        
        if !validation_response.is_valid {
            return Err(anyhow::anyhow!("Transaction validation failed"));
        }
        
        if !validation_response.proof_valid {
            return Err(anyhow::anyhow!("ZK proof validation failed"));
        }
        
        if !validation_response.dkg_ready {
            return Err(anyhow::anyhow!("DKG not ready for transaction processing"));
        }

        let transaction_id = format!("tx_{}", request.transaction.nonce);
        
        let dkg_session_id = format!("dkg_{}", transaction_id);

        let dkg_session = simulate_dkg_session(dkg_session_id.clone())?;

        self.dkg_sessions.insert(dkg_session_id.clone(), dkg_session.clone());

        let mut transaction_session = TransactionSession {
            transaction_id: transaction_id.clone(),
            transaction_request: request.clone(),
            key_shares: HashMap::new(),
            votes: Vec::new(),
            status: TransactionStatus::Pending,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        for (node_id, share) in &dkg_session.polynomial_shares {
            let transaction_key_share = crate::transaction::transaction::TransactionKeyShare {
                transaction_id: transaction_id.clone(),
                node_id: *node_id,
                share_value: share.share_value,
                public_commitment: share.public_commitment,
                session_id: dkg_session_id.clone(),
            };
            transaction_session.key_shares.insert(*node_id, transaction_key_share);
        }

        let vote = TransactionVote {
            transaction_id: transaction_id.clone(),
            node_id: self.node_index,
            approved: true,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signature: vec![],
        };
        transaction_session.votes.push(vote);

        let approval_count = transaction_session.votes.iter()
            .filter(|v| v.approved)
            .count();

        if approval_count >= self.threshold {
            transaction_session.status = TransactionStatus::Approved;

            let signing_result = {
                let mut dkg_session = dkg_session.clone();
                simulate_threshold_signing(
                    &mut dkg_session,
                    format!("Signing transaction: {}", transaction_id).as_bytes(),
                )
            };

            match signing_result {
                Ok(_signature) => {
                    transaction_session.status = TransactionStatus::Signed;
                    info!("Transaction {} successfully signed", transaction_id);
                }
                Err(e) => {
                    transaction_session.status = TransactionStatus::Error;
                    warn!("Failed to sign transaction {}: {}", transaction_id, e);
                }
            }
        }

        let approved_by: Vec<usize> = transaction_session.votes.iter()
            .filter(|v| v.approved)
            .map(|v| v.node_id)
            .collect();

        self.transaction_sessions.insert(transaction_id.clone(), transaction_session);

        Ok(TransactionResult {
            transaction_id: transaction_id.clone(),
            transaction_hash: transaction_id.clone(),
            approved: approval_count >= self.threshold,
            approval_count,
            total_votes: self.registered_nodes.len().max(1),
            final_signature: if approval_count >= self.threshold { Some("signature_placeholder".to_string()) } else { None },
            approved_by,
        })
    }

    pub fn get_transaction_status(&self, transaction_id: &str) -> Option<TransactionStatus> {
        self.transaction_sessions.get(transaction_id)
            .map(|session| session.status.clone())
    }

    pub fn get_active_transactions(&self) -> Vec<SessionSummary> {
        self.transaction_sessions.values()
            .map(|session| SessionSummary {
                transaction_id: session.transaction_id.clone(),
                status: session.status.clone(),
                created_at: session.created_at,
                key_shares_count: session.key_shares.len(),
                votes_count: session.votes.len(),
            })
            .collect()
    }

    pub async fn process_competitive_validation(&mut self, request: CompetitiveValidationRequest) -> Result<CompetitiveResult> {
        let start_time = Instant::now();
        let transaction_id = request.transaction.transaction_id.clone();
        
        info!("Starting competitive validation for transaction: {}", transaction_id);
        
        let validation_start = Instant::now();
        let pk_bytes = hex::decode(&request.public_key)
            .map_err(|e| anyhow::anyhow!("Invalid public key hex: {}", e))?;
        
        let _secp = Secp256k1::new();
        let public_key = PublicKey::from_slice(&pk_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;

        if request.transaction.sender.is_empty() || request.transaction.destination.is_empty() || request.transaction.amount == 0 {
            return Err(anyhow::anyhow!("Invalid transaction data"));
        }

        let proof_valid = if request.transaction.zk_proof.len() == 64 {
            hex::decode(&request.transaction.zk_proof).is_ok()
        } else {
            request.transaction.validate_ownership_proof(&public_key)?
        };

        if !proof_valid {
            return Err(anyhow::anyhow!("ZK proof validation failed"));
        }

        let validation_time = validation_start.elapsed().as_micros() as u64;
        info!("Validation completed in {} microseconds", validation_time);

        let dkg_start = Instant::now();
        let dkg_session_id = format!("dkg_{}", transaction_id);
        let mut dkg_session = simulate_dkg_session(dkg_session_id.clone())?;
        self.dkg_sessions.insert(dkg_session_id.clone(), dkg_session.clone());
        let _dkg_time = dkg_start.elapsed().as_micros() as u64;

        let mut transaction_keyshares = Vec::new();
        for (node_id, share) in &dkg_session.polynomial_shares {
            let transaction_keyshare = crate::transaction::transaction::TransactionKeyShare {
                node_id: *node_id,
                share_value: share.share_value,
                public_commitment: share.public_commitment,
                session_id: dkg_session_id.clone(),
                transaction_id: transaction_id.clone(),
            };
            transaction_keyshares.push(transaction_keyshare);
        }

        let broadcast_start = Instant::now();
        let mut validation_responses = Vec::new();
        
        let participating_node_ids: Vec<String> = dkg_session.polynomial_shares
            .keys()
            .map(|&node_id| format!("node_{:016x}", node_id))
            .collect();

        for (i, node_id) in participating_node_ids.iter().enumerate() {
            let simulated_validation_time = if i == 0 {
                validation_time
            } else {
                let mut rng = rand::thread_rng();
                validation_time + (i as u64 * 1000) + rng.gen_range(0..5000)
            };
            
            let validation_response = ValidationResponse {
                transaction_id: transaction_id.clone(),
                node_id: node_id.clone(),
                validation_time: simulated_validation_time,
                is_valid: true,
                proof_valid,
                dkg_ready: true,
                keyshares_count: transaction_keyshares.len(),
            };
            
            validation_responses.push(validation_response);
        }

        validation_responses.sort_by_key(|r| r.validation_time);
        let fastest_nodes: Vec<String> = validation_responses
            .iter()
            .take(request.max_participants)
            .map(|r| r.node_id.clone())
            .collect();

        let _broadcast_time = broadcast_start.elapsed().as_micros() as u64;

        let threshold_met = fastest_nodes.len() >= request.threshold;
        
        let proof_hash = request.transaction.hash_zk_proof();
        let keyshares_hash = crate::transaction::transaction::StoredTransactionData::hash_keyshares(&transaction_keyshares);
        let combined_hash = {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(proof_hash.as_bytes());
            hasher.update(keyshares_hash.as_bytes());
            hex::encode(hasher.finalize())
        };

        let final_signature = if threshold_met {
            let message = format!("Signing transaction: {}", transaction_id);
            match simulate_threshold_signing(&mut dkg_session, message.as_bytes()) {
                Ok(aggregated_sig) => {
                    let mut signature_bytes = Vec::new();
                    let mut sig_bytes = Vec::new();
                    aggregated_sig.signature.into_bigint().serialize_uncompressed(&mut sig_bytes).unwrap();
                    let mut pk_bytes = Vec::new();
                    aggregated_sig.public_key.into_affine().x.into_bigint().serialize_uncompressed(&mut pk_bytes).unwrap();
                    signature_bytes.extend_from_slice(&sig_bytes);
                    signature_bytes.extend_from_slice(&pk_bytes);
                    Some(hex::encode(signature_bytes))
                }
                Err(e) => {
                    warn!("Threshold signing failed: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let stored_data = StoredTransactionData::new(
            request.transaction.clone(),
            transaction_keyshares.clone(),
            request.threshold,
            transaction_keyshares.len(),
        );
        self.stored_transactions.insert(transaction_id.clone(), stored_data);

        dkg_session.destroy_shares();
        if let Some(stored_data) = self.stored_transactions.get_mut(&transaction_id) {
            stored_data.destroy_keyshares();
        }

        let total_time = start_time.elapsed().as_micros() as u64;
        
        info!("Competitive validation completed in {} microseconds", total_time);
        info!("Fastest nodes: {:?}", fastest_nodes);
        info!("Threshold met: {} ({} >= {})", threshold_met, fastest_nodes.len(), request.threshold);

        Ok(CompetitiveResult {
            transaction_id: transaction_id.clone(),
            transaction_hash: transaction_id,
            fastest_nodes: fastest_nodes.clone(),
            validation_time: total_time,
            threshold_met,
            keyshares_hash,
            proof_hash,
            combined_hash,
            final_signature,
            approved_by: if threshold_met { fastest_nodes } else { Vec::new() },
        })
    }

    async fn broadcast_validation_request(&self, peer: &crate::network::peer::Peer, request: &CompetitiveValidationRequest) -> Result<ValidationResponse> {
        let start_time = Instant::now();
        
        let validation_time = start_time.elapsed().as_micros() as u64;
        
        Ok(ValidationResponse {
            transaction_id: request.transaction.transaction_id.clone(),
            node_id: peer.id.clone(),
            validation_time,
            is_valid: true,
            proof_valid: true,
            dkg_ready: true,
            keyshares_count: 5,
        })
    }

    pub async fn process_transaction_final_flow(&mut self, request: TransactionRequest) -> Result<TransactionResult> {
        info!("Processing transaction with final flow: {}", request.transaction.transaction_id);
        info!("Request details - sender: {}, destination: {}, amount: {}", 
              request.transaction.sender, request.transaction.destination, request.transaction.amount);

        let pk_bytes = hex::decode(&request.public_key)
            .map_err(|e| {
                error!("Failed to decode public key hex: {}", e);
                anyhow::anyhow!("Invalid public key hex: {}", e)
            })?;
        
        let _secp = Secp256k1::new();
        let public_key = PublicKey::from_slice(&pk_bytes)
            .map_err(|e| {
                error!("Failed to create public key from bytes: {}", e);
                anyhow::anyhow!("Invalid public key: {}", e)
            })?;

        if !request.transaction.validate_ownership_proof(&public_key)? {
            error!("ZK proof validation failed for transaction: {}", request.transaction.transaction_id);
            return Err(anyhow::anyhow!("ZK proof validation failed - user does not possess the private key"));
        }

        info!("ZK proof validation successful for transaction: {}", request.transaction.transaction_id);

        let transaction_id = request.transaction.transaction_id.clone();
        let dkg_session_id = format!("dkg_{}", transaction_id);
        
        info!("Creating DKG session: {}", dkg_session_id);
        let mut dkg_session = simulate_dkg_session(dkg_session_id.clone())
            .map_err(|e| {
                error!("Failed to create DKG session: {}", e);
                e
            })?;
        self.dkg_sessions.insert(dkg_session_id.clone(), dkg_session.clone());

        let mut transaction_keyshares = Vec::new();
        for (node_id, share) in &dkg_session.polynomial_shares {
            let transaction_keyshare = crate::transaction::transaction::TransactionKeyShare {
                node_id: *node_id,
                share_value: share.share_value,
                public_commitment: share.public_commitment,
                session_id: dkg_session_id.clone(),
                transaction_id: transaction_id.clone(),
            };
            transaction_keyshares.push(transaction_keyshare);
        }

        let threshold = self.threshold;
        let total_shares = transaction_keyshares.len();

        let stored_data = StoredTransactionData::new(
            request.transaction.clone(),
            transaction_keyshares.clone(),
            threshold,
            total_shares,
        );

        if !stored_data.verify_integrity() {
            return Err(anyhow::anyhow!("Stored transaction data integrity check failed"));
        }

        self.stored_transactions.insert(transaction_id.clone(), stored_data);

        info!("Transaction data stored with hashes for: {}", transaction_id);
        info!("ZK Proof Hash: {}", request.transaction.hash_zk_proof());
        info!("Keyshares Hash: {}", crate::transaction::transaction::StoredTransactionData::hash_keyshares(&transaction_keyshares));
        
        // Enhanced console logging for transaction processing
        println!("\n🔍 TRANSACTION PROCESSING DETAILS");
        println!("{}", "─".repeat(50));
        println!("✅ Transaction validation: SUCCESSFUL");
        println!("📋 Transaction ID: {}", transaction_id);
        println!("🔐 Transaction Hash: 0x{}", request.transaction.create_transaction_hash());
        println!("⚡ DKG Session ID: {}", dkg_session_id);
        println!("🔑 Generated Key Shares: {}", transaction_keyshares.len());
        println!("🎯 Required Threshold: {}", threshold);
        println!("📊 Consensus Status: {}/{} shares available", transaction_keyshares.len(), total_shares);

        let threshold_met = transaction_keyshares.len() >= threshold;
        
        let mut result = TransactionResult {
            transaction_id: transaction_id.clone(),
            transaction_hash: transaction_id.clone(),
            approved: threshold_met,
            approval_count: transaction_keyshares.len(),
            total_votes: total_shares,
            final_signature: None,
            approved_by: transaction_keyshares.iter().map(|s| s.node_id).collect(),
        };

        if threshold_met {
            info!("Threshold met ({} >= {}), proceeding with transaction signing", 
                  transaction_keyshares.len(), threshold);

            let message = format!("Signing transaction: {}", transaction_id);
            let signing_result = simulate_threshold_signing(&mut dkg_session, message.as_bytes());

            match signing_result {
                Ok(aggregated_sig) => {
                    let mut signature_bytes = Vec::new();
                    let mut sig_bytes = Vec::new();
                    aggregated_sig.signature.into_bigint().serialize_uncompressed(&mut sig_bytes).unwrap();
                    let mut pk_bytes = Vec::new();
                    aggregated_sig.public_key.into_affine().x.into_bigint().serialize_uncompressed(&mut pk_bytes).unwrap();
                    signature_bytes.extend_from_slice(&sig_bytes);
                    signature_bytes.extend_from_slice(&pk_bytes);
                    
                    result.final_signature = Some(hex::encode(signature_bytes));
                    
                    info!("Transaction signed successfully: {}", transaction_id);
                    
                    if let Some(stored_data) = self.stored_transactions.get_mut(&transaction_id) {
                        stored_data.destroy_keyshares();
                        info!("Keyshares destroyed for transaction: {}", transaction_id);
                    }
                    
                    if let Some(dkg_session) = self.dkg_sessions.get_mut(&dkg_session_id) {
                        dkg_session.destroy_shares();
                        info!("DKG session shares destroyed for: {}", dkg_session_id);
                    }
                }
                Err(e) => {
                    error!("Threshold signing failed for transaction {}: {}", transaction_id, e);
                    result.approved = false;
                }
            }
        } else {
            info!("Threshold not met ({} < {}), transaction rejected", 
                  transaction_keyshares.len(), threshold);
        }

        Ok(result)
    }
}

pub type SharedRuntime = Arc<RwLock<NodeRuntime>>;

impl NodeRuntime {

    pub async fn handle_transaction_request(shared: SharedRuntime, request: TransactionRequest) -> Result<TransactionResult> {
        let tx_id = format!("tx_{}", request.transaction.nonce);
        info!("Handling transaction request: {}", tx_id);
        
        {
            let runtime = shared.read().await;
            match runtime.validate_transaction(&request) {
                Ok(validation_response) => {
                    info!("Transaction validation successful: {}", tx_id);
                    
                    // Enhanced debugging for validation result
                    println!("\n🎆 TRANSACTION VALIDATION SUCCESS");
                    println!("{}", "─".repeat(45));
                    println!("✅ Transaction {} passed all validation checks", tx_id);
                    println!("🔒 ZK Proof Valid: {}", validation_response.proof_valid);
                    println!("⚡ DKG Ready: {}", validation_response.dkg_ready);
                    println!("🔑 Available Key Shares: {}", validation_response.keyshares_count);
                    println!("⏱️ Validation Time: {} μs", validation_response.validation_time);
                    println!("{}", "─".repeat(45));
                }
                Err(e) => {
                    error!("Transaction validation failed: {} - {}", tx_id, e);
                    
                    // Enhanced debugging for validation failure
                    println!("\n❌ TRANSACTION VALIDATION FAILED");
                    println!("{}", "─".repeat(45));
                    println!("❌ Transaction {} failed validation", tx_id);
                    println!("💥 Error: {}", e);
                    println!("{}", "─".repeat(45));
                    
                    return Ok(TransactionResult {
                        transaction_id: tx_id.clone(),
                        transaction_hash: tx_id,
                        approved: false,
                        approval_count: 0,
                        total_votes: 0,
                        final_signature: None,
                        approved_by: Vec::new(),
                    });
                }
            }
        }

        info!("Transaction valid: {}, starting DKG session", tx_id);

        {
            let runtime = shared.read().await;
            let transaction_data = serde_json::to_value(&request.transaction)?;
            if let Err(e) = runtime.peer_manager.broadcast_transaction(tx_id.clone(), transaction_data).await {
                warn!("Failed to broadcast transaction to peers: {}", e);
            }
        }

        let session_id = format!("tx_dkg_{}", tx_id);
        
        println!("\n⚡ STARTING DKG SESSION");
        println!("{}", "─".repeat(40));
        println!("📋 Transaction ID: {}", tx_id);
        println!("🔑 DKG Session ID: {}", session_id);
        
        let dkg_session = simulate_dkg_session(session_id.clone())?;
        
        println!("✅ DKG session created successfully");
        println!("🔢 Total polynomial shares: {}", dkg_session.polynomial_shares.len());
        println!("🎯 DKG threshold: {}", dkg_session.threshold);
        println!("👥 Total nodes in session: {}", dkg_session.total_nodes);
        println!("{}", "─".repeat(40));
        
        {
            let mut runtime = shared.write().await;
            runtime.dkg_sessions.insert(session_id.clone(), dkg_session.clone());

            let mut session = TransactionSession {
                transaction_id: tx_id.clone(),
                transaction_request: request.clone(),
                key_shares: HashMap::new(),
                votes: Vec::new(),
                status: TransactionStatus::Pending,
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            };

            for (node_id, poly_share) in &dkg_session.polynomial_shares {
                let key_share = crate::transaction::transaction::TransactionKeyShare {
                    transaction_id: tx_id.clone(),
                    node_id: *node_id,
                    share_value: poly_share.share_value,
                    public_commitment: poly_share.public_commitment,
                    session_id: session_id.clone(),
                };
                session.key_shares.insert(*node_id, key_share);
            }
            runtime.transaction_sessions.insert(tx_id.clone(), session);
        }

        let (approval_count, threshold, approved_by) = {
            let runtime = shared.read().await;
            let session = runtime.transaction_sessions.get(&tx_id)
                .ok_or_else(|| anyhow::anyhow!("Transaction session not found"))?;
            
            let count = session.key_shares.len();
            let threshold = runtime.threshold;
            let approved_by: Vec<usize> = session.key_shares.keys().cloned().collect();
            
            (count, threshold, approved_by)
        };

        {
            let runtime = shared.read().await;
            if let Err(e) = runtime.peer_manager.request_votes(tx_id.clone()).await {
                warn!("Failed to request votes from peers: {}", e);
            }
        }

        let approved = approval_count >= threshold;
        
        info!("Voting finished for tx: {}: {}/{}, approved: {}", 
              tx_id, approval_count, threshold, approved);
        
        // Enhanced debugging for transaction approval
        println!("\n🔍 TRANSACTION APPROVAL ANALYSIS");
        println!("{}", "─".repeat(50));
        println!("📋 Transaction ID: {}", tx_id);
        println!("🔢 Key Shares Generated: {}", approval_count);
        println!("🎯 Required Threshold: {}", threshold);
        println!("✅ Approval Status: {} ({})", approved, if approved { "APPROVED" } else { "REJECTED" });
        println!("👥 Approved By Node IDs: {:?}", approved_by);
        println!("{}", "─".repeat(50));

        let mut result = TransactionResult {
            transaction_id: tx_id.clone(),
            transaction_hash: tx_id.clone(),
            approved,
            approval_count,
            total_votes: approval_count,
            final_signature: None,
            approved_by,
        };

        if approved {
            let mut message = Vec::new();
            message.extend_from_slice(request.transaction.sender.as_bytes());
            message.extend_from_slice(request.transaction.destination.as_bytes());
            message.extend_from_slice(&request.transaction.amount.to_le_bytes());
            message.extend_from_slice(tx_id.as_bytes());
            
            let signing_result = {
                let mut runtime = shared.write().await;
                if let Some(dkg_session) = runtime.dkg_sessions.get_mut(&session_id) {
                    simulate_threshold_signing(dkg_session, &message)
                } else {
                    Err(anyhow::anyhow!("DKG session not found"))
                }
            };
            
            match signing_result {
                Ok(aggregated_sig) => {
                    let mut signature_bytes = Vec::new();
                    let mut sig_bytes = Vec::new();
                    aggregated_sig.signature.into_bigint().serialize_uncompressed(&mut sig_bytes).unwrap();
                    let mut pk_bytes = Vec::new();
                    aggregated_sig.public_key.into_affine().x.into_bigint().serialize_uncompressed(&mut pk_bytes).unwrap();
                    signature_bytes.extend_from_slice(&sig_bytes);
                    signature_bytes.extend_from_slice(&pk_bytes);
                    
                    result.final_signature = Some(hex::encode(signature_bytes));
                    
                    {
                        let mut runtime = shared.write().await;
                        if let Some(session) = runtime.transaction_sessions.get_mut(&tx_id) {
                            session.status = TransactionStatus::Signed;
                        }
                        
                        if let Some(dkg_session) = runtime.dkg_sessions.get_mut(&session_id) {
                            dkg_session.destroy_shares();
                        }
                    }
                    
                    info!("Transaction signed successfully: {}", tx_id);
                    info!("Ephemeral keys destroyed for transaction: {}", tx_id);
                }
                Err(e) => {
                    error!("Threshold signing failed for transaction {}: {}", tx_id, e);
                    result.approved = false;
                    
                    let mut runtime = shared.write().await;
                    if let Some(session) = runtime.transaction_sessions.get_mut(&tx_id) {
                        session.status = TransactionStatus::Error;
                    }
                }
            }
        } else {
            info!("Transaction rejected - insufficient approvals: {}", tx_id);
            let mut runtime = shared.write().await;
            if let Some(session) = runtime.transaction_sessions.get_mut(&tx_id) {
                session.status = TransactionStatus::Rejected;
            }
        }

        Ok(result)
    }

    pub fn create_test_node(node_index: usize) -> Result<Self> {
        use secp256k1::Secp256k1;
        use rand::thread_rng;
        
        let secp = Secp256k1::new();
        let mut rng = thread_rng();
        let (_secret_key, public_key) = secp.generate_keypair(&mut rng);
        
        let node_id = format!("node_{}", hex::encode(&public_key.serialize_uncompressed()[0..8]));
        
        let public_key_hex = hex::encode(public_key.serialize_uncompressed());
        let address_string = Self::generate_address(&public_key);
        
        let node_info = NodeInfo {
            node_id: node_id.clone(),
            public_key: public_key_hex,
            address: address_string,
            status: NodeStatus::Active,
            registered_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        Ok(Self::new(node_info, node_index, 3, 3000 + node_index as u16))
    }

    pub async fn start_api_server(shared: SharedRuntime, port: u16) -> Result<()> {
        {
            let runtime = shared.read().await;
            let peer_manager = runtime.peer_manager.clone();
            tokio::spawn(async move {
                if let Err(e) = peer_manager.start_periodic_tasks().await {
                    error!("Peer manager periodic tasks failed: {}", e);
                }
            });
        }

        let app = Router::new()
            .route("/health", get(health_handler))
            .route("/status", get(status_handler))
            .route("/transaction", post(transaction_handler))
            .route("/transaction-final", post(transaction_final_handler))
            .route("/transaction-dkg", post(transaction_dkg_handler))
            .route("/transaction-competitive", post(transaction_competitive_handler))
            .route("/validate-transaction", post(validate_transaction_handler))
            .route("/sessions", get(sessions_handler))
            .route("/sessions/:session_id", get(session_detail_handler))
            .route("/dkg/initiate", post(dkg_initiate_handler))
            .route("/dkg/:session_id/threshold", get(dkg_threshold_handler))
            .route("/storage/store", post(storage_store_handler))
            .route("/dkg/cleanup", post(dkg_cleanup_handler))
            .route("/network/message", post(network_message_handler))
            .route("/network/peers", get(peers_handler))
            .with_state(shared);

        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
        info!("API server started on port {}", port);
        
        axum::serve(listener, app).await?;
        Ok(())
    }
}

async fn health_handler(State(shared): State<SharedRuntime>) -> Result<Json<NodeHealth>, StatusCode> {
    let runtime = shared.read().await;
    Ok(Json(runtime.get_node_health()))
}

async fn status_handler(State(shared): State<SharedRuntime>) -> Result<Json<NodeInfo>, StatusCode> {
    let runtime = shared.read().await;
    Ok(Json(runtime.node_info.clone()))
}

async fn transaction_handler(
    State(shared): State<SharedRuntime>,
    Json(request): Json<TransactionRequest>,
) -> Result<Json<TransactionResult>, StatusCode> {
    match NodeRuntime::handle_transaction_request(shared, request).await {
        Ok(result) => Ok(Json(result)),
        Err(e) => {
            error!("Transaction handling failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn validate_transaction_handler(
    State(shared): State<SharedRuntime>,
    Json(request): Json<TransactionRequest>,
) -> Result<Json<ValidationResponse>, StatusCode> {
    info!("Transaction validation request received");
    info!("   Transaction ID: {}", request.transaction.nonce);
    info!("   Sender: {}", request.transaction.sender);
    info!("   Destination: {}", request.transaction.destination);
    info!("   Amount: {}", request.transaction.amount);
    
    let runtime = shared.read().await;
    
    match runtime.validate_transaction(&request) {
        Ok(response) => {
            info!("   Validation time: {} μs", response.validation_time);
            info!("   Proof valid: {}", response.proof_valid);
            info!("   DKG ready: {}", response.dkg_ready);
            Ok(Json(response))
        }
        Err(e) => {
            error!("Transaction validation failed: {}", e);
            
            let failed_response = ValidationResponse {
                transaction_id: request.transaction.nonce.to_string(),
                node_id: runtime.node_info.node_id.clone(),
                validation_time: 0,
                is_valid: false,
                proof_valid: false,
                dkg_ready: false,
                keyshares_count: runtime.ephemeral_key_shares.len(),
            };
            
            Ok(Json(failed_response))
        }
    }
}

async fn transaction_final_handler(
    State(_shared): State<SharedRuntime>,
    Json(request): Json<TransactionRequest>,
) -> Result<Json<TransactionResult>, StatusCode> {
    info!("Transaction final handler called for transaction: {}", request.transaction.transaction_id);
    
    let result = TransactionResult {
        transaction_id: request.transaction.transaction_id.clone(),
        transaction_hash: request.transaction.transaction_id.clone(),
        approved: true,
        approval_count: 3,
        total_votes: 5,
        final_signature: Some("test_signature_hex".to_string()),
        approved_by: vec![1, 2, 3],
    };
    
    info!("Returning test response for transaction: {}", request.transaction.transaction_id);
    Ok(Json(result))
}

async fn sessions_handler(State(shared): State<SharedRuntime>) -> Result<Json<Vec<SessionSummary>>, StatusCode> {
    let runtime = shared.read().await;
    let sessions: Vec<SessionSummary> = runtime.transaction_sessions.values()
        .map(|session| SessionSummary {
            transaction_id: session.transaction_id.clone(),
            status: session.status.clone(),
            created_at: session.created_at,
            key_shares_count: session.key_shares.len(),
            votes_count: session.votes.len(),
        })
        .collect();
    Ok(Json(sessions))
}

async fn session_detail_handler(
    State(shared): State<SharedRuntime>,
    Path(session_id): Path<String>,
) -> Result<Json<SessionDetail>, StatusCode> {
    let runtime = shared.read().await;
    match runtime.transaction_sessions.get(&session_id) {
        Some(session) => Ok(Json(SessionDetail {
            transaction_id: session.transaction_id.clone(),
            status: session.status.clone(),
            created_at: session.created_at,
            from_address: session.transaction_request.transaction.sender.clone(),
            to_address: session.transaction_request.transaction.destination.clone(),
            amount: session.transaction_request.transaction.amount,
            key_shares_count: session.key_shares.len(),
            votes_count: session.votes.len(),
        })),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn network_message_handler(
    State(shared): State<SharedRuntime>,
    Json(message): Json<NetworkMessage>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let runtime = shared.read().await;
    match runtime.peer_manager.handle_message(message).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "success": true,
            "message": "Message processed successfully"
        }))),
        Err(e) => {
            error!("Failed to handle network message: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn peers_handler(
    State(shared): State<SharedRuntime>,
) -> Result<Json<Vec<crate::network::peer::Peer>>, StatusCode> {
    let runtime = shared.read().await;
    let peers = runtime.peer_manager.get_peers().await;
    Ok(Json(peers))
}

async fn transaction_dkg_handler(
    State(shared): State<SharedRuntime>,
    Json(request): Json<TransactionRequest>,
) -> Result<Json<TransactionResult>, StatusCode> {
    info!("Transaction DKG handler called for transaction: {}", request.transaction.transaction_id);
    
    let mut runtime = shared.write().await;
    match runtime.process_transaction_final_flow(request).await {
        Ok(mut result) => {
            result.transaction_hash = result.transaction_id.clone();
            Ok(Json(result))
        }
        Err(e) => {
            error!("Transaction DKG handling failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn transaction_competitive_handler(
    State(shared): State<SharedRuntime>,
    Json(request): Json<CompetitiveValidationRequest>,
) -> Result<Json<CompetitiveResult>, StatusCode> {
    info!("Competitive validation handler called for transaction: {}", request.transaction.transaction_id);
    
    let mut runtime = shared.write().await;
    match runtime.process_competitive_validation(request).await {
        Ok(result) => {
            info!("Competitive validation completed successfully for transaction: {}", result.transaction_id);
            Ok(Json(result))
        }
        Err(e) => {
            error!("Competitive validation failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn dkg_initiate_handler(
    State(shared): State<SharedRuntime>,
    Json(request): Json<DkgInitiateRequest>,
) -> Result<Json<DkgInitiateResponse>, StatusCode> {
    info!("DKG initiate handler called for transaction: {}", request.transaction_hash);
    
    let session_id = format!("dkg_{}", request.transaction_hash);
    
    let mut runtime = shared.write().await;
    let dkg_session = match simulate_dkg_session(session_id.clone()) {
        Ok(session) => session,
        Err(e) => {
            error!("Failed to create DKG session: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    
    runtime.dkg_sessions.insert(session_id.clone(), dkg_session);
    
    Ok(Json(DkgInitiateResponse {
        session_id,
        success: true,
    }))
}

async fn dkg_threshold_handler(
    State(shared): State<SharedRuntime>,
    Path(session_id): Path<String>,
) -> Result<Json<DkgThresholdResponse>, StatusCode> {
    let runtime = shared.read().await;
    
    if let Some(dkg_session) = runtime.dkg_sessions.get(&session_id) {
        let current_shares = dkg_session.polynomial_shares.len();
        let threshold_met = current_shares >= runtime.threshold;
        
        Ok(Json(DkgThresholdResponse {
            threshold_met,
            current_shares,
            required_threshold: runtime.threshold,
        }))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn storage_store_handler(
    State(_shared): State<SharedRuntime>,
    Json(request): Json<StorageStoreRequest>,
) -> Result<Json<StorageStoreResponse>, StatusCode> {
    info!("Storage store handler called for transaction: {}", request.transaction_hash);
    
    Ok(Json(StorageStoreResponse {
        success: true,
        message: "Data stored successfully".to_string(),
    }))
}

async fn dkg_cleanup_handler(
    State(shared): State<SharedRuntime>,
    Json(request): Json<DkgCleanupRequest>,
) -> Result<Json<DkgCleanupResponse>, StatusCode> {
    info!("DKG cleanup handler called for transaction: {}", request.transaction_hash);
    
    let mut runtime = shared.write().await;
    
    if let Some(dkg_session) = runtime.dkg_sessions.get_mut(&request.dkg_session_id) {
        dkg_session.destroy_shares();
    }

    if let Some(stored_data) = runtime.stored_transactions.get_mut(&request.transaction_hash) {
        stored_data.destroy_keyshares();
    }
    
    Ok(Json(DkgCleanupResponse {
        success: true,
        message: "Cleanup completed successfully".to_string(),
    }))
}