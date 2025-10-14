use secp256k1::{SecretKey, PublicKey};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use hex;
use crate::dkg::ephemeral_dkg::{DkgSession, simulate_dkg_session, simulate_threshold_signing, PartialSignature};
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use ark_bls12_381::{Fr, G1Projective};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub public_key: String,
    pub address: String,
    pub status: NodeStatus,
    pub registered_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeStatus {
    Active,
    Inactive,
    Suspended,
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
    pub transaction_id: String,
    pub from_address: String,
    pub to_address: String,
    pub amount: u64,
    pub proof_data: Vec<u8>,        // ZK proof: "I own this private key and want to transact"
    pub public_key: String,
    pub challenge: String,
}

#[derive(Debug, Clone)]
pub struct TransactionKeyShare {
    pub transaction_id: String,
    pub node_id: usize,
    pub share_value: Fr,
    pub public_commitment: G1Projective,
    pub session_id: String,
    pub threshold: usize,
    pub total_shares: usize,
    pub is_used: bool,               // Track if this share has been used
}

#[derive(Debug, Clone)]
pub struct TransactionSession {
    pub transaction_id: String,
    pub transaction_request: TransactionRequest,
    pub key_shares: HashMap<usize, TransactionKeyShare>,
    pub votes: Vec<TransactionVote>,
    pub status: TransactionStatus,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionStatus {
    Pending,        // Waiting for key generation and voting
    Approved,       // Approved by threshold nodes
    Signed,         // Successfully signed
    Completed,      // Transaction completed, keys burned
    Failed,         // Transaction failed
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionVote {
    pub transaction_id: String,
    pub node_id: String,
    pub approved: bool,
    pub timestamp: u64,
    pub signature: Vec<u8>, // Node's signature on the vote
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionResult {
    pub transaction_id: String,
    pub approved: bool,
    pub approval_count: usize,
    pub total_votes: usize,
    pub final_signature: Option<Vec<u8>>,
    pub approved_by: Vec<String>,
}

pub struct NodeManager {
    pub node_info: NodeInfo,
    pub ephemeral_shares: HashMap<String, EphemeralKeyShare>, // session_id -> share
    pub registered_nodes: HashMap<String, NodeInfo>,
    pub node_index: usize, // Index for DKG participation
}

pub struct NetworkCoordinator {
    pub nodes: Vec<NodeManager>,
    pub transaction_sessions: HashMap<String, TransactionSession>,
    pub threshold: usize,
    pub master_private_key: Option<SecretKey>,  // Master key for generating transaction-specific keys
    pub dkg_sessions: HashMap<String, DkgSession>,  // Ephemeral DKG sessions per transaction
}

impl NodeManager {
    pub fn new(node_id: String, public_key: PublicKey, node_index: usize) -> Self {
        let address = hex::encode(public_key.serialize_uncompressed());
        let node_info = NodeInfo {
            node_id: node_id.clone(),
            public_key: hex::encode(public_key.serialize_uncompressed()),
            address,
            status: NodeStatus::Active,
            registered_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        Self {
            node_info,
            ephemeral_shares: HashMap::new(),
            registered_nodes: HashMap::new(),
            node_index,
        }
    }

    pub fn register_node(&mut self) -> Result<()> {
        println!("Registering node: {}", self.node_info.node_id);
        println!("Public Key: 0x{}", self.node_info.public_key);
        println!("Address: 0x{}", self.node_info.address);
        println!("Status: {:?}", self.node_info.status);
        println!("Registered at: {}", self.node_info.registered_at);
        
        // Simulate adding to network registry
        self.registered_nodes.insert(self.node_info.node_id.clone(), self.node_info.clone());
        
        println!("Node {} successfully registered!", self.node_info.node_id);
        Ok(())
    }

    pub fn receive_ephemeral_share(&mut self, share: EphemeralKeyShare) -> Result<()> {
        println!("Node {} receiving ephemeral share for session {}", 
                self.node_info.node_id, share.session_id);
        
        // Validate share
        if share.node_id != self.node_index + 1 {
            return Err(anyhow::anyhow!("Share node_id {} doesn't match node index {}", 
                share.node_id, self.node_index));
        }
        
        // Store the ephemeral share
        self.ephemeral_shares.insert(share.session_id.clone(), share.clone());
        
        let mut share_bytes = Vec::new();
        share.share_value.into_bigint().serialize_uncompressed(&mut share_bytes).unwrap();
        println!("Ephemeral share stored successfully for session {}", share.session_id);
        println!("Share value: 0x{}", hex::encode(share_bytes));
        println!("Current ephemeral shares held: {}", self.ephemeral_shares.len());
        
        Ok(())
    }

    pub fn validate_user_proof(&self, request: &ProofValidationRequest) -> Result<ProofValidationResponse> {
        println!("Node {} validating proof from user", self.node_info.node_id);
        
        // Parse public key
        let pk_bytes = hex::decode(&request.public_key)
            .map_err(|e| anyhow::anyhow!("Invalid public key hex: {}", e))?;
        
        let public_key = PublicKey::from_slice(&pk_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;
        
        // For this prototype, we'll simulate proof validation
        // In a real implementation, you would verify the ZK proof here
        let is_valid = self.simulate_proof_validation(&request, &public_key);
        
        let response = ProofValidationResponse {
            is_valid,
            node_id: self.node_info.node_id.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        if is_valid {
            println!("Proof validation successful for user with public key: 0x{}", request.public_key);
        } else {
            println!("Proof validation failed for user with public key: 0x{}", request.public_key);
        }
        
        Ok(response)
    }

    fn simulate_proof_validation(&self, request: &ProofValidationRequest, _public_key: &PublicKey) -> bool {
        // Simulate proof validation logic
        // In a real implementation, this would verify the ZK proof
        println!("Simulating proof validation...");
        println!("Challenge: {}", request.challenge);
        println!("Proof data length: {} bytes", request.proof_data.len());
        
        // For prototype, accept if proof data is not empty and challenge is valid
        !request.proof_data.is_empty() && !request.challenge.is_empty()
    }

    pub fn participate_in_threshold_signing(&self, session_id: &str, message: &[u8]) -> Result<PartialSignature> {
        println!("Node {} participating in threshold signing for session {}", 
                self.node_info.node_id, session_id);
        
        // Check if we have an ephemeral share for this session
        let ephemeral_share = self.ephemeral_shares.get(session_id)
            .ok_or_else(|| anyhow::anyhow!("No ephemeral share found for session {}", session_id))?;
        
        println!("  - Using ephemeral share for session {}", session_id);
        
        // Convert message to field element for signing
        let message_hash = Fr::from_le_bytes_mod_order(message);
        
        // Generate partial signature using our share
        let signature_share = ephemeral_share.share_value * message_hash;
        
        let partial_sig = PartialSignature {
            node_id: self.node_index + 1,
            signature_share,
            public_commitment: ephemeral_share.public_commitment,
        };
        
        let mut sig_bytes = Vec::new();
        signature_share.into_bigint().serialize_uncompressed(&mut sig_bytes).unwrap();
        println!("  - Generated partial signature: 0x{}", hex::encode(sig_bytes));
        
        Ok(partial_sig)
    }

    pub fn get_node_status(&self) -> &NodeStatus {
        &self.node_info.status
    }

    pub fn get_held_ephemeral_shares_count(&self) -> usize {
        self.ephemeral_shares.len()
    }
    
    pub fn has_ephemeral_share_for_session(&self, session_id: &str) -> bool {
        self.ephemeral_shares.contains_key(session_id)
    }

    pub fn list_registered_nodes(&self) {
        println!("Registered nodes in network:");
        for (node_id, node_info) in &self.registered_nodes {
            println!("  - {}: {:?} (Address: 0x{})", 
                    node_id, node_info.status, node_info.address);
        }
    }

}

pub fn create_test_node(node_index: usize) -> Result<NodeManager> {
    use secp256k1::Secp256k1;
    use rand::thread_rng;
    
    let secp = Secp256k1::new();
    let mut rng = thread_rng();
    let (_secret_key, public_key) = secp.generate_keypair(&mut rng);
    
    let node_id = format!("node_{}", hex::encode(&public_key.serialize_uncompressed()[0..8]));
    
    Ok(NodeManager::new(node_id, public_key, node_index))
}

pub fn distribute_ephemeral_shares_to_nodes(
    nodes: &mut Vec<NodeManager>, 
    dkg_session: &DkgSession
) -> Result<()> {
    println!("=== DISTRIBUTING EPHEMERAL SHARES ===");
    println!("Session ID: {}", dkg_session.session_id);
    println!("Threshold: {}", dkg_session.threshold);
    println!("Total nodes: {}", nodes.len());
    
    // Distribute polynomial shares from the DKG session to nodes
    for (node_index, node) in nodes.iter_mut().enumerate() {
        let node_id = node_index + 1;
        
        if let Some(polynomial_share) = dkg_session.polynomial_shares.get(&node_id) {
            let ephemeral_share = EphemeralKeyShare {
                node_id,
                share_value: polynomial_share.share_value,
                public_commitment: polynomial_share.public_commitment,
                session_id: dkg_session.session_id.clone(),
                is_used: false,
            };
            
            println!("Distributing ephemeral share to node {} (index {})", 
                    node.node_info.node_id, node_index);
            
            node.receive_ephemeral_share(ephemeral_share)?;
        }
    }
    
    println!("Successfully distributed ephemeral shares to {} nodes", nodes.len());
    
    // Debug: Show final distribution
    println!("Final ephemeral share distribution:");
    for (i, node) in nodes.iter().enumerate() {
        println!("  Node {} ({}): {} ephemeral shares", 
                i + 1, 
                node.node_info.node_id,
                node.ephemeral_shares.len());
        for (session_id, share) in &node.ephemeral_shares {
            let mut share_bytes = Vec::new();
            share.share_value.into_bigint().serialize_uncompressed(&mut share_bytes).unwrap();
            println!("    - Session {}: 0x{}", session_id, hex::encode(share_bytes));
        }
    }
    
    Ok(())
}

impl NetworkCoordinator {
    pub fn new(nodes: Vec<NodeManager>, threshold: usize, master_private_key: SecretKey) -> Self {
        Self {
            nodes,
            transaction_sessions: HashMap::new(),
            threshold,
            master_private_key: Some(master_private_key),
            dkg_sessions: HashMap::new(),
        }
    }

    pub fn submit_transaction_request(&mut self, request: TransactionRequest) -> Result<TransactionResult> {
        println!("=== NEW TRANSACTION REQUEST WITH EPHEMERAL DKG ===");
        println!("Transaction ID: {}", request.transaction_id);
        println!("From: {}", request.from_address);
        println!("To: {}", request.to_address);
        println!("Amount: {}", request.amount);
        println!("Threshold required: {}", self.threshold);
        
        // Step 1: Validate user's proof of ownership
        println!("\n=== STEP 1: VALIDATING USER PROOF ===");
        let proof_valid = self.validate_user_ownership_proof(&request)?;
        
        if !proof_valid {
            return Ok(TransactionResult {
                transaction_id: request.transaction_id.clone(),
                approved: false,
                approval_count: 0,
                total_votes: 0,
                final_signature: None,
                approved_by: Vec::new(),
            });
        }
        
        println!("User proof validation: SUCCESS");
        
        // Step 2: Run ephemeral DKG session
        println!("\n=== STEP 2: RUNNING EPHEMERAL DKG SESSION ===");
        let dkg_session_id = format!("dkg_{}", request.transaction_id);
        let mut dkg_session = simulate_dkg_session(dkg_session_id.clone())?;
        
        // Store DKG session
        self.dkg_sessions.insert(dkg_session_id.clone(), dkg_session.clone());
        
        // Distribute ephemeral shares to nodes
        distribute_ephemeral_shares_to_nodes(&mut self.nodes, &dkg_session)?;
        
        // Step 3: Create transaction session
        let mut session = TransactionSession {
            transaction_id: request.transaction_id.clone(),
            transaction_request: request.clone(),
            key_shares: HashMap::new(), // Will be populated with ephemeral shares
            votes: Vec::new(),
            status: TransactionStatus::Pending,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        // Convert ephemeral shares to transaction key shares
        for (i, node) in self.nodes.iter().enumerate() {
            if let Some(ephemeral_share) = node.ephemeral_shares.get(&dkg_session_id) {
                let transaction_share = TransactionKeyShare {
                    transaction_id: request.transaction_id.clone(),
                    node_id: i + 1,
                    share_value: ephemeral_share.share_value,
                    public_commitment: ephemeral_share.public_commitment,
                    session_id: dkg_session_id.clone(),
                    threshold: self.threshold,
                    total_shares: self.nodes.len(),
                    is_used: false,
                };
                session.key_shares.insert(i + 1, transaction_share);
            }
        }
        
        // Step 4: Request votes from nodes
        println!("\n=== STEP 3: REQUESTING VOTES FROM NODES ===");
        for (i, node) in self.nodes.iter().enumerate() {
            println!("Requesting vote from Node {}: {}", i + 1, node.node_info.node_id);
            
            let vote = self.request_vote_from_node(node, &request)?;
            session.votes.push(vote);
        }
        
        // Step 5: Count votes and determine result
        let approval_count = session.votes.iter().filter(|v| v.approved).count();
        let approved_by: Vec<String> = session.votes.iter()
            .filter(|v| v.approved)
            .map(|v| v.node_id.clone())
            .collect();
        
        println!("\n=== VOTING RESULTS ===");
        println!("Total votes: {}", session.votes.len());
        println!("Approvals: {}", approval_count);
        println!("Threshold: {}", self.threshold);
        
        for vote in &session.votes {
            println!("  - {}: {}", vote.node_id, if vote.approved { "APPROVED" } else { "REJECTED" });
        }
        
        let approved = approval_count >= self.threshold;
        
        let mut result = TransactionResult {
            transaction_id: request.transaction_id.clone(),
            approved,
            approval_count,
            total_votes: session.votes.len(),
            final_signature: None,
            approved_by,
        };
        
        // Step 6: If approved, perform threshold signing with ephemeral DKG keys
        if approved {
            println!("\n=== STEP 4: THRESHOLD SIGNING WITH EPHEMERAL DKG KEYS ===");
            session.status = TransactionStatus::Approved;
            
            // Create transaction message
            let mut message = Vec::new();
            message.extend_from_slice(session.transaction_request.from_address.as_bytes());
            message.extend_from_slice(session.transaction_request.to_address.as_bytes());
            message.extend_from_slice(&session.transaction_request.amount.to_le_bytes());
            message.extend_from_slice(session.transaction_request.transaction_id.as_bytes());
            
            // Perform threshold signing with DKG
            match simulate_threshold_signing(&mut dkg_session, &message) {
                Ok(aggregated_sig) => {
                    // Convert aggregated signature to bytes for result
                    let mut signature_bytes = Vec::new();
                    let mut sig_bytes = Vec::new();
                    aggregated_sig.signature.into_bigint().serialize_uncompressed(&mut sig_bytes).unwrap();
                    let mut pk_bytes = Vec::new();
                    aggregated_sig.public_key.into_affine().x.into_bigint().serialize_uncompressed(&mut pk_bytes).unwrap();
                    signature_bytes.extend_from_slice(&sig_bytes);
                    signature_bytes.extend_from_slice(&pk_bytes);
                    
                    result.final_signature = Some(signature_bytes);
                    session.status = TransactionStatus::Signed;
                    println!("Transaction signed successfully with ephemeral DKG keys!");
                    let mut global_pk_bytes = Vec::new();
                    aggregated_sig.public_key.into_affine().x.into_bigint().serialize_uncompressed(&mut global_pk_bytes).unwrap();
                    println!("Global public key: 0x{}", 
                            hex::encode(global_pk_bytes));
                    
                    // Step 7: Destroy ephemeral keys
                    println!("\n=== STEP 5: DESTROYING EPHEMERAL KEYS ===");
                    dkg_session.destroy_shares();
                    session.status = TransactionStatus::Completed;
                    println!("Ephemeral DKG keys have been destroyed!");
                }
                Err(e) => {
                    println!("Transaction signing failed: {:?}", e);
                    session.status = TransactionStatus::Failed;
                    result.approved = false;
                }
            }
        } else {
            println!("Transaction rejected - insufficient approvals");
            session.status = TransactionStatus::Failed;
        }
        
        // Store the session
        self.transaction_sessions.insert(request.transaction_id.clone(), session);
        
        Ok(result)
    }

    fn validate_user_ownership_proof(&self, request: &TransactionRequest) -> Result<bool> {
        println!("Validating user's proof of ownership...");
        
        // Parse public key
        let pk_bytes = hex::decode(&request.public_key)
            .map_err(|e| anyhow::anyhow!("Invalid public key hex: {}", e))?;
        
        let _public_key = PublicKey::from_slice(&pk_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;
        
        // For this prototype, we'll simulate proof validation
        // In a real implementation, you would verify the ZK proof here
        println!("Challenge: {}", request.challenge);
        println!("Proof data length: {} bytes", request.proof_data.len());
        
        // Simulate proof validation - accept if proof data is not empty and challenge is valid
        let is_valid = !request.proof_data.is_empty() && !request.challenge.is_empty();
        
        if is_valid {
            println!("User ownership proof validation: SUCCESS");
        } else {
            println!("User ownership proof validation: FAILED");
        }
        
        Ok(is_valid)
    }


    fn perform_transaction_signing(&self, session: &mut TransactionSession, dkg_session: &mut DkgSession) -> Result<Vec<u8>> {
        println!("Performing collaborative signing with ephemeral DKG keys...");
        
        // Get approved nodes
        let approved_nodes: Vec<&NodeManager> = session.votes.iter()
            .filter(|v| v.approved)
            .filter_map(|v| self.nodes.iter().find(|n| n.node_info.node_id == v.node_id))
            .collect();
        
        println!("Approved nodes for signing: {}", approved_nodes.len());
        
        if approved_nodes.len() < self.threshold {
            return Err(anyhow::anyhow!("Not enough approved nodes for signing"));
        }
        
        // Create transaction message for signing
        let mut message = Vec::new();
        message.extend_from_slice(session.transaction_request.from_address.as_bytes());
        message.extend_from_slice(session.transaction_request.to_address.as_bytes());
        message.extend_from_slice(&session.transaction_request.amount.to_le_bytes());
        message.extend_from_slice(session.transaction_request.transaction_id.as_bytes());
        
        // Collect partial signatures from approved nodes
        let mut partial_signatures = Vec::new();
        for node in approved_nodes.iter().take(self.threshold) {
            println!("Collecting partial signature from node: {}", node.node_info.node_id);
            
            // Generate partial signature using ephemeral DKG
            match node.participate_in_threshold_signing(&dkg_session.session_id, &message) {
                Ok(partial_sig) => {
                    partial_signatures.push(partial_sig);
                    println!("  - Partial signature collected from node {}", node.node_info.node_id);
                }
                Err(e) => {
                    println!("  - Failed to get partial signature from node {}: {:?}", 
                            node.node_info.node_id, e);
                    return Err(e);
                }
            }
        }
        
        println!("Total partial signatures collected: {}", partial_signatures.len());
        
        // Aggregate signatures using ephemeral DKG
        match simulate_threshold_signing(dkg_session, &message) {
            Ok(aggregated_sig) => {
                println!("Transaction signed successfully with ephemeral DKG!");
                
                // Convert aggregated signature to bytes
                let mut signature_bytes = Vec::new();
                let mut sig_bytes = Vec::new();
                aggregated_sig.signature.into_bigint().serialize_uncompressed(&mut sig_bytes).unwrap();
                let mut pk_bytes = Vec::new();
                aggregated_sig.public_key.into_affine().x.into_bigint().serialize_uncompressed(&mut pk_bytes).unwrap();
                signature_bytes.extend_from_slice(&sig_bytes);
                signature_bytes.extend_from_slice(&pk_bytes);
                
                println!("Aggregated signature: 0x{}", hex::encode(&signature_bytes));
                
                Ok(signature_bytes)
            }
            Err(e) => {
                println!("Failed to aggregate signatures: {:?}", e);
                Err(e)
            }
        }
    }

    fn burn_transaction_keys(&self, session: &mut TransactionSession) {
        println!("Burning ephemeral keys for transaction: {}", session.transaction_id);
        
        for (node_id, share) in &mut session.key_shares {
            if !share.is_used {
                println!("Burning ephemeral share (Node: {})", node_id);
                share.is_used = true;
                // In a real implementation, you would securely delete/overwrite the key data
                share.share_value = Fr::zero(); // Zero out the share value
            }
        }
        
        println!("All ephemeral keys have been burned!");
    }

    fn request_vote_from_node(&self, node: &NodeManager, transaction: &TransactionRequest) -> Result<TransactionVote> {
        println!("  - Node {} validating proof...", node.node_info.node_id);
        
        let proof_request = ProofValidationRequest {
            proof_data: transaction.proof_data.clone(),
            public_key: transaction.public_key.clone(),
            challenge: transaction.challenge.clone(),
        };
        
        let validation_response = node.validate_user_proof(&proof_request)?;
        
        let vote = TransactionVote {
            transaction_id: transaction.transaction_id.clone(),
            node_id: node.node_info.node_id.clone(),
            approved: validation_response.is_valid,
            timestamp: validation_response.timestamp,
            signature: vec![0x01, 0x02, 0x03], // Simplified signature for prototype
        };
        
        println!("  - Node {} vote: {}", node.node_info.node_id, 
                if vote.approved { "APPROVED" } else { "REJECTED" });
        
        Ok(vote)
    }

    pub fn get_network_status(&self) {
        println!("\n=== NETWORK STATUS ===");
        println!("Total nodes: {}", self.nodes.len());
        println!("Threshold: {}", self.threshold);
        println!("Active transaction sessions: {}", self.transaction_sessions.len());
        println!("Active DKG sessions: {}", self.dkg_sessions.len());
        
        for (i, node) in self.nodes.iter().enumerate() {
            println!("Node {}: {} (Ephemeral Shares: {}, Status: {:?})", 
                    i + 1, 
                    node.node_info.node_id,
                    node.ephemeral_shares.len(),
                    node.get_node_status());
        }
        
        // Show transaction session status
        for (tx_id, session) in &self.transaction_sessions {
            println!("Transaction {}: {:?}", tx_id, session.status);
        }
        
        // Show DKG session status
        for (dkg_id, dkg_session) in &self.dkg_sessions {
            println!("DKG Session {}: Completed: {}", dkg_id, dkg_session.is_completed);
        }
    }
}

