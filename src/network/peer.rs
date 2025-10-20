use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;
use tracing::{info, warn, error};
use reqwest::Client;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeStatus {
    Active,
    Inactive,
    Syncing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub id: String,
    pub public_key: String,
    pub address: String,
    pub status: NodeStatus,
    pub registered_at: u64,
    pub last_seen: u64,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMessage {
    pub message_type: MessageType,
    pub sender_id: String,
    pub recipient_id: Option<String>,
    pub payload: serde_json::Value,
    pub timestamp: u64,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    NodeDiscovery,
    TransactionBroadcast,
    VoteRequest,
    VoteResponse,
    Heartbeat,
    SyncRequest,
    SyncResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionVote {
    pub transaction_id: String,
    pub node_id: String,
    pub approved: bool,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub bootstrap_nodes: Vec<String>,
    pub max_peers: usize,
    pub heartbeat_interval: u64,
    pub discovery_interval: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            bootstrap_nodes: vec![
                "http://localhost:3000".to_string(),
                "http://localhost:3001".to_string(),
                "http://localhost:3002".to_string(),
                "http://localhost:3003".to_string(),
                // "http://localhost:3005".to_string(),
                // "http://localhost:3006".to_string(),
                // "http://localhost:3007".to_string(),
            ],
            max_peers: 10,
            heartbeat_interval: 30,
            discovery_interval: 60,
        }
    }
}

#[derive(Debug)]
pub struct PeerManager {
    pub peers: Arc<RwLock<HashMap<String, Peer>>>,
    pub config: NetworkConfig,
    pub client: Client,
    pub node_id: String,
    pub node_port: u16,
}

impl PeerManager {
    pub fn new(node_id: String, node_port: u16) -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            config: NetworkConfig::default(),
            client: Client::new(),
            node_id,
            node_port,
        }
    }

    pub async fn discover_peers(&self) -> Result<()> {
        info!("Starting peer discovery...");
        
        for bootstrap_url in &self.config.bootstrap_nodes {
            if bootstrap_url.contains(&format!(":{}", self.node_port)) {
                continue; // Skip self
            }
            
            match self.connect_to_peer(bootstrap_url).await {
                Ok(_) => info!("Successfully connected to peer: {}", bootstrap_url),
                Err(e) => warn!("Failed to connect to peer {}: {}", bootstrap_url, e),
            }
        }
        
        Ok(())
    }

    /// Connect to a specific peer
    pub async fn connect_to_peer(&self, peer_url: &str) -> Result<()> {
        let response = self.client
            .get(&format!("{}/status", peer_url))
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await?;

        if response.status().is_success() {
            let node_info: serde_json::Value = response.json().await?;
            
            let peer = Peer {
                id: node_info["node_id"].as_str().unwrap_or("unknown").to_string(),
                public_key: node_info["public_key"].as_str().unwrap_or("").to_string(),
                address: node_info["address"].as_str().unwrap_or("").to_string(),
                status: NodeStatus::Active,
                registered_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                last_seen: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                port: peer_url.split(':').last().unwrap_or("3000").parse().unwrap_or(3000),
            };

            let mut peers = self.peers.write().await;
            let peer_id = peer.id.clone();
            peers.insert(peer_id.clone(), peer);
            info!("Connected to peer: {}", peer_id);
        }

        Ok(())
    }

    pub async fn broadcast_message(&self, message: NetworkMessage) -> Result<()> {
        let peers = self.peers.read().await;
        let mut tasks = Vec::new();

        for (peer_id, peer) in peers.iter() {
            if peer_id != &self.node_id {
                let client = self.client.clone();
                let message = message.clone();
                let peer_url = format!("http://localhost:{}", peer.port);
                
                let task = tokio::spawn(async move {
                    Self::send_message_to_peer(client, &peer_url, message).await
                });
                tasks.push(task);
            }
        }

        for task in tasks {
            if let Err(e) = task.await {
                error!("Broadcast task failed: {}", e);
            }
        }

        Ok(())
    }

    async fn send_message_to_peer(client: Client, peer_url: &str, message: NetworkMessage) -> Result<()> {
        let response = client
            .post(&format!("{}/network/message", peer_url))
            .json(&message)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Failed to send message to peer: {}", response.status()));
        }

        Ok(())
    }

    pub async fn broadcast_transaction(&self, transaction_id: String, transaction_data: serde_json::Value) -> Result<()> {
        let message = NetworkMessage {
            message_type: MessageType::TransactionBroadcast,
            sender_id: self.node_id.clone(),
            recipient_id: None,
            payload: serde_json::json!({
                "transaction_id": transaction_id,
                "transaction_data": transaction_data
            }),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            signature: None,
        };

        self.broadcast_message(message).await?;
        info!("Broadcasted transaction {} to all peers", transaction_id);
        Ok(())
    }

    pub async fn request_votes(&self, transaction_id: String) -> Result<()> {
        let message = NetworkMessage {
            message_type: MessageType::VoteRequest,
            sender_id: self.node_id.clone(),
            recipient_id: None,
            payload: serde_json::json!({
                "transaction_id": transaction_id
            }),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            signature: None,
        };

        self.broadcast_message(message).await?;
        info!("Requested votes for transaction {} from all peers", transaction_id);
        Ok(())
    }

    pub async fn send_vote_response(&self, recipient_id: String, vote: TransactionVote) -> Result<()> {
        let message = NetworkMessage {
            message_type: MessageType::VoteResponse,
            sender_id: self.node_id.clone(),
            recipient_id: Some(recipient_id.clone()),
            payload: serde_json::to_value(vote)?,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            signature: None,
        };

        let peers = self.peers.read().await;
        if let Some(peer) = peers.get(&recipient_id) {
            let peer_url = format!("http://localhost:{}", peer.port);
            Self::send_message_to_peer(self.client.clone(), &peer_url, message).await?;
            info!("Sent vote response to peer: {}", recipient_id);
        }

        Ok(())
    }

    /// Handle incoming network messages
    pub async fn handle_message(&self, message: NetworkMessage) -> Result<()> {
        match message.message_type {
            MessageType::NodeDiscovery => {
                info!("Received node discovery from: {}", message.sender_id);
                let mut peers = self.peers.write().await;
                if !peers.contains_key(&message.sender_id) {
                    if let Some(peer_info) = message.payload.get("peer_info") {
                        let peer = Peer {
                            id: message.sender_id.clone(),
                            public_key: peer_info["public_key"].as_str().unwrap_or("").to_string(),
                            address: peer_info["address"].as_str().unwrap_or("").to_string(),
                            status: NodeStatus::Active,
                            registered_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                            last_seen: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                            port: peer_info["port"].as_u64().unwrap_or(3000) as u16,
                        };
                        peers.insert(message.sender_id, peer);
                    }
                }
            }
            MessageType::TransactionBroadcast => {
                info!("Received transaction broadcast from: {}", message.sender_id);
                if let Some(transaction_id) = message.payload.get("transaction_id") {
                    info!("Processing transaction: {}", transaction_id);
                }
            }
            MessageType::VoteRequest => {
                info!("Received vote request from: {}", message.sender_id);
                if let Some(transaction_id) = message.payload.get("transaction_id") {
                    info!("Voting on transaction: {}", transaction_id);
                    let vote = TransactionVote {
                        transaction_id: transaction_id.as_str().unwrap_or("").to_string(),
                        node_id: self.node_id.clone(),
                        approved: true,
                        timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                        signature: "demo_signature".to_string(),
                    };
                    self.send_vote_response(message.sender_id, vote).await?;
                }
            }
            MessageType::VoteResponse => {
                info!("Received vote response from: {}", message.sender_id);
                if let Ok(vote) = serde_json::from_value::<TransactionVote>(message.payload) {
                    info!("Vote from {}: {} for transaction {}", 
                          message.sender_id, 
                          if vote.approved { "APPROVED" } else { "REJECTED" },
                          vote.transaction_id);
                }
            }
            MessageType::Heartbeat => {
                let mut peers = self.peers.write().await;
                if let Some(peer) = peers.get_mut(&message.sender_id) {
                    peer.last_seen = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                }
            }
            MessageType::SyncRequest => {
                info!("Received sync request from: {}", message.sender_id);
            }
            MessageType::SyncResponse => {
                info!("Received sync response from: {}", message.sender_id);
            }
        }

        Ok(())
    }

    pub async fn start_periodic_tasks(&self) -> Result<()> {
        let peer_manager_heartbeat = self.clone();
        let peer_manager_discovery = self.clone();
        
        let heartbeat_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(peer_manager_heartbeat.config.heartbeat_interval)
            );
            
            loop {
                interval.tick().await;
                
                let message = NetworkMessage {
                    message_type: MessageType::Heartbeat,
                    sender_id: peer_manager_heartbeat.node_id.clone(),
                    recipient_id: None,
                    payload: serde_json::json!({}),
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                    signature: None,
                };
                
                if let Err(e) = peer_manager_heartbeat.broadcast_message(message).await {
                    error!("Heartbeat failed: {}", e);
                }
            }
        });

        let discovery_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(peer_manager_discovery.config.discovery_interval)
            );
            
            loop {
                interval.tick().await;
                
                if let Err(e) = peer_manager_discovery.discover_peers().await {
                    error!("Peer discovery failed: {}", e);
                }
            }
        });

        tokio::select! {
            _ = heartbeat_task => {},
            _ = discovery_task => {},
        }

        Ok(())
    }

    pub async fn get_peers(&self) -> Vec<Peer> {
        let peers = self.peers.read().await;
        peers.values().cloned().collect()
    }

    pub async fn get_peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.len()
    }
}

impl Clone for PeerManager {
    fn clone(&self) -> Self {
        Self {
            peers: Arc::clone(&self.peers),
            config: self.config.clone(),
            client: self.client.clone(),
            node_id: self.node_id.clone(),
            node_port: self.node_port,
        }
    }
}

impl Peer {
    pub fn new(id: String, public_key: String, address: String, port: u16) -> Self {
        Self { 
            id, 
            public_key, 
            address, 
            status: NodeStatus::Active, 
            registered_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            last_seen: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            port,
        }
    }

    pub fn get_id(&self) -> String {
        self.id.clone()
    }
}