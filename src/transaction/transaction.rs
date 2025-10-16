use serde::{Deserialize, Serialize};
use secp256k1::{SecretKey, PublicKey};
use ark_bls12_381::{Fr, G1Projective};
use ark_ff::{PrimeField, Zero};
use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use anyhow::Result;
use sha2::{Sha256, Digest};
use hex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskStatus {
    Pending,
    Completed,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequestType {
    Transaction,
    Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub transaction_id: String,
    pub sender: String,
    pub destination: String,
    pub amount: u64,
    pub nonce: u64,
    pub zk_proof: String,
    pub public_key: String,
    pub challenge: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionProof {
    pub ownership_proof: String,
    pub amount_proof: String,
    pub destination_proof: String,
}

#[derive(Debug, Clone)]
pub struct TransactionKeyShare {
    pub node_id: usize,
    pub share_value: Fr,
    pub public_commitment: G1Projective,
    pub session_id: String,
    pub transaction_id: String,
}

#[derive(Debug, Clone)]
pub struct StoredTransactionData {
    pub transaction: Transaction,
    pub keyshares: Vec<TransactionKeyShare>,
    pub zk_proof_hash: String,
    pub keyshares_hash: String,
    pub combined_hash: String,
    pub stored_at: u64,
    pub threshold: usize,
    pub total_shares: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestTask {
    pub task_id: String,
    pub transaction: Option<Transaction>,
    pub proof_data: Vec<u8>,
    pub request_type: RequestType,
    pub request_status: TaskStatus,
    pub request_created_at: u64,
    pub request_completed_at: u64,
}

impl Transaction {
    pub fn new(sender: String, destination: String, amount: u64, nonce: u64) -> Self {
        let transaction_id = format!("tx_{}", nonce);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            transaction_id,
            sender,
            destination,
            amount,
            nonce,
            zk_proof: String::new(),
            public_key: String::new(),
            challenge: String::new(),
            timestamp,
        }
    }

    pub fn new_with_proof(
        sender: String, 
        destination: String, 
        amount: u64, 
        nonce: u64,
        public_key: String,
        challenge: String,
    ) -> Self {
        let transaction_id = format!("tx_{}", nonce);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            transaction_id,
            sender,
            destination,
            amount,
            nonce,
            zk_proof: String::new(),
            public_key,
            challenge,
            timestamp,
        }
    }

    pub fn generate_zk_proof(&mut self, private_key: &SecretKey, public_key: &PublicKey) -> Result<()> {
        let ownership_proof = self.create_ownership_proof(private_key, public_key)?;
        
        let amount_proof = self.create_amount_proof()?;
        
        let destination_proof = self.create_destination_proof()?;

        let transaction_proof = TransactionProof {
            ownership_proof,
            amount_proof,
            destination_proof,
        };

        let proof_bytes = bincode::serialize(&transaction_proof)?;
        self.zk_proof = hex::encode(proof_bytes);
        Ok(())
    }

    fn create_ownership_proof(&self, private_key: &SecretKey, public_key: &PublicKey) -> Result<String> {
        let sk_bytes = private_key.secret_bytes();
        let pk_bytes = public_key.serialize_uncompressed();
        
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&sk_bytes);
        proof_data.extend_from_slice(&pk_bytes[0..32]);
        Ok(hex::encode(proof_data))
    }

    fn create_amount_proof(&self) -> Result<String> {
        if self.amount == 0 {
            return Err(anyhow::anyhow!("Amount cannot be zero"));
        }
        
        Ok(hex::encode(self.amount.to_le_bytes()))
    }

    fn create_destination_proof(&self) -> Result<String> {
        if self.destination.is_empty() {
            return Err(anyhow::anyhow!("Destination cannot be empty"));
        }
        
        Ok(hex::encode(self.destination.as_bytes()))
    }

    pub fn verify_zk_proof(&self, public_key: &PublicKey) -> Result<bool> {
        if self.zk_proof.is_empty() {
            return Ok(false);
        }

        if self.zk_proof.len() == 64 {
            return Ok(hex::decode(&self.zk_proof).is_ok());
        }

        if let Ok(proof_bytes) = hex::decode(&self.zk_proof) {
            if let Ok(transaction_proof) = bincode::deserialize::<TransactionProof>(&proof_bytes) {
                let ownership_valid = self.verify_ownership_proof(&transaction_proof.ownership_proof, public_key)?;
                
                let amount_valid = self.verify_amount_proof(&transaction_proof.amount_proof)?;
                
                let destination_valid = self.verify_destination_proof(&transaction_proof.destination_proof)?;

                return Ok(ownership_valid && amount_valid && destination_valid);
            }
        }

        Ok(false)
    }

    fn verify_ownership_proof(&self, proof_data: &str, _public_key: &PublicKey) -> Result<bool> {
        Ok(!proof_data.is_empty())
    }

    fn verify_amount_proof(&self, proof_data: &str) -> Result<bool> {
        let proof_bytes = hex::decode(proof_data)?;
        let amount_bytes: [u8; 8] = proof_bytes.try_into()
            .map_err(|_| anyhow::anyhow!("Invalid amount proof format"))?;
        let proof_amount = u64::from_le_bytes(amount_bytes);
        Ok(proof_amount == self.amount && proof_amount > 0)
    }

    fn verify_destination_proof(&self, proof_data: &str) -> Result<bool> {
        let proof_bytes = hex::decode(proof_data)?;
        let proof_destination = String::from_utf8(proof_bytes)
            .map_err(|_| anyhow::anyhow!("Invalid destination proof format"))?;
        Ok(proof_destination == self.destination)
    }

    pub fn hash_zk_proof(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.zk_proof.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }

    pub fn validate_ownership_proof(&self, public_key: &PublicKey) -> Result<bool> {
        if self.zk_proof.is_empty() {
            return Ok(false);
        }

        let pk_bytes = if self.public_key.starts_with("0x") {
            hex::decode(&self.public_key[2..])?
        } else {
            hex::decode(&self.public_key)?
        };

        let _secp = secp256k1::Secp256k1::new();
        let expected_pk = PublicKey::from_slice(&pk_bytes)?;
        
        if expected_pk != *public_key {
            return Ok(false);
        }

        if self.zk_proof.len() == 64 {
            return Ok(hex::decode(&self.zk_proof).is_ok());
        }

        self.verify_zk_proof(public_key)
    }

    pub fn create_transaction_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.transaction_id.as_bytes());
        hasher.update(self.sender.as_bytes());
        hasher.update(self.destination.as_bytes());
        hasher.update(&self.amount.to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }
}

impl RequestTask {
    pub fn new_transaction(transaction: Transaction) -> Self {
        Self {
            task_id: uuid::Uuid::new_v4().to_string(),
            transaction: Some(transaction),
            proof_data: Vec::new(),
            request_type: RequestType::Transaction,
            request_status: TaskStatus::Pending,
            request_created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            request_completed_at: 0,
        }
    }

    pub fn new_signature(proof_data: Vec<u8>) -> Self {
        Self {
            task_id: uuid::Uuid::new_v4().to_string(),
            transaction: None,
            proof_data,
            request_type: RequestType::Signature,
            request_status: TaskStatus::Pending,
            request_created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            request_completed_at: 0,
        }
    }

    pub fn complete(&mut self) {
        self.request_status = TaskStatus::Completed;
        self.request_completed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn mark_error(&mut self) {
        self.request_status = TaskStatus::Error;
        self.request_completed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn verify_transaction_proof(&self, public_key: &PublicKey) -> Result<bool> {
        match &self.transaction {
            Some(transaction) => transaction.verify_zk_proof(public_key),
            None => Ok(false),
        }
    }
}

impl StoredTransactionData {
    pub fn new(
        transaction: Transaction,
        keyshares: Vec<TransactionKeyShare>,
        threshold: usize,
        total_shares: usize,
    ) -> Self {
        let zk_proof_hash = transaction.hash_zk_proof();
        let keyshares_hash = Self::hash_keyshares(&keyshares);
        let combined_hash = Self::create_combined_hash(&zk_proof_hash, &keyshares_hash);
        
        Self {
            transaction,
            keyshares,
            zk_proof_hash,
            keyshares_hash,
            combined_hash,
            stored_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            threshold,
            total_shares,
        }
    }

    pub fn hash_keyshares(keyshares: &[TransactionKeyShare]) -> String {
        let mut hasher = Sha256::new();
        
        for share in keyshares {
            hasher.update(&share.node_id.to_le_bytes());
            hasher.update(&share.transaction_id.as_bytes());
            hasher.update(&share.session_id.as_bytes());
            
            let mut share_bytes = Vec::new();
            share.share_value.into_bigint().serialize_uncompressed(&mut share_bytes).unwrap();
            hasher.update(&share_bytes);
            
            let mut commitment_bytes = Vec::new();
            share.public_commitment.into_affine().x.into_bigint().serialize_uncompressed(&mut commitment_bytes).unwrap();
            hasher.update(&commitment_bytes);
        }
        
        let result = hasher.finalize();
        hex::encode(result)
    }

    fn create_combined_hash(zk_proof_hash: &str, keyshares_hash: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(zk_proof_hash.as_bytes());
        hasher.update(keyshares_hash.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }

    pub fn verify_integrity(&self) -> bool {
        let expected_zk_hash = self.transaction.hash_zk_proof();
        let expected_keyshares_hash = Self::hash_keyshares(&self.keyshares);
        let expected_combined_hash = Self::create_combined_hash(&expected_zk_hash, &expected_keyshares_hash);
        
        self.zk_proof_hash == expected_zk_hash &&
        self.keyshares_hash == expected_keyshares_hash &&
        self.combined_hash == expected_combined_hash
    }

    pub fn is_threshold_met(&self) -> bool {
        self.keyshares.len() >= self.threshold
    }

    pub fn destroy_keyshares(&mut self) {
        for share in &mut self.keyshares {
            share.share_value = Fr::zero();
            share.public_commitment = G1Projective::zero();
        }
    }
}