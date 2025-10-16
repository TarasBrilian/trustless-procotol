use ark_bls12_381::{Fr, G1Projective};
use ark_ec::{CurveGroup, Group};
use ark_ff::{PrimeField, Zero, One, UniformRand};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::CanonicalSerialize;
use rand::thread_rng;
use std::collections::HashMap;
use anyhow::Result;
use hex;

#[derive(Debug, Clone)]
pub struct PolynomialShare {
    pub node_id: usize,
    pub share_value: Fr,
    pub public_commitment: G1Projective,
}

#[derive(Debug, Clone)]
pub struct DkgSession {
    pub session_id: String,
    pub threshold: usize,
    pub total_nodes: usize,
    pub polynomial_shares: HashMap<usize, PolynomialShare>,
    pub global_public_key: Option<G1Projective>,
    pub is_completed: bool,
}

#[derive(Debug, Clone)]
pub struct PartialSignature {
    pub node_id: usize,
    pub signature_share: Fr,
    pub public_commitment: G1Projective,
}

#[derive(Debug, Clone)]
pub struct AggregatedSignature {
    pub signature: Fr,
    pub public_key: G1Projective,
}

impl DkgSession {
    pub fn new(session_id: String, threshold: usize, total_nodes: usize) -> Self {
        Self {
            session_id,
            threshold,
            total_nodes,
            polynomial_shares: HashMap::new(),
            global_public_key: None,
            is_completed: false,
        }
    }

    pub fn generate_polynomial(&self, node_id: usize) -> Result<DensePolynomial<Fr>> {
        println!("Node {} generating random polynomial of degree {}", node_id, self.threshold - 1);
        
        let mut rng = thread_rng();
        let mut coeffs = Vec::new();
        
        for i in 0..self.threshold {
            let coeff = Fr::rand(&mut rng);
            coeffs.push(coeff);
            let mut coeff_bytes = Vec::new();
            coeff.into_bigint().serialize_uncompressed(&mut coeff_bytes).unwrap();
            println!("  Coefficient a{}: 0x{}", i, hex::encode(coeff_bytes));
        }
        
        let polynomial = DensePolynomial::from_coefficients_vec(coeffs);
        println!("Node {} polynomial generated successfully", node_id);
        
        Ok(polynomial)
    }

    pub fn generate_shares(&self, node_id: usize, polynomial: &DensePolynomial<Fr>) -> Result<Vec<PolynomialShare>> {
        println!("Node {} generating shares for all nodes", node_id);
        
        let mut shares = Vec::new();

        for i in 1..=self.total_nodes {
            let x = Fr::from(i as u64);
            let share_value = polynomial.evaluate(&x);
            
            let public_commitment = G1Projective::generator() * share_value;
            
            let share = PolynomialShare {
                node_id: i,
                share_value,
                public_commitment,
            };
            
            shares.push(share);
            let mut share_bytes = Vec::new();
            share_value.into_bigint().serialize_uncompressed(&mut share_bytes).unwrap();
            println!("  Share for node {}: 0x{}", i, hex::encode(share_bytes));
        }
        
        println!("Node {} generated {} shares successfully", node_id, shares.len());
        Ok(shares)
    }

    pub fn add_node_shares(&mut self, node_id: usize, shares: Vec<PolynomialShare>) -> Result<()> {
        println!("Adding shares from node {} to DKG session", node_id);
        
        for share in shares {
            self.polynomial_shares.insert(share.node_id, share);
        }
        
        println!("Total shares in session: {}", self.polynomial_shares.len());
        Ok(())
    }

    pub fn compute_global_public_key(&mut self) -> Result<G1Projective> {
        println!("Computing global public key from {} shares", self.polynomial_shares.len());
        
        if self.polynomial_shares.len() < self.total_nodes {
            return Err(anyhow::anyhow!("Not enough shares to compute global public key"));
        }

        let mut global_pk = G1Projective::zero();
        
        for (node_id, share) in &self.polynomial_shares {
            global_pk += share.public_commitment;
            let mut commitment_bytes = Vec::new();
            share.public_commitment.into_affine().x.into_bigint().serialize_uncompressed(&mut commitment_bytes).unwrap();
            println!("  Added share from node {}: 0x{}", 
                    node_id, 
                    hex::encode(commitment_bytes));
        }
        
        self.global_public_key = Some(global_pk);
        self.is_completed = true;
        
        let mut global_pk_bytes = Vec::new();
        global_pk.into_affine().x.into_bigint().serialize_uncompressed(&mut global_pk_bytes).unwrap();
        println!("Global public key computed: 0x{}", 
                hex::encode(global_pk_bytes));
        
        Ok(global_pk)
    }

    pub fn generate_partial_signature(&self, node_id: usize, message: &[u8]) -> Result<PartialSignature> {
        println!("Node {} generating partial signature", node_id);
        
        let share = self.polynomial_shares.get(&node_id)
            .ok_or_else(|| anyhow::anyhow!("No share found for node {}", node_id))?;

        let message_hash = self.hash_message_to_field(message);
        
        let signature_share = share.share_value * message_hash;
        
        let partial_sig = PartialSignature {
            node_id,
            signature_share,
            public_commitment: share.public_commitment,
        };
        
        let mut sig_bytes = Vec::new();
        signature_share.into_bigint().serialize_uncompressed(&mut sig_bytes).unwrap();
        println!("Node {} partial signature: 0x{}", 
                node_id, 
                hex::encode(sig_bytes));
        
        Ok(partial_sig)
    }

    pub fn aggregate_signatures(&self, partial_sigs: &[PartialSignature], message: &[u8]) -> Result<AggregatedSignature> {
        println!("Aggregating {} partial signatures", partial_sigs.len());
        
        if partial_sigs.len() < self.threshold {
            return Err(anyhow::anyhow!("Not enough partial signatures for threshold"));
        }
        
        let mut aggregated_signature = Fr::zero();
        let mut global_pk = G1Projective::zero();
        
        for (i, partial_sig) in partial_sigs.iter().enumerate() {
            let lagrange_coeff = self.compute_lagrange_coefficient(partial_sig.node_id, &partial_sigs);
            
            aggregated_signature += lagrange_coeff * partial_sig.signature_share;
            
            global_pk += partial_sig.public_commitment * lagrange_coeff;
            
            let mut lagrange_bytes = Vec::new();
            lagrange_coeff.into_bigint().serialize_uncompressed(&mut lagrange_bytes).unwrap();
            println!("  Node {} Lagrange coeff: 0x{}", 
                    partial_sig.node_id, 
                    hex::encode(lagrange_bytes));
        }
        
        let result = AggregatedSignature {
            signature: aggregated_signature,
            public_key: global_pk,
        };
        
        let mut aggregated_bytes = Vec::new();
        aggregated_signature.into_bigint().serialize_uncompressed(&mut aggregated_bytes).unwrap();
        println!("Aggregated signature: 0x{}", 
                hex::encode(aggregated_bytes));
        
        Ok(result)
    }

    fn compute_lagrange_coefficient(&self, node_id: usize, partial_sigs: &[PartialSignature]) -> Fr {
        let mut numerator = Fr::one();
        let mut denominator = Fr::one();
        
        let x_i = Fr::from(node_id as u64);
        
        for partial_sig in partial_sigs {
            if partial_sig.node_id != node_id {
                let x_j = Fr::from(partial_sig.node_id as u64);
                numerator *= x_j;
                denominator *= x_i - x_j;
            }
        }
        
        numerator / denominator
    }

    fn hash_message_to_field(&self, message: &[u8]) -> Fr {
        let mut hash_bytes = [0u8; 32];
        for (i, byte) in message.iter().enumerate() {
            hash_bytes[i % 32] = hash_bytes[i % 32].wrapping_add(*byte);
        }
        
        Fr::from_le_bytes_mod_order(&hash_bytes)
    }

    pub fn destroy_shares(&mut self) {
        println!("Destroying all shares for session: {}", self.session_id);
        
        for (node_id, share) in &mut self.polynomial_shares {
            println!("  Destroying share for node {}", node_id);
            share.share_value = Fr::zero();
            share.public_commitment = G1Projective::zero();
        }
        
        self.polynomial_shares.clear();
        self.global_public_key = None;
        self.is_completed = false;
        
        println!("All shares destroyed successfully");
    }
}

pub fn simulate_dkg_session(session_id: String) -> Result<DkgSession> {
    println!("=== STARTING EPHEMERAL DKG SIMULATION ===");
    println!("Session ID: {}", session_id);
    println!("Nodes: 5, Threshold: 3");
    
    let mut dkg_session = DkgSession::new(session_id, 3, 5);
    
    for node_id in 1..=5 {
        println!("\n--- Node {} Phase ---", node_id);
        
        let polynomial = dkg_session.generate_polynomial(node_id)?;
        
        let shares = dkg_session.generate_shares(node_id, &polynomial)?;
        
        dkg_session.add_node_shares(node_id, shares)?;
    }
    
    let global_pk = dkg_session.compute_global_public_key()?;
    
    let mut global_pk_bytes = Vec::new();
    global_pk.into_affine().x.into_bigint().serialize_uncompressed(&mut global_pk_bytes).unwrap();
    println!("Global public key: 0x{}", 
            hex::encode(global_pk_bytes));
    
    Ok(dkg_session)
}

pub fn simulate_threshold_signing(dkg_session: &mut DkgSession, message: &[u8]) -> Result<AggregatedSignature> {
    println!("\n=== SIMULATING THRESHOLD SIGNING ===");
    println!("Message: 0x{}", hex::encode(message));
    
    let mut partial_sigs = Vec::new();
    let participating_nodes = vec![1, 2, 3];

    for node_id in participating_nodes {
        println!("\n--- Node {} Generating Partial Signature ---", node_id);
        let partial_sig = dkg_session.generate_partial_signature(node_id, message)?;
        partial_sigs.push(partial_sig);
    }
    
    let aggregated_sig = dkg_session.aggregate_signatures(&partial_sigs, message)?;
    
    println!("Threshold signing completed successfully!");
    let mut final_sig_bytes = Vec::new();
    aggregated_sig.signature.into_bigint().serialize_uncompressed(&mut final_sig_bytes).unwrap();
    println!("Final signature: 0x{}", 
            hex::encode(final_sig_bytes));
    
    Ok(aggregated_sig)
}
