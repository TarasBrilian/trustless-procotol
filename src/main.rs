mod wallet_gen;
mod zk;
mod nodes;
mod dkg;

use wallet_gen::wallet::{pub_key_address, generate_and_store_wallet};
use zk::zk_ownership::{create_ownership_proof};
use dkg::ephemeral_dkg::{simulate_dkg_session, simulate_threshold_signing};
use hex;
use wallet_gen::secure_storage;
use secp256k1::{SecretKey, Secp256k1};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Trustless wallet system with ephemeral keys per transaction");
    
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
