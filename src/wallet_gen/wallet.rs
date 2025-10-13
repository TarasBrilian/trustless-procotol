use secp256k1::{SecretKey, PublicKey, Secp256k1};
use tiny_keccak::{Hasher, Keccak};
use web3::types::Address;
use rand::thread_rng;
use anyhow::Result;
use super::secure_storage;
use super::zk_ownership;

pub fn generate_and_store_wallet() -> Result<PublicKey> {
    let secp = secp256k1::Secp256k1::new();
    let mut rng = thread_rng();
    let (sk, pk) = secp.generate_keypair(&mut rng);
    
    // Store private key securely in macOS Keychain
    secure_storage::store_private_key(&sk.secret_bytes())?;
    
    println!("Private key stored securely in macOS Keychain");
    
    Ok(pk)
}

pub fn export_private_key_with_zk_proof() -> Result<Vec<u8>> {
    println!("ZK verification for private key export");

    let private_key_bytes = secure_storage::retrieve_private_key()?;
    let private_key = SecretKey::from_slice(&private_key_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;
    
    // Generate corresponding public key
    let secp = Secp256k1::new();
    let public_key = private_key.public_key(&secp);

    // Create ZK proof that we own the private key
    let proof_valid = zk_ownership::create_ownership_proof(&private_key, &public_key)?;
    
    if !proof_valid {
        return Err(anyhow::anyhow!("ZK proof verification failed - access denied"));
    }
    
    Ok(private_key_bytes)
}

pub fn pub_key_address(pub_key: &PublicKey) -> Address {
    let pub_key = pub_key.serialize_uncompressed();

    debug_assert_eq!(pub_key[0], 0x04);

    let mut hasher = Keccak::v256();
    hasher.update(&pub_key[1..]);
    let mut result = [0u8; 32];
    hasher.finalize(&mut result);
    let hash = result;

    Address::from_slice(&hash[12..])
}