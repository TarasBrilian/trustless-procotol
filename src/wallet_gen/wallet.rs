use secp256k1::{SecretKey, PublicKey, Secp256k1};
use tiny_keccak::{Hasher, Keccak};
use web3::types::Address;
use rand::thread_rng;
use anyhow::Result;
use crate::storage::secure_storage;
use crate::zk::zk_ownership::{OwnershipCircuit, generate_ownership_proof_and_verify};

pub fn generate_and_store_wallet() -> Result<PublicKey> {
    let secp = secp256k1::Secp256k1::new();
    let mut rng = thread_rng();
    let (sk, pk) = secp.generate_keypair(&mut rng);

    secure_storage::store_private_key(&sk.secret_bytes())?;

    println!("Private key stored securely in macOS Keychain");
    
    Ok(pk)
}

pub fn export_private_key_with_zk_proof() -> Result<Vec<u8>> {
    println!("ZK verification for private key export");

    let private_key_bytes = secure_storage::retrieve_private_key()?;
    let private_key = SecretKey::from_slice(&private_key_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;

    let secp = Secp256k1::new();
    let public_key = private_key.public_key(&secp);

    let sk_bytes = private_key.secret_bytes();
    let pk_bytes = public_key.serialize_uncompressed();
    
    use ark_bls12_381::Fr;
    use ark_ff::PrimeField;
    
    let sk_fr = Fr::from_le_bytes_mod_order(&sk_bytes);
    let pk_hash = Fr::from_le_bytes_mod_order(&pk_bytes[0..32]);
    
    let circuit = OwnershipCircuit {
        private_key: Some(sk_fr),
        public_key_hash: Some(pk_hash),
    };

    let proof_valid = generate_ownership_proof_and_verify(circuit)?;

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