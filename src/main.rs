mod wallet_gen;
mod zk;
mod key_shares;

use wallet_gen::wallet::{pub_key_address, generate_and_store_wallet, export_private_key_with_zk_proof};
use zk::zk_ownership::{create_ownership_proof};
use key_shares::gen_key_shares::{gen_key_shares, reconstruct_private_key};
use hex;
use wallet_gen::secure_storage;
use secp256k1::{SecretKey, Secp256k1};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match generate_and_store_wallet() {
        Ok(pk) => {
            println!("Public Key: 0x{}", hex::encode(pk.serialize_uncompressed()));
            let address = pub_key_address(&pk);
            println!("Address: 0x{}", hex::encode(address.as_bytes()));
            println!("\nPrivate key is securely stored in macOS Keychain");

            // Commented out for now as we don't need to export the private key
            // match export_private_key_with_zk_proof() {
            //     Ok(private_key_bytes) => {
            //         println!("Private Key: 0x{}", hex::encode(&private_key_bytes));
            //         println!("Export successful with ZK proof verification!");
            //     }
            //     Err(e) => eprintln!("Export failed: {:?}", e),
            // }
        }
        Err(e) => eprintln!("Error generating wallet: {:?}", e),
    }
    
    match secure_storage::retrieve_private_key() {
        Ok(private_key_bytes) => {
            let private_key = SecretKey::from_slice(&private_key_bytes)
                .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;
            
            let secp = Secp256k1::new();
            let public_key = private_key.public_key(&secp);
            
            match create_ownership_proof(&private_key, &public_key) {
                Ok(valid) => {
                    if valid {
                        println!("ZK ownership proof verified successfully!");
                        println!("User has proven ownership of the private key");
                    } else {
                        println!("ZK ownership proof verification failed");
                    }
                }
                Err(e) => eprintln!("ZK proof generation failed: {:?}", e),
            }
        }
        Err(e) => eprintln!("Failed to retrieve private key: {:?}", e),
    }
    
    // DKG Demonstration: Split private key into 5 shares
    match secure_storage::retrieve_private_key() {
        Ok(private_key_bytes) => {
            let private_key = SecretKey::from_slice(&private_key_bytes)
                .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;
            
            // Generate 5 key shares with threshold 3
            match gen_key_shares(&private_key, 5, 3) {
                Ok(shares) => {
                    // Demo reconstruction with first 3 shares
                    println!("\nTesting reconstruction with 3 shares...");
                    match reconstruct_private_key(&shares[0..3], 3) {
                        Ok(reconstructed_key) => {
                            let original_hex = hex::encode(private_key.secret_bytes());
                            let reconstructed_hex = hex::encode(reconstructed_key.secret_bytes());
                            
                            if original_hex == reconstructed_hex {
                                println!("Reconstruction successful! Keys match perfectly");
                            } else {
                                println!("Reconstruction completed but keys don't match exactly");
                                println!("   Original:    0x{}", original_hex);
                                println!("   Reconstructed: 0x{}", reconstructed_hex);
                            }
                        }
                        Err(e) => eprintln!("Reconstruction failed: {:?}", e),
                    }
                }
                Err(e) => eprintln!("DKG generation failed: {:?}", e),
            }
        }
        Err(e) => eprintln!("Failed to retrieve private key for DKG: {:?}", e),
    }
    
    Ok(())
}
