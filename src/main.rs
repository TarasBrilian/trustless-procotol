mod circuit;
mod prover;
mod wallet_gen;

use circuit::KnowSkCircuit;
use prover::{generate_proof_and_verify, gen_keypair};
use wallet_gen::wallet::{pub_key_address, generate_and_store_wallet, export_private_key_with_zk_proof};
use hex;

fn main() {
    let (sk, expected_result) = gen_keypair();
    println!("Generated keypair:");
    println!("sk = {:?}", sk);
    println!("expected_result = {:?}", expected_result);

    let circuit = KnowSkCircuit {
        sk: Some(sk),
        expected_result: Some(expected_result),
    };

    match generate_proof_and_verify(circuit) {
        Ok(valid) => println!("Proof verified: {}", valid),
        Err(e) => eprintln!("Error: {:?}", e),
    }

    match generate_and_store_wallet() {
        Ok(pk) => {
            println!("Public Key: 0x{}", hex::encode(pk.serialize_uncompressed()));
            let address = pub_key_address(&pk);
            println!("Address: 0x{}", hex::encode(address.as_bytes()));
            println!("\n✓ Private key is securely stored in macOS Keychain");

            println!("\nZK-Verified Private Key Export");
            match export_private_key_with_zk_proof() {
                Ok(private_key_bytes) => {
                    println!("✓ Private Key: 0x{}", hex::encode(&private_key_bytes));
                    println!("✓ Export successful with ZK proof verification!");
                }
                Err(e) => eprintln!("Export failed: {:?}", e),
            }
        }
        Err(e) => eprintln!("Error generating wallet: {:?}", e),
    }
}
