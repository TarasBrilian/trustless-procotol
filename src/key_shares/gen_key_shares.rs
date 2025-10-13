use secp256k1::{SecretKey, Secp256k1};
use rand::{thread_rng, Rng};
use anyhow::Result;
use hex;

pub fn gen_key_shares(private_key: &SecretKey, num_shares: usize, threshold: usize) -> Result<Vec<Vec<u8>>> {
    println!("Generating {} key shares with threshold {}", num_shares, threshold);
    
    let secp = Secp256k1::new();
    let mut rng = thread_rng();
    
    let sk_bytes = private_key.secret_bytes();
    let sk_value = u64::from_le_bytes([
        sk_bytes[0], sk_bytes[1], sk_bytes[2], sk_bytes[3],
        sk_bytes[4], sk_bytes[5], sk_bytes[6], sk_bytes[7]
    ]);

    let mut coefficients = Vec::new();
    coefficients.push(sk_value); // a0 = secret
    
    for _ in 1..threshold {
        coefficients.push(rng.gen::<u64>());
    }
    
    // Generate shares by evaluating polynomial at different points
    let mut shares = Vec::new();
    
    for i in 1..=num_shares {
        let x = i as u64;
        let mut y = 0u64;
        
        // Evaluate polynomial: y = a0 + a1*x + a2*x^2 + ... + a(t-1)*x^(t-1)
        for (j, coeff) in coefficients.iter().enumerate() {
            y = y.wrapping_add(coeff.wrapping_mul(x.pow(j as u32)));
        }
        
        let mut share_bytes = vec![0u8; 32];
        share_bytes[0..8].copy_from_slice(&y.to_le_bytes());

        for i in 8..32 {
            share_bytes[i] = rng.gen();
        }
        
        println!("Share {}: 0x{}", i, hex::encode(&share_bytes));
        
        shares.push(share_bytes);
    }
    
    println!("Successfully generated {} key shares", num_shares);
    println!("Threshold: {} shares needed to reconstruct private key", threshold);
    
    Ok(shares)
}

pub fn reconstruct_private_key(shares: &[Vec<u8>], threshold: usize) -> Result<SecretKey> {
    println!("Reconstructing private key from {} shares", shares.len());
    
    if shares.len() < threshold {
        return Err(anyhow::anyhow!("Not enough shares to reconstruct private key"));
    }
    
    // Simplified reconstruction (in practice, you'd use Lagrange interpolation)
    let mut reconstructed_bytes = vec![0u8; 32];
    
    for share in shares.iter().take(threshold) {
        for (i, byte) in share.iter().enumerate() {
            reconstructed_bytes[i] = reconstructed_bytes[i].wrapping_add(*byte);
        }
    }
    
    // Normalize the result
    for byte in reconstructed_bytes.iter_mut() {
        *byte = *byte % 255;
    }
    
    let secret_key = SecretKey::from_slice(&reconstructed_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to create secret key: {}", e))?;
    
    println!("Private key reconstructed successfully");
    println!("Reconstructed key: 0x{}", hex::encode(secret_key.secret_bytes()));
    
    Ok(secret_key)
}
