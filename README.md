**Note**: THE CODE CAN ONLY RUN ON MAC OS 
**Note**: This is a prototype implementation for educational and research purposes. For production use, additional security audits and testing are required. 

# ZK-Wallet: Zero-Knowledge Cryptocurrency Wallet

A secure cryptocurrency wallet implementation featuring **Zero-Knowledge Proofs**, **macOS Secure Enclave integration**, and **Distributed Key Generation (DKG)** for enhanced security and privacy.

## 🚀 Features

### 1. **Secure Wallet Generation**
- Generates cryptographically secure private/public key pairs using secp256k1
- Creates Ethereum-compatible addresses using Keccak256 hashing
- Random key generation for maximum security

### 2. **macOS Secure Enclave Integration**
- Stores private keys securely in macOS Keychain
- Private keys are encrypted at rest and protected by system security
- No plain-text private keys in memory or logs
- Protected by macOS authentication mechanisms

### 3. **Zero-Knowledge Proof Verification**
- Implements **Groth16** zk-SNARKs using **BLS12-381** elliptic curve
- Proves ownership of private key without revealing it
- Cryptographic verification that user controls the private key
- Uses **arkworks** library for advanced cryptographic operations

### 4. **Distributed Key Generation (DKG)**
- Splits private key into multiple shares using polynomial secret sharing
- Configurable threshold (e.g., 3 out of 5 shares needed)
- Each share distributed to different nodes for fault tolerance
- Demonstrates reconstruction from minimum required shares

## 🏗️ Architecture

```
src/
├── main.rs                 # Main application entry point
├── wallet_gen/             # Wallet generation and management
│   ├── wallet.rs          # Core wallet functions
│   └── secure_storage.rs  # macOS Keychain integration
├── zk/                     # Zero-Knowledge Proof system
│   └── zk_ownership.rs    # Ownership verification circuits
└── key_shares/             # Distributed Key Generation
    └── gen_key_shares.rs  # DKG implementation
```

## 🔧 Technical Implementation

### Wallet Generation (`wallet_gen/`)
- **secp256k1**: Elliptic curve cryptography for key generation
- **tiny_keccak**: Keccak256 hashing for Ethereum address generation
- **security-framework**: macOS Keychain integration for secure storage

### Zero-Knowledge Proofs (`zk/`)
- **arkworks**: Advanced cryptographic library suite
- **Groth16**: zk-SNARK proving system
- **BLS12-381**: Pairing-friendly elliptic curve
- **R1CS**: Rank-1 Constraint System for circuit definition

### Distributed Key Generation (`key_shares/`)
- **Polynomial Secret Sharing**: Shamir's Secret Sharing Scheme
- **Threshold Cryptography**: Configurable minimum shares required
- **Fault Tolerance**: System works even if some nodes fail

## 🛡️ Security Features

1. **Private Key Protection**
   - Never stored in plain text
   - Encrypted in macOS Keychain
   - Zero-knowledge proof verification before access

2. **Cryptographic Security**
   - Industry-standard secp256k1 curve
   - Cryptographically secure random number generation
   - BLS12-381 pairing-friendly curve for zk-SNARKs

3. **Distributed Security**
   - No single point of failure
   - Threshold-based access control
   - Fault-tolerant key reconstruction

## 🚀 Usage

### Prerequisites
- macOS (for Secure Enclave integration)
- Rust 1.70+
- Xcode Command Line Tools

### Installation
```bash
git clone <repository-url>
cd zk-signing
cargo build
```

### Running the Application
```bash
cargo run
```

### Expected Output
```
Public Key: 0x04[64-byte-public-key]
Address: 0x[40-character-ethereum-address]

Private key is securely stored in macOS Keychain

ZK ownership proof verified successfully!
User has proven ownership of the private key

Generating 5 key shares with threshold 3
Share 1: 0x[32-byte-share]
Share 2: 0x[32-byte-share]
Share 3: 0x[32-byte-share]
Share 4: 0x[32-byte-share]
Share 5: 0x[32-byte-share]

Successfully generated 5 key shares
Threshold: 3 shares needed to reconstruct private key

Testing reconstruction with 3 shares...
Reconstructing private key from 3 shares
Private key reconstructed successfully
Reconstructed key: 0x[32-byte-reconstructed-key]
Reconstruction successful! Keys match perfectly
```

## 🔬 Cryptographic Details

### Zero-Knowledge Proof Circuit
The ownership verification circuit (`OwnershipCircuit`) implements:
- **Private Input**: Secret key (witness)
- **Public Input**: Public key hash
- **Constraints**: 
  - Private key is non-zero
  - Private key is within valid range
  - Cryptographic relationship verification

### Distributed Key Generation Algorithm
1. **Polynomial Generation**: Creates polynomial `f(x) = a₀ + a₁x + a₂x² + ... + aₜ₋₁xᵗ⁻¹`
   - `a₀` = secret (private key)
   - `a₁, a₂, ..., aₜ₋₁` = random coefficients
2. **Share Distribution**: Evaluates polynomial at points `x = 1, 2, 3, ..., n`
3. **Reconstruction**: Uses Lagrange interpolation to recover secret from threshold shares

## 🎯 Use Cases

1. **High-Security Wallets**: For users requiring maximum security
2. **Institutional Custody**: Multi-signature wallets with threshold access
3. **Decentralized Systems**: Distributed key management for blockchain networks
4. **Privacy-Preserving Authentication**: Prove ownership without revealing secrets

## ⚠️ Important Notes

- **macOS Only**: Secure Enclave integration requires macOS
- **Prototype Implementation**: DKG uses simplified polynomial evaluation
- **Production Use**: Requires additional security audits and testing
- **Key Management**: Always backup recovery phrases securely

## 🔮 Future Enhancements

- [ ] Multi-signature wallet support
- [ ] Hardware security module (HSM) integration
- [ ] Cross-platform secure storage
- [ ] Advanced DKG protocols (Feldman VSS, Pedersen commitments)
- [ ] Integration with major blockchain networks
- [ ] Web3 wallet interface

## 📚 Dependencies

- **arkworks**: Advanced cryptographic library
- **secp256k1**: Elliptic curve cryptography
- **security-framework**: macOS security integration
- **rand**: Cryptographically secure random number generation
- **anyhow**: Error handling
- **hex**: Hexadecimal encoding/decoding

---
