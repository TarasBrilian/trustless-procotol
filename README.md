**Note**: THE CODE CAN ONLY RUN ON MAC OS and this is a prototype implementation for educational and research purposes not for production use.

# Trustless Protocol: Decentralized TSS Network with Ephemeral DKG

A revolutionary decentralized node system featuring **Zero-Knowledge Proofs**, **macOS Secure Enclave integration**, **Ephemeral Distributed Key Generation (DKG)**, and **Permissionless TSS Network** for maximum security and privacy. This system creates a network of nodes that can independently validate proofs, participate in threshold signing, and generate unique ephemeral keys for each transaction that are destroyed immediately after use.

## Features

### 1. **Decentralized Node System**
- **Permissionless Network**: Nodes can join the network without permission
- **Independent Operation**: Each node runs autonomously and can process requests
- **REST API Interface**: HTTP endpoints for communication and monitoring
- **Node Health Monitoring**: Real-time CPU, memory, and uptime tracking
- **Unique Node Identity**: Each node has unique ID, public key, and address

### 2. **Secure Address Generation**
- **Proper Address Format**: Address ≠ Public Key (unlike previous version)
- **SHA256 Hashing**: Address = SHA256(public_key)[:20] + "0x" prefix
- **Ethereum-Compatible**: 42-character address format (0x + 40 hex chars)
- **Cryptographically Secure**: Uses secp256k1 for key generation

### 3. **Zero-Knowledge Proof Verification**
- **Proof Validation**: Nodes can validate user proofs of ownership
- **Simplified Logic**: Current implementation validates proof structure
- **Public Key Verification**: Validates secp256k1 public key format
- **Challenge-Response**: Implements challenge-response mechanism

### 4. **Ephemeral Distributed Key Generation (DKG)**
- **Trustless System**: No persistent private keys stored anywhere
- **Per-Transaction Keys**: Generates unique ephemeral keys for each transaction
- **Polynomial Secret Sharing**: Uses advanced cryptographic field elements (Fr) and elliptic curve commitments (G1Projective)
- **Threshold Signatures**: Configurable threshold (e.g., 3 out of 5 nodes required)
- **Automatic Key Destruction**: Keys are destroyed immediately after transaction completion
- **Zero Key Storage**: No keys persist between transactions

### 5. **Transaction Processing**
- **ZK Proof Validation**: Validates user ownership proofs before transaction processing
- **DKG Session Management**: Each transaction gets unique DKG session with ephemeral keys
- **Threshold Signing**: Collaborative threshold signature creation with 5 nodes
- **Transaction Hash Generation**: Creates unique transaction identifiers
- **Automatic Cleanup**: Destroys ephemeral keys immediately after transaction completion
- **Multi-Step Flow**: Complete transaction flow from submission to cleanup

## Architecture

```
src/
├── main.rs                 # Main application entry point & CLI interface
├── storage/                # Private key storage logic in enclaves
│   └── secure_storage.rs  # macOS Keychain integration
├── zk/                     # Zero-Knowledge Proof system
│   └── zk_ownership.rs    # Ownership verification circuits
├── dkg/                    # Ephemeral Distributed Key Generation
│   └── ephemeral_dkg.rs   # DKG implementation with polynomial commitments
├── nodes/                  # Decentralized Node System
|   └── node.rs           # Node runtime, API server, and transaction processing
├── wallet_gen/             # Generate wallet
|   └── wallet.rs           # Symple logic for generation wallet
├── network/             # p2p network
|   └── peer.rs           # Symple logic for connecting node
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

### Ephemeral Distributed Key Generation (`dkg/`)
- **Polynomial Secret Sharing**: Advanced Shamir's Secret Sharing with field elements
- **BLS12-381 Field Elements**: Uses `Fr` (field elements) for cryptographic operations
- **Elliptic Curve Commitments**: Uses `G1Projective` for public commitments
- **Threshold Cryptography**: Configurable minimum nodes required for signing
- **Ephemeral Sessions**: Each transaction gets a unique DKG session
- **Automatic Cleanup**: Keys are destroyed after transaction completion

### Decentralized Node System (`nodes/`)
- **Node Runtime**: Core node logic with health monitoring and session management
- **REST API Server**: Axum-based HTTP server for node communication
- **Transaction Processing**: Handles transaction requests and proof validation
- **DKG Integration**: Manages ephemeral DKG sessions for each transaction
- **Session Tracking**: Monitors active transaction sessions and voting
- **Address Generation**: Proper SHA256-based address generation from public keys
- **Zero Persistence**: No persistent key material stored on nodes

## Security Features

1. **Private Key Protection**
   - Never stored in plain text
   - Encrypted in macOS Keychain
   - Zero-knowledge proof verification before access

2. **Cryptographic Security**
   - Industry-standard secp256k1 curve
   - Cryptographically secure random number generation
   - BLS12-381 pairing-friendly curve for zk-SNARKs

3. **Ephemeral Security**
   - **Zero Key Persistence**: No private keys stored between transactions
   - **Per-Transaction Isolation**: Each transaction uses completely unique keys
   - **Automatic Destruction**: Keys are destroyed immediately after use
   - **Trustless Architecture**: No single point of key compromise
   - **Forward Secrecy**: Compromise of one transaction doesn't affect others

## Usage

### Prerequisites
- macOS (for Secure Enclave integration)
- Rust 1.70+
- Xcode Command Line Tools

### Installation
```bash
git clone https://github.com/TarasBrilian/zk-wallet.git
cd zk-signing
cargo build
```

### Running the Node System

#### 1. Start Multiple Nodes
```bash
# Start all 5 nodes (ports 3000-3004)
./start_p2p_nodes.sh
```

#### 2. Test the Complete Transaction Flow
```bash
# Test the full DKG-based transaction flow
./test_transaction.sh
```

#### API Response Examples
```json
{
  "transaction_id": "tx_1760587911",
  "transaction_hash": "tx_1760587911",
  "approved": true,
  "approval_count": 5,
  "total_votes": 5,
  "final_signature": "c4449ebe6f6ccdae8cccff02614ce6734ec10c95f2e312c6e324b8704cd91a5f38d1d53835271494f971f692af620d6a05493a90ab225af7282c3556df86de23dd8554c8f90577df6251393e1d565404",
  "approved_by": [4, 5, 3, 1, 2]
}

{
  "session_id": "dkg_tx_1760587911",
  "success": true
}

{
  "threshold_met": true,
  "current_shares": 5,
  "required_threshold": 3
}
```

#### Transaction Processing Log
```
=== STARTING EPHEMERAL DKG SIMULATION ===
Session ID: tx_dkg_tx_demo_001
Nodes: 5, Threshold: 3
--- Node 1 Phase ---
Node 1 generating random polynomial of degree 2
Node 1 polynomial generated successfully
Node 1 generating shares for all nodes
Node 1 generated 5 shares successfully
--- [Similar for nodes 2-5] ---
Computing global public key from 5 shares
Global public key computed: 0xf82963aca07285d07910b0b91a151f030c5d1e3f8159218dc927c6c12039962be71419dd70b94788b70a6877c1e4ea09
=== SIMULATING THRESHOLD SIGNING ===
--- Node 1 Generating Partial Signature ---
Node 1 partial signature: 0x97ba0bcdf7a638bfa0eefc56ee45a5f0a2e3bb13779accf4c79aaec88867912b
--- [Similar for nodes 2-3] ---
Aggregated signature: 0x1a2b6fc1f6012b3da0f36e33f820ca5e252c1497357bade1b63e91f84977f44d
Threshold signing completed successfully!
Final signature: 0x1a2b6fc1f6012b3da0f36e33f820ca5e252c1497357bade1b63e91f84977f44d
Destroying all shares for session: tx_dkg_tx_demo_001
All shares destroyed successfully
✓ Transaction signed successfully with ephemeral keys!
✓ All ephemeral keys destroyed
✓ No keys stored - fully trustless system
```

## API Endpoints

### Node Management
| Method | Endpoint | Description | Request Body | Response |
|--------|----------|-------------|--------------|----------|
| GET | `/health` | Node health status | - | `NodeHealth` |
| GET | `/status` | Node information | - | `NodeInfo` |
| GET | `/sessions` | List active sessions | - | `Vec<SessionSummary>` |
| GET | `/sessions/:id` | Get session details | - | `SessionDetail` |

### Transaction Processing
| Method | Endpoint | Description | Request Body | Response |
|--------|----------|-------------|--------------|----------|
| POST | `/transaction` | Submit transaction | `TransactionRequest` | `TransactionResult` |
| POST | `/transaction-final` | Submit transaction (final flow) | `TransactionRequest` | `TransactionResult` |
| POST | `/transaction-dkg` | Submit transaction with DKG | `TransactionRequest` | `TransactionResult` |

### DKG Operations
| Method | Endpoint | Description | Request Body | Response |
|--------|----------|-------------|--------------|----------|
| POST | `/dkg/initiate` | Initiate DKG session | `DkgInitiateRequest` | `DkgInitiateResponse` |
| GET | `/dkg/:session_id/threshold` | Check threshold status | - | `DkgThresholdResponse` |
| POST | `/dkg/cleanup` | Cleanup DKG session | `DkgCleanupRequest` | `DkgCleanupResponse` |

### Storage Operations
| Method | Endpoint | Description | Request Body | Response |
|--------|----------|-------------|--------------|----------|
| POST | `/storage/store` | Store keyshares and proof | `StorageStoreRequest` | `StorageStoreResponse` |

### Network Operations
| Method | Endpoint | Description | Request Body | Response |
|--------|----------|-------------|--------------|----------|
| POST | `/network/message` | Send network message | `NetworkMessage` | `Json<Value>` |
| GET | `/network/peers` | Get connected peers | - | `Vec<Peer>` |

### Request/Response Types

#### TransactionRequest
```json
{
  "transaction": {
    "transaction_id": "tx_1760587911",
    "sender": "0x1234567890abcdef1234567890abcdef12345678",
    "destination": "0x52b0f78ca732389f96539e8E3E0d02F2796D8bac",
    "amount": 1000,
    "nonce": 1,
    "zk_proof": "f80fd962c5df75118b5802b66efd8c011cd204ce86dae33c4aba905be16c8121",
    "public_key": "047a0cdb260bb0a1fc98cc42a139332e016aa00df38baa80b4eef1e850e44ecc534a4f69504bb7d3e1ee5132c027cd766c73c9a9cc6dff5cf522911d5547130afd",
    "challenge": "challenge_1760587911",
    "timestamp": 1760587911
  },
  "public_key": "047a0cdb260bb0a1fc98cc42a139332e016aa00df38baa80b4eef1e850e44ecc534a4f69504bb7d3e1ee5132c027cd766c73c9a9cc6dff5cf522911d5547130afd",
  "challenge": "challenge_1760587911",
  "threshold": 3
}
```

#### TransactionResult
```json
{
  "transaction_id": "tx_1760587911",
  "transaction_hash": "tx_1760587911",
  "approved": true,
  "approval_count": 5,
  "total_votes": 5,
  "final_signature": "c4449ebe6f6ccdae8cccff02614ce6734ec10c95f2e312c6e324b8704cd91a5f38d1d53835271494f971f692af620d6a05493a90ab225af7282c3556df86de23dd8554c8f90577df6251393e1d565404",
  "approved_by": [4, 5, 3, 1, 2]
}
```

#### DkgInitiateRequest
```json
{
  "transaction_hash": "tx_1760587911",
  "threshold": 3,
  "participants": 5
}
```

#### DkgInitiateResponse
```json
{
  "session_id": "dkg_tx_1760587911",
  "success": true
}
```

#### DkgThresholdResponse
```json
{
  "threshold_met": true,
  "current_shares": 5,
  "required_threshold": 3
}
```

#### StorageStoreRequest
```json
{
  "transaction_hash": "tx_1760587911",
  "dkg_session_id": "dkg_tx_1760587911",
  "zk_proof": "f80fd962c5df75118b5802b66efd8c011cd204ce86dae33c4aba905be16c8121",
  "public_key": "047a0cdb260bb0a1fc98cc42a139332e016aa00df38baa80b4eef1e850e44ecc534a4f69504bb7d3e1ee5132c027cd766c73c9a9cc6dff5cf522911d5547130afd",
  "challenge": "challenge_1760587911"
}
```

#### DkgCleanupRequest
```json
{
  "transaction_hash": "tx_1760587911",
  "dkg_session_id": "dkg_tx_1760587911"
}
```

## Cryptographic Details

### Zero-Knowledge Proof Validation
The system supports two types of ZK proof validation:

1. **Simple Hash-Based Proofs** (Test Implementation)
   - Generates SHA256 hash of `public_key + challenge`
   - 64-character hexadecimal string
   - Used for testing and demonstration purposes

2. **Complex Proof Structures** (Production Implementation)
   - Serialized `TransactionProof` containing:
     - `ownership_proof`: Proof of private key ownership
     - `amount_proof`: Proof of transaction amount validity
     - `destination_proof`: Proof of destination address validity
   - Uses bincode serialization for structured proofs

### Address Generation Algorithm
1. **Public Key Generation**: Generate secp256k1 public key (uncompressed format)
2. **SHA256 Hashing**: Compute `SHA256(public_key_bytes)`
3. **Address Extraction**: Take first 20 bytes of hash
4. **Formatting**: Prepend "0x" prefix for Ethereum compatibility
5. **Result**: 42-character address (0x + 40 hex characters)

```rust
pub fn generate_address(public_key: &PublicKey) -> String {
    let pub_key_bytes = public_key.serialize_uncompressed();
    let mut hasher = Sha256::new();
    hasher.update(&pub_key_bytes);
    let hash = hasher.finalize();
    
    let address_bytes = &hash[..20];
    format!("0x{}", hex::encode(address_bytes))
}
```

### Ephemeral Distributed Key Generation Algorithm
1. **Session Initialization**: Creates unique DKG session for each transaction
2. **Polynomial Generation**: Each node generates random polynomial `f(x) = a₀ + a₁x + a₂x² + ... + aₜ₋₁xᵗ⁻¹`
   - `a₀` = ephemeral secret (unique per transaction)
   - `a₁, a₂, ..., aₜ₋₁` = random field elements (Fr)
3. **Share Distribution**: Evaluates polynomials at points `x = 1, 2, 3, ..., n`
4. **Public Commitments**: Each share includes elliptic curve commitment `G1Projective`
5. **Threshold Signing**: Uses partial signatures from threshold nodes
6. **Key Destruction**: All ephemeral shares destroyed after transaction completion

### Transaction Flow
The complete transaction flow consists of 5 main steps:

1. **User Submits Transaction with ZK Proof**
   - User generates ZK proof using public key + challenge
   - Submits transaction with proof to `/transaction-dkg` endpoint
   - Node validates ZK proof and transaction details
   - Returns transaction hash and approval status

2. **DKG Keyshare Generation and ZK Proof Validation**
   - Node initiates DKG session using `/dkg/initiate` endpoint
   - Generates ephemeral keyshares for all 5 nodes
   - Creates unique session ID for this transaction
   - Validates ZK proof against public key

3. **Threshold Validation**
   - Checks if sufficient keyshares are available (5/3 threshold)
   - Uses `/dkg/{session_id}/threshold` endpoint
   - Ensures threshold cryptography requirements are met

4. **Hash and Store Keyshares and ZK Proof**
   - Stores transaction data across all nodes using `/storage/store`
   - Creates cryptographic hashes of keyshares and ZK proof
   - Ensures data integrity and availability

5. **Cleanup Keyshares After Transaction Fulfillment**
   - Destroys all ephemeral keyshares using `/dkg/cleanup`
   - Removes transaction data from memory
   - Ensures zero key persistence

## Use Cases

1. **Ultra-High-Security Wallets**: For users requiring maximum security with zero key persistence
2. **Institutional Custody**: Trustless multi-signature wallets with ephemeral keys
3. **Decentralized Systems**: Distributed key management with forward secrecy
4. **Privacy-Preserving Authentication**: Prove ownership without revealing secrets
5. **Regulatory Compliance**: Systems requiring audit trails with no persistent keys
6. **Quantum-Resistant Preparation**: Ephemeral keys reduce long-term attack surface

## Important Notes

- **macOS Only**: Secure Enclave integration requires macOS
- **Prototype Implementation**: Ephemeral DKG uses advanced cryptographic primitives
- **Production Use**: Requires additional security audits and testing
- **Key Management**: Master private key stored securely in macOS Keychain
- **Ephemeral Nature**: No persistent keys - each transaction uses unique ephemeral keys
- **Trustless Design**: No single point of failure or key compromise

## Future Enhancements

### Network & Decentralization
- [x] **Multi-Node Network**: 5-node P2P network implemented
- [x] **Node Discovery**: Peer-to-peer node discovery implemented
- [x] **REST API**: Complete API server with all endpoints
- [ ] **Bootstrap Servers**: Create seed nodes for network initialization
- [ ] **Node Registration**: API for new nodes to join the network
- [ ] **Consensus Mechanism**: Implement consensus for transaction approval

### Advanced Cryptography
- [x] **ZK Proof Validation**: Both simple and complex proof structures
- [x] **Ephemeral DKG**: Per-transaction key generation implemented
- [x] **Threshold Cryptography**: 3-of-5 threshold signing implemented
- [ ] **Real ZK Proofs**: Implement actual Groth16 zk-SNARKs
- [ ] **Advanced DKG Protocols**: Feldman VSS, Pedersen commitments
- [ ] **Quantum-Resistant Primitives**: Post-quantum cryptography

### System Integration
- [x] **Multi-Step Transaction Flow**: Complete 5-step transaction process
- [x] **Automatic Cleanup**: Keyshare destruction after transaction completion
- [x] **Health Monitoring**: Node health and status tracking
- [ ] **Multi-Signature Wallets**: Support for multiple signers
- [ ] **Hardware Security Module (HSM)**: Hardware-based key protection
- [ ] **Cross-Platform Support**: Linux and Windows compatibility
- [ ] **Mobile Wallet Support**: iOS and Android applications

### Blockchain Integration
- [ ] **Multi-Chain Support**: Ethereum, Bitcoin, and other networks
- [ ] **Web3 Interface**: Browser-based wallet interface
- [ ] **Smart Contract Integration**: DeFi protocol support
- [ ] **Cross-Chain Transactions**: Interoperability between chains

### Security & Compliance
- [ ] **Formal Verification**: Mathematical proof of security properties
- [ ] **Security Audits**: Third-party security assessments
- [ ] **Regulatory Compliance**: KYC/AML integration
- [ ] **Audit Trails**: Comprehensive transaction logging

## Dependencies

### Core Cryptography
- **arkworks**: Advanced cryptographic library for zk-SNARKs and field operations
- **secp256k1**: Elliptic curve cryptography for wallet generation
- **sha2**: SHA256 hashing for address generation
- **rand**: Cryptographically secure random number generation

### System Integration
- **security-framework**: macOS security integration for Keychain
- **sysinfo**: System monitoring for node health

### Networking & API
- **axum**: Modern async HTTP web framework for REST API
- **tokio**: Async runtime for concurrent operations
- **reqwest**: HTTP client for network communication

### Serialization & Utilities
- **serde**: Serialization framework
- **serde_json**: JSON serialization
- **hex**: Hexadecimal encoding/decoding
- **anyhow**: Error handling
- **clap**: Command-line argument parsing

### Blockchain Integration
- **web3**: Ethereum integration
- **tiny-keccak**: Keccak256 hashing for address generation
- **ethers**: Ethereum utilities

### Logging & Monitoring
- **tracing**: Structured logging
- **tracing-subscriber**: Logging configuration

## Revolutionary Features

### **Trustless Architecture**
This implementation represents a paradigm shift in cryptocurrency wallet security:

- **Zero Key Persistence**: Unlike traditional wallets that store private keys persistently, this system generates ephemeral keys for each transaction
- **Forward Secrecy**: Compromise of one transaction's keys doesn't affect any other transactions
- **No Single Point of Failure**: No persistent private keys exist anywhere in the system
- **Quantum-Resistant Preparation**: Ephemeral keys reduce the attack surface for future quantum attacks

### **Ephemeral DKG Innovation**
- **Per-Transaction Isolation**: Each transaction uses completely unique cryptographic material
- **Advanced Cryptography**: Uses BLS12-381 field elements and elliptic curve commitments
- **Automatic Cleanup**: Keys are destroyed immediately after use
- **Threshold Security**: Maintains security even if some nodes are compromised

### **Security Model**
```
Traditional Wallet:     Master Key → Persistent Storage → Multiple Transactions
Ephemeral Wallet:       Master Key → ZK Proof → Ephemeral DKG → Single Transaction → Destruction
```

This creates an unprecedented level of security where:
- **No persistent attack surface** exists
- **Each transaction is cryptographically isolated**
- **Compromise of one transaction cannot affect others**
- **Keys exist only for the duration of signing**

---
