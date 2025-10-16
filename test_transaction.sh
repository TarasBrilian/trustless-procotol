set -e

echo "=== Testing Final Transaction Flow ==="
echo ""

NODE_PORT=3000
BASE_URL="http://localhost:${NODE_PORT}"

TRANSACTION_ID="tx_$(date +%s)"
FROM_ADDRESS="0x1234567890abcdef1234567890abcdef12345678"
TO_ADDRESS="0x52b0f78ca732389f96539e8E3E0d02F2796D8bac"
AMOUNT=1000
PUBLIC_KEY="047a0cdb260bb0a1fc98cc42a139332e016aa00df38baa80b4eef1e850e44ecc534a4f69504bb7d3e1ee5132c027cd766c73c9a9cc6dff5cf522911d5547130afd"
CHALLENGE="challenge_$(date +%s)"
THRESHOLD=3
NODE_PORTS=(3000 3001 3002 3003 3004)

echo "Test Configuration:"
echo "  Transaction ID: ${TRANSACTION_ID}"
echo "  From: ${FROM_ADDRESS}"
echo "  To: ${TO_ADDRESS}"
echo "  Amount: ${AMOUNT}"
echo "  Public Key: ${PUBLIC_KEY}"
echo "  Challenge: ${CHALLENGE}"
echo "  Threshold: ${THRESHOLD}"
echo "  Node Ports: ${NODE_PORTS[*]}"
echo ""

generate_proof_data() {
    local pk="$1"
    local challenge="$2"
    echo -n "${pk}${challenge}" | sha256sum | cut -d' ' -f1
}

# Check if all nodes are healthy
check_all_nodes_health() {
    echo "Checking all nodes health..."
    local all_healthy=true
    
    for port in "${NODE_PORTS[@]}"; do
        if curl -s "http://localhost:${port}/health" > /dev/null; then
            echo "Node on port ${port} is healthy"
        else
            echo "Node on port ${port} is not responding"
            all_healthy=false
        fi
    done
    
    if [ "$all_healthy" = true ]; then
        echo "All nodes are healthy"
        return 0
    else
        echo "Some nodes are not responding"
        return 1
    fi
}

check_node_health() {
    echo "Checking node health..."
    if curl -s "${BASE_URL}/health" > /dev/null; then
        echo "Node is running and healthy"
        return 0
    else
        echo "Node is not responding"
        return 1
    fi
}

get_node_status() {
    echo "Getting node status..."
    curl -s "${BASE_URL}/status" | jq '.' || echo "Failed to get node status"
    echo ""
}

submit_transaction_with_zk_proof() {
    echo "=== User Submits Transaction with ZK Proof ==="
    
    local proof_data=$(generate_proof_data "$PUBLIC_KEY" "$CHALLENGE")
    echo "Generated proof data: ${proof_data}"
    
    local transaction_request=$(cat <<EOF
{
    "transaction": {
        "transaction_id": "${TRANSACTION_ID}",
        "sender": "${FROM_ADDRESS}",
        "destination": "${TO_ADDRESS}",
        "amount": ${AMOUNT},
        "nonce": 1,
        "zk_proof": "${proof_data}",
        "public_key": "${PUBLIC_KEY}",
        "challenge": "${CHALLENGE}",
        "timestamp": $(date +%s)
    },
    "public_key": "${PUBLIC_KEY}",
    "challenge": "${CHALLENGE}",
    "threshold": ${THRESHOLD}
}
EOF
)
    
    echo "Submitting transaction with ZK proof..."
    echo "Request: ${transaction_request}"
    echo ""
    
    local response=$(curl -s -X POST "${BASE_URL}/transaction-dkg" \
        -H "Content-Type: application/json" \
        -d "${transaction_request}")
    
    echo "Response:"
    echo "${response}" | jq '.' || echo "${response}"
    echo ""
    
    TRANSACTION_HASH=$(echo "${response}" | jq -r '.transaction_hash // empty')
    if [ -n "$TRANSACTION_HASH" ]; then
        echo "Transaction submitted successfully. Hash: ${TRANSACTION_HASH}"
    else
        echo "Failed to submit transaction"
        return 1
    fi
}

initiate_dkg_and_validation() {
    echo "=== DKG Keyshare Generation and ZK Proof Validation ==="
    
    if [ -z "$TRANSACTION_HASH" ]; then
        echo "No transaction hash available. Please submit transaction first."
        return 1
    fi
    
    local dkg_request=$(cat <<EOF
{
    "transaction_hash": "${TRANSACTION_HASH}",
    "threshold": ${THRESHOLD},
    "participants": ${#NODE_PORTS[@]}
}
EOF
)
    
    echo "Initiating DKG process..."
    echo "Request: ${dkg_request}"
    echo ""
    
    local response=$(curl -s -X POST "${BASE_URL}/dkg/initiate" \
        -H "Content-Type: application/json" \
        -d "${dkg_request}")
    
    echo "DKG Response:"
    echo "${response}" | jq '.' || echo "${response}"
    echo ""

    DKG_SESSION_ID=$(echo "${response}" | jq -r '.session_id // empty')
    if [ -n "$DKG_SESSION_ID" ]; then
        echo "DKG session initiated. Session ID: ${DKG_SESSION_ID}"
    else
        echo "Failed to initiate DKG session"
        return 1
    fi
}

validate_threshold() {
    echo "=== Threshold Validation (Threshold = ${THRESHOLD}) ==="
    
    if [ -z "$DKG_SESSION_ID" ]; then
        echo "No DKG session ID available."
        return 1
    fi
    
    echo "Checking threshold validation on the transaction node..."
    
    local response=$(curl -s "http://localhost:3000/dkg/${DKG_SESSION_ID}/threshold")
    
    local threshold_met=$(echo "${response}" | jq -r '.threshold_met // false')
    local current_shares=$(echo "${response}" | jq -r '.current_shares // 0')
    local required_threshold=$(echo "${response}" | jq -r '.required_threshold // 0')
    
    if [ "$threshold_met" = "true" ]; then
        echo "✓ Threshold validation successful: ${current_shares}/${required_threshold} shares"
    else
        echo "✗ Threshold validation failed: ${current_shares}/${required_threshold} shares"
        return 1
    fi
}

store_keyshares_and_proof() {
    echo "=== Hash and Store Keyshares and ZK Proof ==="
    
    if [ -z "$DKG_SESSION_ID" ] || [ -z "$TRANSACTION_HASH" ]; then
        echo "Missing DKG session ID or transaction hash."
        return 1
    fi
    
    local proof_data=$(generate_proof_data "$PUBLIC_KEY" "$CHALLENGE")
    
    echo "Storing keyshares and proof data on the transaction node..."
    
    local storage_success=true
    for port in "${NODE_PORTS[@]}"; do
        echo "Storing on node ${port} (transaction node)..."
        
        local storage_request=$(cat <<EOF
{
    "transaction_hash": "${TRANSACTION_HASH}",
    "dkg_session_id": "${DKG_SESSION_ID}",
    "zk_proof": "${proof_data}",
    "public_key": "${PUBLIC_KEY}",
    "challenge": "${CHALLENGE}"
}
EOF
)
        
        local response=$(curl -s -X POST "http://localhost:${port}/storage/store" \
            -H "Content-Type: application/json" \
            -d "${storage_request}")
        
        local success=$(echo "${response}" | jq -r '.success // false')
        if [ "$success" = "true" ]; then
            echo "✓ Node ${port}: Storage successful"
        else
            echo "✗ Node ${port}: Storage failed"
            storage_success=false
        fi
    done
    
    if [ "$storage_success" = true ]; then
        echo "Keyshares and proof data stored successfully on all nodes"
    else
        echo "Storage failed on some nodes"
        return 1
    fi
}

cleanup_keyshares() {
    echo "=== Cleanup Keyshares After Transaction Fulfillment ==="
    
    if [ -z "$DKG_SESSION_ID" ] || [ -z "$TRANSACTION_HASH" ]; then
        echo "Missing DKG session ID or transaction hash."
        return 1
    fi
    
    echo "Cleaning up keyshares on the transaction node..."
    
    local cleanup_success=true
    for port in "${NODE_PORTS[@]}"; do
        echo "Cleaning up on node ${port}..."
        
        local cleanup_request=$(cat <<EOF
{
    "transaction_hash": "${TRANSACTION_HASH}",
    "dkg_session_id": "${DKG_SESSION_ID}"
}
EOF
)
        
        local response=$(curl -s -X POST "http://localhost:${port}/dkg/cleanup" \
            -H "Content-Type: application/json" \
            -d "${cleanup_request}")
        
        local success=$(echo "${response}" | jq -r '.success // false')
        if [ "$success" = "true" ]; then
            echo "Node ${port}: Cleanup successful"
        else
            echo "Node ${port}: Cleanup failed"
            cleanup_success=false
        fi
    done
    
    if [ "$cleanup_success" = true ]; then
        echo "Keyshares cleaned up successfully on all nodes"
    else
        echo "Cleanup failed on some nodes"
        return 1
    fi
}


main() {
    echo "Starting DKG-based Transaction Flow Test..."
    echo ""

    if ! check_all_nodes_health; then
        echo "Please start all nodes first using: ./start_p2p_nodes.sh"
        exit 1
    fi
    
    echo ""
    echo "=== Executing DKG Transaction Flow ==="
    echo ""
    
    if ! submit_transaction_with_zk_proof; then
        echo "Transaction submission failed"
        exit 1
    fi
    
    echo ""
    sleep 2
    
    if ! initiate_dkg_and_validation; then
        echo "DKG initiation and validation failed"
        exit 1
    fi
    
    echo ""
    sleep 3
    
    if ! validate_threshold; then
        echo "Threshold validation failed"
        exit 1
    fi
    
    echo ""
    sleep 2
    
    if ! store_keyshares_and_proof; then
        echo "Keyshare and proof storage failed"
        exit 1
    fi
    
    echo ""
    sleep 2
    
    if ! cleanup_keyshares; then
        echo "Keyshare cleanup failed"
        exit 1
    fi
}

main "$@"
