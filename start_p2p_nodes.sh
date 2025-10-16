echo "Starting ZK-Wallet Nodes with P2P Communication"
echo "=================================================="

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_status "Stopping any existing nodes..."
pkill -f "zk-signing start-node" || true
sleep 2

print_status "Starting nodes with P2P communication..."

PORTS=(3000 3001 3002 3003 3004)

for port in "${PORTS[@]}"; do
    print_status "Starting node on port $port..."
    
    cargo run start-node $port > "node_${port}.log" 2>&1 &
    NODE_PID=$!
    
    sleep 3
    
    if curl -s http://localhost:$port/health > /dev/null 2>&1; then
        print_success "Node on port $port started successfully (PID: $NODE_PID)"
    else
        print_error "Failed to start node on port $port"
    fi
done

echo ""
print_status "Waiting for all nodes to initialize..."
sleep 10

print_status "Verifying all nodes are active..."

ALL_NODES_ACTIVE=true
for port in "${PORTS[@]}"; do
    if curl -s http://localhost:$port/health > /dev/null 2>&1; then
        print_success "Node on port $port is healthy"
        
        NODE_INFO=$(curl -s http://localhost:$port/status | jq .)
        NODE_ID=$(echo "$NODE_INFO" | jq -r '.node_id')
        print_status "  Node ID: $NODE_ID"
    else
        print_error "Node on port $port is not responding"
        ALL_NODES_ACTIVE=false
    fi
done

if [ "$ALL_NODES_ACTIVE" = false ]; then
    print_error "Not all nodes are active. Please check the logs and restart."
    exit 1
fi

print_success "All nodes are active! Proceeding with peer connections..."

echo ""
print_status "Starting controlled peer connections..."

print_status "Initiating peer connection from node 3000 to node 3004..."
if curl -s -X POST http://localhost:3000/network/connect -H "Content-Type: application/json" -d '{"peer_url": "http://localhost:3004"}' > /dev/null 2>&1; then
    print_success "Successfully initiated connection from node 3000 to node 3004"
else
    print_warning "Failed to initiate connection from node 3000 to node 3004"
fi

print_status "Waiting for peer discovery to propagate..."
sleep 10

print_status "Checking peer connections..."

for port in "${PORTS[@]}"; do
    print_status "Checking peers for node on port $port..."
    PEERS=$(curl -s http://localhost:$port/network/peers | jq .)
    PEER_COUNT=$(echo "$PEERS" | jq 'length')
    
    if [ "$PEER_COUNT" -gt 0 ]; then
        print_success "Node $port has $PEER_COUNT peers"
        echo "Peers:"
        echo "$PEERS" | jq .
    else
        print_warning "Node $port has no peers yet"
    fi
    echo ""
done

echo ""
print_status "Node endpoints:"
for port in "${PORTS[@]}"; do
    echo "  - http://localhost:$port"
done
echo ""
print_status "Transaction logs:"
for port in "${PORTS[@]}"; do
    echo "  - transaction_${port}.log"
done
