package coordinator

import (
	"fmt"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	tsav1 "pv204/gen/go"
)

type signerConn struct {
	info   *tsav1.NodeInfo
	client tsav1.SignerServiceClient
}

type Registry struct {
	mu    sync.RWMutex
	nodes map[string]*signerConn
}

func NewRegistry() *Registry {
	return &Registry{nodes: make(map[string]*signerConn)}
}

// Register dials the signer node and stores the connection.
func (r *Registry) Register(info *tsav1.NodeInfo) error {
	addr := fmt.Sprintf("%s:%d", info.Host, info.Port)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.nodes[info.NodeId] = &signerConn{info: info, client: tsav1.NewSignerServiceClient(conn)}
	r.mu.Unlock()
	return nil
}

// Get returns the SignerServiceClient for a given node ID.
func (r *Registry) Get(nodeID string) (tsav1.SignerServiceClient, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.nodes[nodeID]
	if !ok {
		return nil, false
	}
	return c.client, true
}

// All returns all registered signer clients.
func (r *Registry) All() []tsav1.SignerServiceClient {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]tsav1.SignerServiceClient, 0, len(r.nodes))
	for _, c := range r.nodes {
		out = append(out, c.client)
	}
	return out
}
