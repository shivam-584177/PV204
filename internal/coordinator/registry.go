package coordinator

import (
	"fmt"
	"sort"
	"sync"

	tsav1 "pv204/gen/go"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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

// AllExcept returns all signer clients except the one with the given nodeID.
// Used for broadcast relay to avoid echoing a message back to its sender.
func (r *Registry) AllExcept(excludeID string) []tsav1.SignerServiceClient {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]tsav1.SignerServiceClient, 0, len(r.nodes))
	for id, c := range r.nodes {
		if id != excludeID {
			out = append(out, c.client)
		}
	}
	return out
}

// Select returns k signer clients chosen deterministically by sorted node ID.
func (r *Registry) Select(k int) []tsav1.SignerServiceClient {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0, len(r.nodes))
	for id := range r.nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	if k <= 0 || k >= len(ids) {
		k = len(ids)
	}

	out := make([]tsav1.SignerServiceClient, 0, k)
	for _, id := range ids[:k] {
		out = append(out, r.nodes[id].client)
	}
	return out
}
