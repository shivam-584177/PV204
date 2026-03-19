package main

import (
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	tsav1 "pv204/gen/go"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type coordinatorServer struct {
	tsav1.UnimplementedCoordinatorServiceServer
	mu    sync.Mutex
	nodes map[string]*tsav1.NodeInfo
}

func newCoordinatorServer() *coordinatorServer {
	return &coordinatorServer{
		nodes: make(map[string]*tsav1.NodeInfo),
	}
}

func (s *coordinatorServer) RegisterNode(ctx context.Context, info *tsav1.NodeInfo) (*tsav1.Ack, error) {
	s.mu.Lock()
	s.nodes[info.NodeId] = info
	s.mu.Unlock()

	log.Printf("[coord] node registered: %s at %s:%d", info.NodeId, info.Host, info.Port)

	// Automatically trigger one Phase II signing request shortly after registration.
	go func(n *tsav1.NodeInfo) {
		time.Sleep(1 * time.Second)
		if err := s.triggerNode(n, "phase2-demo-job"); err != nil {
			log.Printf("[coord] trigger failed for %s: %v", n.NodeId, err)
		}
	}(info)

	return &tsav1.Ack{Ok: true, Message: "registered"}, nil
}

func (s *coordinatorServer) Health(context.Context, *tsav1.Empty) (*tsav1.HealthStatus, error) {
	return &tsav1.HealthStatus{Status: "ok", Message: "mock coordinator ready"}, nil
}

func (s *coordinatorServer) StartSigning(ctx context.Context, job *tsav1.SignJob) (*tsav1.Ack, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, n := range s.nodes {
		if err := s.triggerNode(n, job.JobId); err != nil {
			return &tsav1.Ack{Ok: false, Message: err.Error()}, nil
		}
	}
	return &tsav1.Ack{Ok: true, Message: "signing triggered"}, nil
}

func (s *coordinatorServer) Relay(ctx context.Context, pkt *tsav1.TssPacket) (*tsav1.Ack, error) {
	log.Printf("[coord] relay from signer: job=%s from=%s to=%s payload_len=%d",
		pkt.JobId, pkt.FromNode, pkt.ToNode, len(pkt.Payload))
	return &tsav1.Ack{Ok: true, Message: "relay received by coordinator"}, nil
}

func (s *coordinatorServer) GetResult(context.Context, *tsav1.SignJobId) (*tsav1.SignResult, error) {
	return &tsav1.SignResult{
		Status:  "pending",
		Message: "mock coordinator does not assemble final signature in Phase II",
	}, nil
}

func (s *coordinatorServer) triggerNode(n *tsav1.NodeInfo, jobID string) error {
	addr := fmt.Sprintf("%s:%d", n.Host, n.Port)

	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("dial signer %s: %w", addr, err)
	}
	defer conn.Close()

	client := tsav1.NewSignerServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	health, err := client.Health(ctx, &tsav1.Empty{})
	if err != nil {
		return fmt.Errorf("signer health failed: %w", err)
	}
	log.Printf("[coord] signer health: %s - %s", health.Status, health.Message)

	hash := sha256.Sum256([]byte("phase2-demo-document"))

	ack, err := client.Relay(ctx, &tsav1.TssPacket{
		JobId:    jobID,
		FromNode: "coordinator",
		ToNode:   n.NodeId,
		Payload:  hash[:],
	})
	if err != nil {
		return fmt.Errorf("relay trigger failed: %w", err)
	}

	log.Printf("[coord] signer relay ack: ok=%v msg=%s", ack.Ok, ack.Message)
	return nil
}

func main() {
	listen := flag.String("listen", "localhost:50050", "listen address")
	flag.Parse()

	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	s := grpc.NewServer()
	tsav1.RegisterCoordinatorServiceServer(s, newCoordinatorServer())

	log.Printf("[coord] mock coordinator listening on %s", *listen)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
