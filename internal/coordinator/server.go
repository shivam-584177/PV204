package coordinator

import (
	"context"
	"log"

	tsav1 "pv204/gen/go"
)

type Server struct {
	tsav1.UnimplementedCoordinatorServiceServer
	registry *Registry
	sessions *SessionStore
}

func NewServer() *Server {
	return &Server{
		registry: NewRegistry(),
		sessions: NewSessionStore(),
	}
}

func (s *Server) Health(_ context.Context, _ *tsav1.Empty) (*tsav1.HealthStatus, error) {
	return &tsav1.HealthStatus{Status: "ok"}, nil
}

func (s *Server) RegisterNode(_ context.Context, info *tsav1.NodeInfo) (*tsav1.Ack, error) {
	if err := s.registry.Register(info); err != nil {
		return &tsav1.Ack{Ok: false, Message: err.Error()}, nil
	}
	log.Printf("registered signer: %s (%s:%d)", info.NodeId, info.Host, info.Port)
	return &tsav1.Ack{Ok: true}, nil
}

func (s *Server) StartSigning(ctx context.Context, job *tsav1.SignJob) (*tsav1.Ack, error) {
	s.sessions.Create(job.JobId, job.MsgHash)
	// Phase II stub: fan out the msg_hash as payload to all signers
	pkt := &tsav1.TssPacket{
		JobId:    job.JobId,
		FromNode: "coordinator",
		Payload:  job.MsgHash,
	}
	for _, c := range s.registry.All() {
		if _, err := c.Relay(ctx, pkt); err != nil {
			log.Printf("relay to signer failed: %v", err)
		}
	}
	log.Printf("started signing job %s", job.JobId)
	return &tsav1.Ack{Ok: true}, nil
}

func (s *Server) Relay(ctx context.Context, pkt *tsav1.TssPacket) (*tsav1.Ack, error) {
	if pkt.ToNode == "" {
		// Broadcast to all signers
		for _, c := range s.registry.All() {
			if _, err := c.Relay(ctx, pkt); err != nil {
				log.Printf("broadcast relay failed: %v", err)
			}
		}
		return &tsav1.Ack{Ok: true}, nil
	}
	c, ok := s.registry.Get(pkt.ToNode)
	if !ok {
		return &tsav1.Ack{Ok: false, Message: "unknown node: " + pkt.ToNode}, nil
	}
	return c.Relay(ctx, pkt)
}

func (s *Server) GetResult(_ context.Context, req *tsav1.SignJobId) (*tsav1.SignResult, error) {
	return s.sessions.ToResult(req.JobId), nil
}
