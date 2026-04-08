package coordinator

import (
	"context"
	"log"

	tsav1 "pv204/gen/go"
)

type Server struct {
	tsav1.UnimplementedCoordinatorServiceServer
	registry  *Registry
	sessions  *SessionStore
	Threshold int
	secret    string
}

func NewServer(threshold int, secret string) *Server {
	return &Server{
		registry:  NewRegistry(),
		sessions:  NewSessionStore(),
		Threshold: threshold,
		secret:    secret,
	}
}

func (s *Server) Health(_ context.Context, _ *tsav1.Empty) (*tsav1.HealthStatus, error) {
	return &tsav1.HealthStatus{Status: "ok"}, nil
}

func (s *Server) RegisterNode(_ context.Context, info *tsav1.NodeInfo) (*tsav1.Ack, error) {
	if s.secret != "" && info.Token != s.secret {
		log.Printf("rejected unauthorized registration attempt from node: %s", info.NodeId)
		return &tsav1.Ack{Ok: false, Message: "unauthorized"}, nil
	}
	if err := s.registry.Register(info); err != nil {
		return &tsav1.Ack{Ok: false, Message: err.Error()}, nil
	}
	log.Printf("registered signer: %s (%s:%d)", info.NodeId, info.Host, info.Port)
	return &tsav1.Ack{Ok: true}, nil
}

func (s *Server) StartSigning(ctx context.Context, job *tsav1.SignJob) (*tsav1.Ack, error) {
	// Reject duplicate job IDs — prevents replay attacks and silent session overwrites.
	if _, exists := s.sessions.Get(job.JobId); exists {
		return &tsav1.Ack{Ok: false, Message: "duplicate job_id"}, nil
	}

	s.sessions.Create(job.JobId, job.MsgHash)
	pkt := &tsav1.TssPacket{
		JobId:    job.JobId,
		FromNode: "coordinator",
		Payload:  job.MsgHash,
	}
	// Contact ALL registered signers. GG20 requires all n parties to participate
	// in every round. The threshold t is enforced cryptographically: at least t+1
	// parties must cooperate to produce a valid signature. Contacting only a subset
	// would cause the others to wait for missing messages and deadlock.
	for _, c := range s.registry.All() {
		if _, err := c.Relay(ctx, pkt); err != nil {
			log.Printf("relay to signer failed: %v", err)
		}
	}
	log.Printf("started signing job %s (threshold=%d)", job.JobId, s.Threshold)
	return &tsav1.Ack{Ok: true}, nil
}

func (s *Server) Relay(ctx context.Context, pkt *tsav1.TssPacket) (*tsav1.Ack, error) {
	if pkt.ToNode == "" {
		for nodeID, c := range s.registry.nodes {
			if nodeID == pkt.FromNode {
				continue
			}
			if _, err := c.client.Relay(ctx, pkt); err != nil {
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

func (s *Server) ReportResult(_ context.Context, req *tsav1.SignResult) (*tsav1.Ack, error) {
	if req.GetJobId() == "" {
		return &tsav1.Ack{Ok: false, Message: "missing job_id"}, nil
	}
	if len(req.GetSignature()) == 0 {
		return &tsav1.Ack{Ok: false, Message: "missing signature"}, nil
	}
	if len(req.GetPubkey()) == 0 {
		return &tsav1.Ack{Ok: false, Message: "missing pubkey"}, nil
	}

	ok := s.sessions.Complete(req.JobId, req.Signature, req.Pubkey)
	if !ok {
		return &tsav1.Ack{Ok: false, Message: "unknown job: " + req.JobId}, nil
	}

	log.Printf("completed signing job %s", req.JobId)
	return &tsav1.Ack{Ok: true}, nil
}
