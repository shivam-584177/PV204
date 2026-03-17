package coordinator

import (
	"sync"

	tsav1 "pv204/gen/go"
)

type Session struct {
	JobID   string
	MsgHash []byte
	Status  string // "pending" / "done" / "error"
}

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[string]*Session)}
}

// Create initialises a new signing session.
func (s *SessionStore) Create(jobID string, msgHash []byte) *Session {
	sess := &Session{JobID: jobID, MsgHash: msgHash, Status: "pending"}
	s.mu.Lock()
	s.sessions[jobID] = sess
	s.mu.Unlock()
	return sess
}

// Get looks up a session by job ID.
func (s *SessionStore) Get(jobID string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[jobID]
	return sess, ok
}

// ToResult converts a session into a SignResult proto message.
func (s *SessionStore) ToResult(jobID string) *tsav1.SignResult {
	sess, ok := s.Get(jobID)
	if !ok {
		return &tsav1.SignResult{JobId: jobID, Status: "error", Message: "unknown job"}
	}
	return &tsav1.SignResult{JobId: sess.JobID, Status: sess.Status}
}
