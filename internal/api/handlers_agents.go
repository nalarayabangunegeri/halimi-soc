package api

import (
	"errors"
	"net/http"

	"github.com/halimi/halimisoc/internal/agents"
	"github.com/halimi/halimisoc/internal/audit"
	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/events/validation"
	"github.com/halimi/halimisoc/internal/id"
	"github.com/halimi/halimisoc/internal/metrics"
	"github.com/halimi/halimisoc/internal/secret"
	"github.com/halimi/halimisoc/internal/storage"
)

// handleListAgents returns the enrolled agents.
func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermViewAgents) {
		return
	}
	list, err := s.store.ListAgents(r.Context())
	if err != nil {
		s.fail(w, err, "list agents")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agents": nonNil(list)})
}

type enrollRequest struct {
	// EnrollmentSecret authorizes the enrollment.
	EnrollmentSecret string `json:"enrollment_secret"`

	Host    string `json:"host"`
	OS      string `json:"os"`
	Version string `json:"version"`
}

type enrollResponse struct {
	AgentID string `json:"agent_id"`
	Host    string `json:"host"`

	// AgentToken is returned exactly once. The server stores only its hash, so
	// a lost token can only be replaced by rotating it, never recovered.
	AgentToken string `json:"agent_token"`
	TokenID    string `json:"token_id"`
}

// handleRegisterAgent exchanges an enrollment secret for a per-agent token.
//
// The enrollment secret is a shared bootstrap credential, so it is compared in
// constant time and its use is audited. The resulting per-agent token is what
// authenticates ingestion, which means one compromised agent cannot be used to
// impersonate another.
//
// Enrollment is rate-limited per source address and globally: without it the
// shared secret is an online brute-force oracle. Failed attempts back off, a
// success clears the source key.
func (s *Server) handleRegisterAgent(w http.ResponseWriter, r *http.Request) {
	if s.enrollSecret == "" {
		writeError(w, http.StatusServiceUnavailable, CodeUnavailable, "agent enrollment is not configured")
		return
	}

	now := s.now()
	ip := clientIP(r)
	ipKey := "enroll:ip:" + ip
	globalKey := "enroll:global"
	if wait := s.limiter.RetryAfter(ipKey, now); wait > 0 {
		s.reg.Inc(metrics.EnrollRateLimitedTotal)
		w.Header().Set("Retry-After", formatSeconds(wait))
		writeError(w, http.StatusTooManyRequests, CodeRateLimited, "too many attempts, try again later")
		return
	}
	if wait := s.limiter.RetryAfter(globalKey, now); wait > 0 {
		s.reg.Inc(metrics.EnrollRateLimitedTotal)
		w.Header().Set("Retry-After", formatSeconds(wait))
		writeError(w, http.StatusTooManyRequests, CodeRateLimited, "too many attempts, try again later")
		return
	}

	var req enrollRequest
	if err := s.decodeJSON(w, r, &req, 16<<10); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}

	if !secret.EqualHash(secret.HashToken(req.EnrollmentSecret), secret.HashToken(s.enrollSecret)) {
		s.limiter.Fail(ipKey, now)
		s.limiter.Fail(globalKey, now)
		s.writeAudit(r, audit.Entry{
			Actor:    audit.ActorRef(audit.ActorSystem, "enrollment"),
			Action:   audit.ActionAgentEnrolled,
			Resource: "agent",
			Result:   audit.ResultDenied,
			Detail:   "invalid enrollment secret",
		})
		writeError(w, http.StatusUnauthorized, CodeUnauthorized, "invalid enrollment credential")
		return
	}

	host, err := validation.CanonicalHost(req.Host, 255)
	if err != nil || host == "" {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid host")
		return
	}
	osName, err := validation.Printable(req.OS, 128)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid os field")
		return
	}
	version, err := validation.Printable(req.Version, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid version field")
		return
	}

	agentID := id.New(id.KindAgent)

	// Re-enrolling the same host replaces its identity rather than creating a
	// duplicate, so a rebuilt machine does not leave a stale agent behind.
	if existing, err := s.store.GetAgentByHost(r.Context(), host); err == nil && existing != nil {
		agentID = existing.ID
		if err := s.store.RevokeTokensForAgent(r.Context(), agentID, now); err != nil {
			s.log.Warn("revoke old tokens failed", "agent", agentID, "error", err)
		}
	} else if err != nil && !errors.Is(err, storage.ErrNotFound) {
		s.fail(w, err, "lookup agent")
		return
	}

	agent := &agents.Agent{
		ID:            agentID,
		Host:          host,
		OS:            osName,
		Version:       version,
		Status:        agents.StatusOnline,
		EnrolledAt:    now,
		LastHeartbeat: now,
	}
	if err := agent.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid agent metadata")
		return
	}
	if err := s.store.SaveAgent(r.Context(), agent); err != nil {
		s.fail(w, err, "save agent")
		return
	}

	token, hash, err := secret.NewToken("agt_")
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeInternal, "could not issue a credential")
		return
	}
	record := &agents.Token{
		ID:        id.New(id.KindToken),
		AgentID:   agentID,
		TokenHash: hash,
		Prefix:    secret.Prefix(token),
		CreatedAt: now,
	}
	if err := s.store.SaveToken(r.Context(), record); err != nil {
		s.fail(w, err, "save agent token")
		return
	}

	s.writeAudit(r, audit.Entry{
		Actor:      audit.ActorRef(audit.ActorAgent, agentID),
		Action:     audit.ActionAgentEnrolled,
		Resource:   "agent",
		ResourceID: agentID,
		Result:     audit.ResultSuccess,
		Detail:     "host=" + host,
	})
	s.limiter.Succeed(ipKey)

	writeJSON(w, http.StatusCreated, enrollResponse{
		AgentID:    agentID,
		Host:       host,
		AgentToken: token,
		TokenID:    record.ID,
	})
}

type heartbeatRequest struct {
	QueueDepth int64 `json:"queue_depth"`
	SpoolBytes int64 `json:"spool_bytes"`
	Degraded   bool  `json:"degraded"`
}

// handleHeartbeat records agent liveness and self-reported buffer health.
//
// The path carries the agent id, so a credential cannot be used to report
// liveness for a different agent. The id is checked against the credential
// rather than trusted: the credential is the authority, and the path value is
// an untrusted claim that must agree with it.
func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	p := s.authenticateAgent(w, r)
	if p == nil {
		return
	}
	if id := r.PathValue("id"); id != p.Agent.AgentID {
		writeError(w, http.StatusForbidden, CodeForbidden,
			"agent credential does not match the requested agent")
		return
	}

	var req heartbeatRequest
	// A heartbeat with no body is valid: the agent may simply be reporting in.
	if err := s.decodeOptionalJSON(w, r, &req, 4<<10); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}

	status := agents.StatusOnline
	if req.Degraded {
		status = agents.StatusDegraded
	}
	now := s.now()
	if err := s.store.UpdateAgentHeartbeat(r.Context(), p.Agent.AgentID, now, req.QueueDepth, req.SpoolBytes, status); err != nil {
		s.fail(w, err, "update heartbeat")
		return
	}
	s.reg.Set(metrics.AgentLastHeartbeat, float64(now.Unix()))

	// Report the agent's new state to the dashboard rather than making it poll.
	if agent, err := s.store.GetAgent(r.Context(), p.Agent.AgentID); err == nil {
		s.publishAgent(agent)
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": string(status), "server_time": now})
}

// handleRotateAgentToken issues a new token and invalidates the old one.
func (s *Server) handleRotateAgentToken(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermManageAgents) {
		return
	}
	if !s.requireCSRF(w, r, p) {
		return
	}

	agentID := r.PathValue("id")
	if _, err := s.store.GetAgent(r.Context(), agentID); err != nil {
		s.fail(w, err, "get agent")
		return
	}

	now := s.now()
	token, hash, err := secret.NewToken("agt_")
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeInternal, "could not issue a credential")
		return
	}
	record := &agents.Token{
		ID:        id.New(id.KindToken),
		AgentID:   agentID,
		TokenHash: hash,
		Prefix:    secret.Prefix(token),
		CreatedAt: now,
	}
	// Rotation is a single logical operation: the old credential must be
	// invalidated before the new one is usable, otherwise a stolen token would
	// survive rotation.
	if err := s.store.RotateTokensForAgent(r.Context(), agentID, now); err != nil {
		s.fail(w, err, "rotate agent tokens")
		return
	}
	if err := s.store.SaveToken(r.Context(), record); err != nil {
		s.fail(w, err, "save rotated token")
		return
	}

	s.writeAudit(r, audit.Entry{
		Actor:      actorName(p),
		Action:     audit.ActionAgentTokenRotated,
		Resource:   "agent",
		ResourceID: agentID,
		Result:     audit.ResultSuccess,
		Detail:     "new token " + record.Prefix,
	})
	writeJSON(w, http.StatusOK, enrollResponse{
		AgentID:    agentID,
		AgentToken: token,
		TokenID:    record.ID,
	})
}

// handleRevokeAgent revokes an agent and every token it holds.
func (s *Server) handleRevokeAgent(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermManageAgents) {
		return
	}
	if !s.requireCSRF(w, r, p) {
		return
	}

	agentID := r.PathValue("id")
	now := s.now()
	if err := s.store.RevokeAgent(r.Context(), agentID, now); err != nil {
		s.fail(w, err, "revoke agent")
		return
	}
	if err := s.store.RevokeTokensForAgent(r.Context(), agentID, now); err != nil {
		s.fail(w, err, "revoke agent tokens")
		return
	}

	s.writeAudit(r, audit.Entry{
		Actor:      actorName(p),
		Action:     audit.ActionAgentTokenRevoked,
		Resource:   "agent",
		ResourceID: agentID,
		Result:     audit.ResultSuccess,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// errEmptyBody signals a legitimately empty request body.
var errEmptyBody = errors.New("empty body")

// handleAgentSelf returns the calling agent's own record.
//
// The agent has no persistent identity of its own: it is a stateless process
// that may be restarted with only a token. This endpoint lets it discover its
// assigned id so it can address the id-scoped endpoints.
func (s *Server) handleAgentSelf(w http.ResponseWriter, r *http.Request) {
	p := s.authenticateAgent(w, r)
	if p == nil {
		return
	}
	agent, err := s.store.GetAgent(r.Context(), p.Agent.AgentID)
	if err != nil {
		s.fail(w, err, "get agent")
		return
	}
	writeJSON(w, http.StatusOK, agent)
}

// handleGetAgent returns one agent by id. Operators only.
func (s *Server) handleGetAgent(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermViewAgents) {
		return
	}
	agent, err := s.store.GetAgent(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err, "get agent")
		return
	}
	writeJSON(w, http.StatusOK, agent)
}
