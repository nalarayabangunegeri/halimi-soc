package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/halimi/halimisoc/internal/audit"
	"github.com/halimi/halimisoc/internal/auth"
	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/id"
	"github.com/halimi/halimisoc/internal/storage"
)

type createUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type userStatusRequest struct {
	Disabled bool `json:"disabled"`
}

// handleListUsers returns every operator account. Password hashes are never
// serialised: auth.User tags the hash json:"-", so even a broad struct dump
// cannot leak it.
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermManageUsers) {
		return
	}
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.fail(w, err, "list users")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": nonNilUsers(users)})
}

// handleCreateUser creates an operator account. Only an admin may do this, and
// the new credential follows the same minimums as the bootstrap admin: a short
// password here would be a weaker lock on the same door.
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermManageUsers) {
		return
	}
	if !s.requireCSRF(w, r, p) {
		return
	}

	var req createUserRequest
	if err := s.decodeJSON(w, r, &req, 4<<10); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}

	username := strings.ToLower(strings.TrimSpace(req.Username))
	if !validUsername(username) {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "username must be 3-64 lowercase alphanumeric characters, dots, dashes or underscores")
		return
	}
	if len(req.Password) < 12 {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "password must be at least 12 characters")
		return
	}
	role := authorization.Role(strings.ToUpper(strings.TrimSpace(req.Role)))
	if !role.Valid() {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "unknown role")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		s.log.Error("hash user password failed", "error", err)
		writeError(w, http.StatusInternalServerError, CodeInternal, "could not create the account")
		return
	}
	now := s.now()
	u := &auth.User{
		ID:           id.New(id.KindUser),
		Username:     username,
		PasswordHash: hash,
		Role:         role,
		CreatedAt:    now,
	}
	if err := s.store.SaveUser(r.Context(), u); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			writeError(w, http.StatusConflict, CodeConflict, "username already exists")
			return
		}
		s.fail(w, err, "create user")
		return
	}
	s.writeAudit(r, audit.Entry{
		Actor:      audit.ActorRef(audit.ActorUser, p.User.Username),
		Action:     audit.ActionUserCreated,
		Resource:   "user",
		ResourceID: u.ID,
		Result:     audit.ResultSuccess,
		Detail:     "role " + string(role),
	})
	writeJSON(w, http.StatusCreated, u)
}

// handleUpdateUserStatus disables or re-enables an account. Disabling revokes
// the account's sessions immediately: a disabled credential must not keep a
// live session, or the disable is theatre.
func (s *Server) handleUpdateUserStatus(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermManageUsers) {
		return
	}
	if !s.requireCSRF(w, r, p) {
		return
	}

	var req userStatusRequest
	if err := s.decodeJSON(w, r, &req, 4<<10); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}

	target, err := s.store.GetUser(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err, "get user")
		return
	}
	if req.Disabled {
		if target.ID == p.User.ID {
			writeError(w, http.StatusConflict, CodeConflict, "an operator cannot disable their own account")
			return
		}
		if target.Role == authorization.RoleAdmin && target.Active() {
			last, err := s.lastActiveAdmin(r, target.ID)
			if err != nil {
				s.fail(w, err, "count admins")
				return
			}
			if last {
				writeError(w, http.StatusConflict, CodeConflict, "cannot disable the last active administrator")
				return
			}
		}
	}

	target.Disabled = req.Disabled
	if err := s.store.SaveUser(r.Context(), target); err != nil {
		s.fail(w, err, "update user status")
		return
	}
	if req.Disabled {
		if err := s.store.RevokeUserSessions(r.Context(), target.ID, s.now()); err != nil {
			s.log.Warn("revoke disabled user sessions failed", "user", target.ID, "error", err)
		}
		s.PublishSessionRevokedForUser(target.ID)
	}
	s.writeAudit(r, audit.Entry{
		Actor:      audit.ActorRef(audit.ActorUser, p.User.Username),
		Action:     audit.ActionUserDisabled,
		Resource:   "user",
		ResourceID: target.ID,
		Result:     audit.ResultSuccess,
		Detail:     disabledDetail(req.Disabled),
	})
	writeJSON(w, http.StatusOK, target)
}

// lastActiveAdmin reports whether id is the only remaining active admin.
func (s *Server) lastActiveAdmin(r *http.Request, id string) (bool, error) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		return false, err
	}
	active := 0
	for _, u := range users {
		if u.Role == authorization.RoleAdmin && u.Active() && u.ID != id {
			active++
		}
	}
	return active == 0, nil
}

func disabledDetail(disabled bool) string {
	if disabled {
		return "account disabled"
	}
	return "account re-enabled"
}

// validUsername keeps login and creation consistent: the login path lowercases
// and trims, so creation must accept exactly the normalised shape.
func validUsername(u string) bool {
	if len(u) < 3 || len(u) > 64 {
		return false
	}
	for i := 0; i < len(u); i++ {
		c := u[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '.' || c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}

func nonNilUsers(in []*auth.User) []*auth.User {
	if in == nil {
		return []*auth.User{}
	}
	return in
}

// PublishSessionRevokedForUser is a hook for realtime session invalidation.
// The SSE hub revalidates on every event and keepalive tick, so revoked
// sessions already terminate within one interval; this is the explicit signal.
func (s *Server) PublishSessionRevokedForUser(userID string) {
	s.hub.RevokeUserSessions(userID)
}
