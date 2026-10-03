// Package authorization enforces the RBAC contract server-side.
//
// DESIGN.md §15.5 and PRD FR-01 define three MVP roles and an operation matrix.
// Authorization is checked here, in domain code, and never inferred from the
// presence or absence of a UI control: hiding a button is not a security
// control, because the API can be called directly.
package authorization

import "fmt"

// Role is an operator role.
type Role string

const (
	RoleAdmin    Role = "ADMIN"
	RoleAnalyst  Role = "ANALYST"
	RoleReadonly Role = "READONLY"
)

// RoleSet is the closed set of roles.
var RoleSet = []Role{RoleAdmin, RoleAnalyst, RoleReadonly}

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	for _, v := range RoleSet {
		if v == r {
			return true
		}
	}
	return false
}

// Permission is a named operation that requires authorization.
type Permission string

const (
	PermViewEvents           Permission = "view_events"
	PermViewAlerts           Permission = "view_alerts"
	PermViewIncidents        Permission = "view_incidents"
	PermViewAgents           Permission = "view_agents"
	PermViewAssets           Permission = "view_assets"
	PermViewAudit            Permission = "view_audit"
	PermRunAIAnalysis        Permission = "run_ai_analysis"
	PermChangeAlertStatus    Permission = "change_alert_status"
	PermChangeIncidentStatus Permission = "change_incident_status"
	PermManageRules          Permission = "manage_rules"
	PermManageAgents         Permission = "manage_agents"
	PermManageUsers          Permission = "manage_users"
	PermApproveResponse      Permission = "approve_response"
)

// PermissionSet is every permission the server knows about.
var PermissionSet = []Permission{
	PermViewEvents, PermViewAlerts, PermViewIncidents, PermViewAgents,
	PermViewAssets, PermViewAudit, PermRunAIAnalysis,
	PermChangeAlertStatus, PermChangeIncidentStatus,
	PermManageRules, PermManageAgents, PermManageUsers, PermApproveResponse,
}

// matrix encodes the PRD permission baseline.
//
// Read access is granted to every authenticated role; mutation is restricted to
// the roles the PRD names. The map is exhaustive over PermissionSet, which is
// asserted by a test so a newly added permission cannot default to allowed.
var matrix = map[Permission]map[Role]bool{
	PermViewEvents:           {RoleAdmin: true, RoleAnalyst: true, RoleReadonly: true},
	PermViewAlerts:           {RoleAdmin: true, RoleAnalyst: true, RoleReadonly: true},
	PermViewIncidents:        {RoleAdmin: true, RoleAnalyst: true, RoleReadonly: true},
	PermViewAgents:           {RoleAdmin: true, RoleAnalyst: true, RoleReadonly: true},
	PermViewAssets:           {RoleAdmin: true, RoleAnalyst: true, RoleReadonly: true},
	PermViewAudit:            {RoleAdmin: true, RoleAnalyst: false, RoleReadonly: false},
	PermRunAIAnalysis:        {RoleAdmin: true, RoleAnalyst: true, RoleReadonly: true},
	PermChangeAlertStatus:    {RoleAdmin: true, RoleAnalyst: true, RoleReadonly: false},
	PermChangeIncidentStatus: {RoleAdmin: true, RoleAnalyst: true, RoleReadonly: false},
	PermManageRules:          {RoleAdmin: true, RoleAnalyst: false, RoleReadonly: false},
	PermManageAgents:         {RoleAdmin: true, RoleAnalyst: false, RoleReadonly: false},
	PermManageUsers:          {RoleAdmin: true, RoleAnalyst: false, RoleReadonly: false},

	// Response execution is post-MVP. Only an admin may ever approve, and the
	// MVP exposes no endpoint that performs the action.
	PermApproveResponse: {RoleAdmin: true, RoleAnalyst: false, RoleReadonly: false},
}

// Allowed reports whether role may perform perm.
//
// Unknown permissions and unknown roles both deny. This is fail-closed: adding
// a permission without updating the matrix denies access rather than granting
// it, so a missing entry cannot silently become a privilege escalation.
func Allowed(role Role, perm Permission) bool {
	roles, ok := matrix[perm]
	if !ok {
		return false
	}
	return roles[role]
}

// Require returns an error when role may not perform perm.
func Require(role Role, perm Permission) error {
	if !Allowed(role, perm) {
		return fmt.Errorf("role %s is not permitted to %s", role, perm)
	}
	return nil
}
