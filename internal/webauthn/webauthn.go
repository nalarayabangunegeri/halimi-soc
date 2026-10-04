// Package webauthn implements a minimal, stdlib-only WebAuthn (passkey)
// verifier for the second-factor/passwordless login.
//
// Scope (deliberate, documented in ADR-015):
//   - COSE ES256 (-7, P-256) only. RSA/OKP rejected.
//   - Attestation "none" and "packed" self-attestation only. Other formats
//     (tpm, android-key, fido-u2f, apple) rejected with a clear error.
//   - User verification REQUIRED on register and login (passkey-grade).
//   - RP ID + exact origin allowlist checked server-side on every ceremony.
//   - Clone detection via sign-count (reject presented <= stored when both >0).
//   - Challenges are 32 random bytes, single-use, 5-minute TTL, in-memory
//     (single-node MVP, like the login limiter).
//
// Wire encoding notes:
//   - clientDataJSON is JSON {type,challenge,origin}.
//   - attestationObject and credentialPublicKey are CBOR; a minimal decoder
//     below handles the subset WebAuthn emits (uint/negint/bytes/text/array/map).
//   - ECDSA signatures are ASN.1 DER (verified with ecdsa.VerifyASN1).
package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

var b64 = base64.RawURLEncoding

// Errors.
var (
	ErrInvalidChallenge   = errors.New("webauthn: invalid challenge")
	ErrInvalidOrigin      = errors.New("webauthn: origin not allowed")
	ErrInvalidRPID        = errors.New("webauthn: rp id mismatch")
	ErrUnsupportedAlg     = errors.New("webauthn: unsupported algorithm (ES256 only)")
	ErrUnsupportedFmt     = errors.New("webauthn: unsupported attestation format")
	ErrUserNotVerified    = errors.New("webauthn: user verification required")
	ErrCloneSuspected     = errors.New("webauthn: credential clone suspected")
	ErrChallengeExpired   = errors.New("webauthn: challenge expired or unknown")
	ErrInvalidCredential  = errors.New("webauthn: invalid credential")
	ErrChallengeExhausted = errors.New("webauthn: too many pending challenges")
)

// Config for a relying party.
type Config struct {
	// RPID is the effective domain, e.g. "soc.example.test". No port.
	RPID string
	// RPName is human-readable, e.g. "HalimiSOC".
	RPName string
	// Origins is the exact allowlist, e.g. ["https://soc.example.test"].
	Origins []string
}

// Validate the RP config at startup (fail closed).
func (c Config) Validate() error {
	if strings.TrimSpace(c.RPID) == "" {
		return fmt.Errorf("webauthn: rp id is required")
	}
	if strings.Contains(c.RPID, ":") || strings.Contains(c.RPID, "/") {
		return fmt.Errorf("webauthn: rp id must be a bare host, got %q", c.RPID)
	}
	if len(c.Origins) == 0 {
		return fmt.Errorf("webauthn: at least one origin is required")
	}
	return nil
}

// RPIDHash returns SHA-256(rpID).
func (c Config) RPIDHash() [32]byte { return sha256.Sum256([]byte(c.RPID)) }

// AllowOrigin reports whether origin is exactly allowlisted.
func (c Config) AllowOrigin(origin string) bool {
	for _, o := range c.Origins {
		if subtle.ConstantTimeCompare([]byte(origin), []byte(o)) == 1 && origin != "" {
			return true
		}
	}
	return false
}

// NewChallenge returns 32 random bytes base64url.
func NewChallenge() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return b64.EncodeToString(raw), nil
}

// --- Client data ------------------------------------------------------------

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// parseClientData decodes base64url clientDataJSON and checks type+challenge+origin.
func parseClientData(rawB64, wantType, wantChallenge string, cfg Config) ([]byte, error) {
	raw, err := b64.DecodeString(rawB64)
	if err != nil {
		return nil, fmt.Errorf("%w: client data encoding", ErrInvalidCredential)
	}
	if len(raw) > 64<<10 {
		return nil, fmt.Errorf("%w: client data too large", ErrInvalidCredential)
	}
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return nil, fmt.Errorf("%w: client data json", ErrInvalidCredential)
	}
	if cd.Type != wantType {
		return nil, fmt.Errorf("%w: type %q", ErrInvalidCredential, cd.Type)
	}
	if subtle.ConstantTimeCompare([]byte(cd.Challenge), []byte(wantChallenge)) != 1 {
		return nil, fmt.Errorf("%w: challenge mismatch", ErrInvalidChallenge)
	}
	if !cfg.AllowOrigin(cd.Origin) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidOrigin, cd.Origin)
	}
	return raw, nil
}

// --- Authenticator data -----------------------------------------------------

// authData is: rpIdHash[32] | flags[1] | signCount[4] | [attestedCredentialData] | [extensions].
// Flags: UP 0x01, UV 0x04, AT 0x40, ED 0x80.
type parsedAuthData struct {
	RPIDHash   [32]byte
	Flags      byte
	SignCount  uint32
	Credential *attestedCredential // non-nil when AT set
	Raw        []byte
}

type attestedCredential struct {
	AAGUID       [16]byte
	CredentialID []byte
	PublicKey    []byte // raw COSE bytes
	X, Y         []byte // P-256 coordinates
}

func parseAuthData(raw []byte) (*parsedAuthData, error) {
	if len(raw) < 37 {
		return nil, fmt.Errorf("%w: auth data too short", ErrInvalidCredential)
	}
	out := &parsedAuthData{Raw: raw}
	copy(out.RPIDHash[:], raw[:32])
	out.Flags = raw[32]
	out.SignCount = binary.BigEndian.Uint32(raw[33:37])
	if out.Flags&0x01 == 0 {
		return nil, fmt.Errorf("%w: user presence not set", ErrInvalidCredential)
	}
	if out.Flags&0x04 == 0 {
		return nil, ErrUserNotVerified
	}
	if out.Flags&0x40 != 0 {
		cred, err := parseAttestedCredential(raw[37:])
		if err != nil {
			return nil, err
		}
		out.Credential = cred
	}
	return out, nil
}

func parseAttestedCredential(raw []byte) (*attestedCredential, error) {
	if len(raw) < 18 {
		return nil, fmt.Errorf("%w: attested data too short", ErrInvalidCredential)
	}
	c := &attestedCredential{}
	copy(c.AAGUID[:], raw[:16])
	idLen := int(binary.BigEndian.Uint16(raw[16:18]))
	if idLen <= 0 || idLen > 1024 || len(raw) < 18+idLen {
		return nil, fmt.Errorf("%w: bad credential id length", ErrInvalidCredential)
	}
	c.CredentialID = append([]byte(nil), raw[18:18+idLen]...)
	rest := raw[18+idLen:]
	// credentialPublicKey is the next CBOR item; decode one value and take its
	// exact bytes so signature verification uses the identical encoding.
	keyBytes, err := cborOne(rest)
	if err != nil {
		return nil, fmt.Errorf("%w: public key cbor: %v", ErrInvalidCredential, err)
	}
	c.PublicKey = keyBytes
	x, y, err := parseCOSEES256(keyBytes)
	if err != nil {
		return nil, err
	}
	c.X, c.Y = x, y
	return c, nil
}

// parseCOSEES256 extracts P-256 x,y from a COSE_Key map. Only kty EC2(2),
// alg ES256(-7), crv P-256(1) accepted.
func parseCOSEES256(raw []byte) ([]byte, []byte, error) {
	m, err := cborMap(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: cose map", ErrInvalidCredential)
	}
	get := func(k int64) ([]byte, bool) {
		for _, kv := range m {
			if kv.K == k {
				if b, ok := kv.V.([]byte); ok {
					return b, true
				}
			}
		}
		return nil, false
	}
	getInt := func(k int64) (int64, bool) {
		for _, kv := range m {
			if kv.K == k {
				if n, ok := kv.V.(int64); ok {
					return n, true
				}
			}
		}
		return 0, false
	}
	kty, ok := getInt(1)
	if !ok || kty != 2 {
		return nil, nil, ErrUnsupportedAlg
	}
	alg, ok := getInt(3)
	if !ok || alg != -7 {
		return nil, nil, ErrUnsupportedAlg
	}
	crv, ok := getInt(-1)
	if !ok || crv != 1 {
		return nil, nil, ErrUnsupportedAlg
	}
	x, ok := get(-2)
	if !ok || len(x) != 32 {
		return nil, nil, fmt.Errorf("%w: bad x", ErrInvalidCredential)
	}
	y, ok := get(-3)
	if !ok || len(y) != 32 {
		return nil, nil, fmt.Errorf("%w: bad y", ErrInvalidCredential)
	}
	if !elliptic.P256().IsOnCurve(new(big.Int).SetBytes(x), new(big.Int).SetBytes(y)) {
		return nil, nil, fmt.Errorf("%w: point off curve", ErrInvalidCredential)
	}
	return append([]byte(nil), x...), append([]byte(nil), y...), nil
}

// PublicKey builds ecdsa.PublicKey from x,y.
func PublicKey(x, y []byte) *ecdsa.PublicKey {
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
}

// ParsePublicKey decodes a base64url COSE_Key and returns P-256 x,y.
// Exported for the API layer, which stores the COSE blob and needs the coordinates.
func ParsePublicKey(coseB64 string) (x, y []byte, err error) {
	raw, err := b64.DecodeString(coseB64)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: public key encoding", ErrInvalidCredential)
	}
	if len(raw) > 1024 {
		return nil, nil, fmt.Errorf("%w: public key size", ErrInvalidCredential)
	}
	return parseCOSEES256(raw)
}

// verifySig checks an ASN.1 DER ECDSA signature over authData||sha256(clientData).
func verifySig(pub *ecdsa.PublicKey, authData, clientData []byte, sigB64 string) error {
	sig, err := b64.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("%w: signature encoding", ErrInvalidCredential)
	}
	if len(sig) == 0 || len(sig) > 1024 {
		return fmt.Errorf("%w: signature size", ErrInvalidCredential)
	}
	h := sha256.Sum256(clientData)
	var data []byte
	data = append(data, authData...)
	data = append(data, h[:]...)
	digest := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return fmt.Errorf("%w: signature", ErrInvalidCredential)
	}
	return nil
}

// --- Attestation ------------------------------------------------------------

type attestationObject struct {
	Fmt      string
	AuthData []byte
	Stmt     map[string]any
}

// parseAttestationObject decodes base64url CBOR {fmt, authData, attStmt}.
func parseAttestationObject(rawB64 string) (*attestationObject, error) {
	raw, err := b64.DecodeString(rawB64)
	if err != nil {
		return nil, fmt.Errorf("%w: attestation encoding", ErrInvalidCredential)
	}
	if len(raw) > 128<<10 {
		return nil, fmt.Errorf("%w: attestation too large", ErrInvalidCredential)
	}
	m, err := cborMap(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: attestation cbor", ErrInvalidCredential)
	}
	var ao attestationObject
	for _, e := range m {
		switch e.KStr {
		case "fmt":
			if s, ok := e.V.(string); ok {
				ao.Fmt = s
			}
		case "authData":
			if b, ok := e.V.([]byte); ok {
				ao.AuthData = b
			}
		case "attStmt":
			if mm, ok := e.V.([]kv); ok {
				ao.Stmt = map[string]any{}
				for _, se := range mm {
					if se.KStr != "" {
						ao.Stmt[se.KStr] = se.V
					}
				}
			}
		}
	}
	// Fallback: string keys decoded as KStr only; attStmt uses int keys so the
	// generic map path above handles it. Re-parse text-keyed variant defensively.
	if ao.Fmt == "" || len(ao.AuthData) == 0 {
		return nil, fmt.Errorf("%w: attestation shape", ErrInvalidCredential)
	}
	return &ao, nil
}

// VerifyRegistration verifies a webauthn.create ceremony and returns the new
// credential (id, COSE public key, x/y, sign count).
type RegisteredCredential struct {
	CredentialID []byte
	PublicKey    []byte
	X, Y         []byte
	SignCount    uint32
}

func VerifyRegistration(cfg Config, challenge, clientDataB64, attObjB64 string) (*RegisteredCredential, error) {
	clientData, err := parseClientData(clientDataB64, "webauthn.create", challenge, cfg)
	if err != nil {
		return nil, err
	}
	ao, err := parseAttestationObject(attObjB64)
	if err != nil {
		return nil, err
	}
	authData, err := parseAuthData(ao.AuthData)
	if err != nil {
		return nil, err
	}
	if authData.RPIDHash != cfg.RPIDHash() {
		return nil, ErrInvalidRPID
	}
	if authData.Credential == nil {
		return nil, fmt.Errorf("%w: missing attested credential", ErrInvalidCredential)
	}
	switch ao.Fmt {
	case "none":
		if len(ao.Stmt) != 0 {
			return nil, fmt.Errorf("%w: none with statement", ErrInvalidCredential)
		}
	case "packed":
		if err := verifyPackedSelf(authData, clientData, ao.Stmt); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: %q (only none/packed self-attestation)", ErrUnsupportedFmt, ao.Fmt)
	}
	return &RegisteredCredential{
		CredentialID: authData.Credential.CredentialID,
		PublicKey:    authData.Credential.PublicKey,
		X:            authData.Credential.X,
		Y:            authData.Credential.Y,
		SignCount:    authData.SignCount,
	}, nil
}

func verifyPackedSelf(authData *parsedAuthData, clientData []byte, stmt map[string]any) error {
	alg, _ := stmt["alg"].(int64)
	if alg != -7 {
		return ErrUnsupportedAlg
	}
	sigB, ok := stmt["sig"].([]byte)
	if !ok || len(sigB) == 0 {
		return fmt.Errorf("%w: packed sig", ErrInvalidCredential)
	}
	if _, hasX5c := stmt["x5c"]; hasX5c {
		return fmt.Errorf("%w: packed with x5c (CA attestation not accepted; use self)", ErrUnsupportedFmt)
	}
	pub := PublicKey(authData.Credential.X, authData.Credential.Y)
	h := sha256.Sum256(clientData)
	var data []byte
	data = append(data, authData.Raw...)
	data = append(data, h[:]...)
	digest := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(pub, digest[:], sigB) {
		return fmt.Errorf("%w: packed self signature", ErrInvalidCredential)
	}
	return nil
}

// VerifyAssertion verifies a webauthn.get ceremony against a stored key.
// Returns the new sign count to persist. Clone detection: presented <= stored
// (both non-zero) is a cloned authenticator.
func VerifyAssertion(cfg Config, challenge, clientDataB64, authDataB64, sigB64 string, x, y []byte, storedCount uint32) (uint32, error) {
	clientData, err := parseClientData(clientDataB64, "webauthn.get", challenge, cfg)
	if err != nil {
		return 0, err
	}
	authRaw, err := b64.DecodeString(authDataB64)
	if err != nil {
		return 0, fmt.Errorf("%w: auth data encoding", ErrInvalidCredential)
	}
	authData, err := parseAuthData(authRaw)
	if err != nil {
		return 0, err
	}
	if authData.RPIDHash != cfg.RPIDHash() {
		return 0, ErrInvalidRPID
	}
	if err := verifySig(PublicKey(x, y), authRaw, clientData, sigB64); err != nil {
		return 0, err
	}
	if storedCount > 0 && authData.SignCount > 0 && authData.SignCount <= storedCount {
		return 0, ErrCloneSuspected
	}
	return authData.SignCount, nil
}

// --- Challenges -------------------------------------------------------------

type purpose string

const (
	PurposeRegister purpose = "register"
	PurposeLogin    purpose = "login"
)

type pending struct {
	Challenge string
	UserID    string // register: owner; login: username (resolved at complete)
	Purpose   purpose
	Expires   time.Time
}

// Challenges is a bounded in-memory single-use challenge store.
type Challenges struct {
	mu      sync.Mutex
	items   map[string]pending
	max     int
	ttl     time.Duration
	now     func() time.Time
	counter uint64
}

func NewChallenges(max int, ttl time.Duration) *Challenges {
	if max <= 0 {
		max = 10000
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &Challenges{items: map[string]pending{}, max: max, ttl: ttl, now: func() time.Time { return time.Now().UTC() }}
}

func (c *Challenges) SetClock(f func() time.Time) { c.mu.Lock(); defer c.mu.Unlock(); c.now = f }

// Issue stores a challenge for userID/purpose and returns it.
func (c *Challenges) Issue(userID string, p purpose) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked()
	if len(c.items) >= c.max {
		return "", ErrChallengeExhausted
	}
	ch, err := NewChallenge()
	if err != nil {
		return "", err
	}
	c.items[ch] = pending{Challenge: ch, UserID: userID, Purpose: p, Expires: c.now().Add(c.ttl)}
	return ch, nil
}

// Consume validates purpose+owner and deletes (single-use).
func (c *Challenges) Consume(challenge, userID string, p purpose) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	pend, ok := c.items[challenge]
	if !ok {
		return ErrChallengeExpired
	}
	delete(c.items, challenge)
	if pend.Purpose != p {
		return ErrInvalidChallenge
	}
	if subtle.ConstantTimeCompare([]byte(pend.UserID), []byte(userID)) != 1 {
		return ErrInvalidChallenge
	}
	if c.now().After(pend.Expires) {
		return ErrChallengeExpired
	}
	return nil
}

// Peek returns the pending entry without consuming (for login username check
// before user resolution use Issue with username as UserID).
func (c *Challenges) sweepLocked() {
	now := c.now()
	for k, v := range c.items {
		if now.After(v.Expires) {
			delete(c.items, k)
		}
	}
}

var _ = bytes.MinRead // keep bytes import if unused in future edits

// Passkey is one registered authenticator.
type Passkey struct {
	ID           string     `json:"id"`
	UserID       string     `json:"user_id"`
	CredentialID string     `json:"credential_id"`
	PublicKey    string     `json:"-"`
	SignCount    uint32     `json:"sign_count"`
	Transports   []string   `json:"transports,omitempty"`
	Name         string     `json:"name,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
}
