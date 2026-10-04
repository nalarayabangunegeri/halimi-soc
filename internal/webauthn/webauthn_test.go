package webauthn_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/webauthn"
)

var b64 = base64.RawURLEncoding

func testConfig() webauthn.Config {
	return webauthn.Config{
		RPID:    "127.0.0.1",
		RPName:  "HalimiSOC",
		Origins: []string{"http://127.0.0.1:3000"},
	}
}

// --- minimal CBOR encoder (test only) ---------------------------------------

func cborUint(n uint64) []byte {
	switch {
	case n < 24:
		return []byte{byte(n)}
	case n < 256:
		return []byte{0x18, byte(n)}
	case n < 65536:
		return []byte{0x19, byte(n >> 8), byte(n)}
	default:
		return []byte{0x1a, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

func cborNeg(n int64) []byte {
	v := uint64(-1 - n)
	b := cborUint(v)
	b[0] |= 0x20
	return b
}

func cborBytes(b []byte) []byte {
	h := cborUint(uint64(len(b)))
	h[0] |= 0x40
	return append(h, b...)
}

func cborText(s string) []byte {
	h := cborUint(uint64(len(s)))
	h[0] |= 0x60
	return append(h, s...)
}

func cborArray(items ...[]byte) []byte {
	h := cborUint(uint64(len(items)))
	h[0] |= 0x80
	for _, it := range items {
		h = append(h, it...)
	}
	return h
}

func cborMapPairs(pairs ...[]byte) []byte {
	if len(pairs)%2 != 0 {
		panic("odd pairs")
	}
	h := cborUint(uint64(len(pairs) / 2))
	h[0] |= 0xa0
	for _, p := range pairs {
		h = append(h, p...)
	}
	return h
}

// coseKey encodes {1:2, 3:-7, -1:1, -2:x, -3:y}.
func coseKey(x, y []byte) []byte {
	return cborMapPairs(
		cborUint(1), cborUint(2),
		cborUint(3), cborNeg(-7),
		cborNeg(-1), cborUint(1),
		cborNeg(-2), cborBytes(x),
		cborNeg(-3), cborBytes(y),
	)
}

func clientDataJSON(typ, challenge, origin string) []byte {
	raw, _ := json.Marshal(map[string]string{"type": typ, "challenge": challenge, "origin": origin})
	return raw
}

// testCredential builds a fresh P-256 key + authData + attestationObject.
type testCredential struct {
	priv         *ecdsa.PrivateKey
	credentialID []byte
	cose         []byte
	authData     []byte
}

func newTestCredential(t *testing.T, rpID string, signCount uint32) *testCredential {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	priv.X.FillBytes(xb)
	priv.Y.FillBytes(yb)
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		t.Fatal(err)
	}
	cose := coseKey(xb, yb)
	rpHash := sha256.Sum256([]byte(rpID))
	authData := append([]byte(nil), rpHash[:]...)
	authData = append(authData, 0x45) // UP|UV|AT
	var sc [4]byte
	binary.BigEndian.PutUint32(sc[:], signCount)
	authData = append(authData, sc[:]...)
	var aaguid [16]byte
	authData = append(authData, aaguid[:]...)
	var idLen [2]byte
	binary.BigEndian.PutUint16(idLen[:], uint16(len(credID)))
	authData = append(authData, idLen[:]...)
	authData = append(authData, credID...)
	authData = append(authData, cose...)
	return &testCredential{priv: priv, credentialID: credID, cose: cose, authData: authData}
}

func attestationNone(authData []byte) string {
	obj := cborMapPairs(
		cborText("fmt"), cborText("none"),
		cborText("authData"), cborBytes(authData),
		cborText("attStmt"), cborMapPairs(),
	)
	return b64.EncodeToString(obj)
}

func attestationPacked(t *testing.T, cred *testCredential, clientData []byte) string {
	t.Helper()
	h := sha256.Sum256(clientData)
	var data []byte
	data = append(data, cred.authData...)
	data = append(data, h[:]...)
	digest := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, cred.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	obj := cborMapPairs(
		cborText("fmt"), cborText("packed"),
		cborText("authData"), cborBytes(cred.authData),
		cborText("attStmt"), cborMapPairs(
			cborText("alg"), cborNeg(-7),
			cborText("sig"), cborBytes(sig),
		),
	)
	return b64.EncodeToString(obj)
}

// --- tests -------------------------------------------------------------------

func TestConfigValidation(t *testing.T) {
	if err := (webauthn.Config{}).Validate(); err == nil {
		t.Error("empty config accepted")
	}
	if err := (webauthn.Config{RPID: "x.test:8080", Origins: []string{"https://x.test"}}).Validate(); err == nil {
		t.Error("rp id with port accepted")
	}
	if err := testConfig().Validate(); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

func TestRegistrationNone(t *testing.T) {
	cfg := testConfig()
	ch, err := webauthn.NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	cred := newTestCredential(t, cfg.RPID, 0)
	cd := clientDataJSON("webauthn.create", ch, cfg.Origins[0])
	reg, err := webauthn.VerifyRegistration(cfg, ch, b64.EncodeToString(cd), attestationNone(cred.authData))
	if err != nil {
		t.Fatalf("none attestation rejected: %v", err)
	}
	if b64.EncodeToString(reg.CredentialID) != b64.EncodeToString(cred.credentialID) {
		t.Fatal("credential id mismatch")
	}
	// Stored COSE must parse back to the same key.
	x, y, err := webauthn.ParsePublicKey(b64.EncodeToString(reg.PublicKey))
	if err != nil {
		t.Fatalf("stored cose unparseable: %v", err)
	}
	if new(big.Int).SetBytes(x).Cmp(cred.priv.X) != 0 {
		t.Fatal("x mismatch")
	}
	_ = y
}

func TestRegistrationPackedSelf(t *testing.T) {
	cfg := testConfig()
	ch, err := webauthn.NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	cred := newTestCredential(t, cfg.RPID, 0)
	cd := clientDataJSON("webauthn.create", ch, cfg.Origins[0])
	reg, err := webauthn.VerifyRegistration(cfg, ch, b64.EncodeToString(cd), attestationPacked(t, cred, cd))
	if err != nil {
		t.Fatalf("packed self rejected: %v", err)
	}
	if len(reg.CredentialID) == 0 {
		t.Fatal("empty credential id")
	}
}

func TestRegistrationRejectsWrongOrigin(t *testing.T) {
	cfg := testConfig()
	ch, _ := webauthn.NewChallenge()
	cred := newTestCredential(t, cfg.RPID, 0)
	cd := clientDataJSON("webauthn.create", ch, "https://evil.test")
	if _, err := webauthn.VerifyRegistration(cfg, ch, b64.EncodeToString(cd), attestationNone(cred.authData)); err == nil {
		t.Fatal("evil origin accepted")
	}
}

func TestRegistrationRejectsWrongRPID(t *testing.T) {
	cfg := testConfig()
	ch, _ := webauthn.NewChallenge()
	cred := newTestCredential(t, "other.test", 0)
	cd := clientDataJSON("webauthn.create", ch, cfg.Origins[0])
	if _, err := webauthn.VerifyRegistration(cfg, ch, b64.EncodeToString(cd), attestationNone(cred.authData)); err == nil {
		t.Fatal("wrong rp id accepted")
	}
}

func TestRegistrationRejectsUnsupportedFmt(t *testing.T) {
	cfg := testConfig()
	ch, _ := webauthn.NewChallenge()
	cred := newTestCredential(t, cfg.RPID, 0)
	cd := clientDataJSON("webauthn.create", ch, cfg.Origins[0])
	obj := cborMapPairs(
		cborText("fmt"), cborText("tpm"),
		cborText("authData"), cborBytes(cred.authData),
		cborText("attStmt"), cborMapPairs(),
	)
	if _, err := webauthn.VerifyRegistration(cfg, ch, b64.EncodeToString(cd), b64.EncodeToString(obj)); err == nil {
		t.Fatal("tpm attestation accepted")
	}
}

func assertionParts(t *testing.T, cred *testCredential, cfg webauthn.Config, ch string, count uint32) (authDataB64, clientDataB64, sigB64 string) {
	t.Helper()
	rpHash := sha256.Sum256([]byte(cfg.RPID))
	authData := append([]byte(nil), rpHash[:]...)
	authData = append(authData, 0x05) // UP|UV
	var sc [4]byte
	binary.BigEndian.PutUint32(sc[:], count)
	authData = append(authData, sc[:]...)
	cd := clientDataJSON("webauthn.get", ch, cfg.Origins[0])
	h := sha256.Sum256(cd)
	var data []byte
	data = append(data, authData...)
	data = append(data, h[:]...)
	digest := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, cred.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return b64.EncodeToString(authData), b64.EncodeToString(cd), b64.EncodeToString(sig)
}

func TestAssertionAndCloneDetection(t *testing.T) {
	cfg := testConfig()
	cred := newTestCredential(t, cfg.RPID, 0)
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	cred.priv.X.FillBytes(xb)
	cred.priv.Y.FillBytes(yb)

	ch, _ := webauthn.NewChallenge()
	aB64, cB64, sB64 := assertionParts(t, cred, cfg, ch, 1)
	count, err := webauthn.VerifyAssertion(cfg, ch, cB64, aB64, sB64, xb, yb, 0)
	if err != nil {
		t.Fatalf("valid assertion rejected: %v", err)
	}
	if count != 1 {
		t.Fatalf("count = %d, want 1", count)
	}

	// Replay with a non-advancing counter is a suspected clone.
	ch2, _ := webauthn.NewChallenge()
	a2, c2, s2 := assertionParts(t, cred, cfg, ch2, 1)
	if _, err := webauthn.VerifyAssertion(cfg, ch2, c2, a2, s2, xb, yb, 1); err == nil {
		t.Fatal("stale counter accepted; clone not detected")
	}

	// Advancing counter passes.
	ch3, _ := webauthn.NewChallenge()
	a3, c3, s3 := assertionParts(t, cred, cfg, ch3, 2)
	if _, err := webauthn.VerifyAssertion(cfg, ch3, c3, a3, s3, xb, yb, 1); err != nil {
		t.Fatalf("advancing counter rejected: %v", err)
	}
}

func TestAssertionRejectsWrongKey(t *testing.T) {
	cfg := testConfig()
	cred := newTestCredential(t, cfg.RPID, 0)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ox := make([]byte, 32)
	oy := make([]byte, 32)
	other.X.FillBytes(ox)
	other.Y.FillBytes(oy)
	ch, _ := webauthn.NewChallenge()
	aB64, cB64, sB64 := assertionParts(t, cred, cfg, ch, 5)
	if _, err := webauthn.VerifyAssertion(cfg, ch, cB64, aB64, sB64, ox, oy, 0); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestChallengesAreSingleUseAndExpiring(t *testing.T) {
	c := webauthn.NewChallenges(10, 50*time.Millisecond)
	ch, err := c.Issue("usr_1", webauthn.PurposeRegister)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Consume(ch, "usr_1", webauthn.PurposeRegister); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if err := c.Consume(ch, "usr_1", webauthn.PurposeRegister); err == nil {
		t.Fatal("challenge reused")
	}
	ch2, _ := c.Issue("usr_1", webauthn.PurposeLogin)
	if err := c.Consume(ch2, "usr_1", webauthn.PurposeRegister); err == nil {
		t.Fatal("wrong purpose accepted")
	}
	ch3, _ := c.Issue("usr_1", webauthn.PurposeLogin)
	time.Sleep(80 * time.Millisecond)
	if err := c.Consume(ch3, "usr_1", webauthn.PurposeLogin); err == nil {
		t.Fatal("expired challenge accepted")
	}
}
