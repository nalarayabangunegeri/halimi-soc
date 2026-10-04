package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Password hashing parameters.
//
// Argon2id is chosen because it is memory-hard: unlike a cheap hash, an
// attacker with GPUs cannot trade memory for parallelism. The parameters below
// target roughly 64 MiB per hash, which is comfortable for a small single-node
// deployment and still expensive to attack at scale.
//
// OWASP's minimum recommendation is m=19456 KiB, t=2, p=1. These values exceed
// it deliberately, and the parameters are encoded in the produced hash so that
// they can be increased later without invalidating existing credentials.
const (
	argonMemoryKiB = 64 * 1024
	argonTime      = 3
	argonThreads   = 4
	argonKeyLen    = 32
	argonSaltLen   = 16
)

// Password length bounds.
//
// MinPasswordLength matches the API and bootstrap minimum: a shorter password
// is rejected before any hashing work happens. MaxPasswordLength bounds the
// Argon2id work an unauthenticated caller can trigger: without it a single
// 8 KiB password on the login path costs ~64 MiB + CPU, which is a cheap
// CPU/RAM DoS. 128 characters is far above any memorable passphrase.
const (
	MinPasswordLength = 12
	MaxPasswordLength = 128
)

// ErrPasswordTooLong means the password exceeds MaxPasswordLength and was
// rejected without hashing to bound unauthenticated CPU/RAM work.
var ErrPasswordTooLong = errors.New("password exceeds maximum length")

// ErrInvalidHash means a stored hash is not in the expected PHC string format.
var ErrInvalidHash = errors.New("invalid password hash format")

// ErrIncompatibleVersion means a stored hash was produced by an unsupported
// Argon2 version.
var ErrIncompatibleVersion = errors.New("incompatible argon2 version")

// HashPassword returns a PHC-formatted Argon2id hash of password.
//
// Format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password must not be empty")
	}
	if len(password) < MinPasswordLength {
		return "", errors.New("password must be at least 12 characters")
	}
	if len(password) > MaxPasswordLength {
		return "", ErrPasswordTooLong
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemoryKiB, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword reports whether password matches the stored PHC hash.
//
// The comparison is constant time. A malformed or unsupported hash is reported
// as a non-match and as an error, so the caller can distinguish "wrong password"
// from "corrupt credential store".
//
// An overlong password is rejected fast without running Argon2id: hashing it
// would let an unauthenticated caller burn ~64 MiB + CPU per attempt.
func VerifyPassword(password, encoded string) (bool, error) {
	if len(password) > MaxPasswordLength {
		return false, nil
	}
	params, salt, want, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}

	got := argon2.IDKey([]byte(password), salt,
		params.time, params.memory, params.threads, uint32(len(want)))

	if subtle.ConstantTimeCompare(got, want) == 1 {
		return true, nil
	}
	return false, nil
}

// NeedsRehash reports whether a stored hash was produced with weaker parameters
// than the current policy, so it can be upgraded on next successful login.
func NeedsRehash(encoded string) bool {
	params, _, _, err := decodeHash(encoded)
	if err != nil {
		return true
	}
	return params.memory < argonMemoryKiB ||
		params.time < argonTime ||
		params.threads < argonThreads
}

type argonParams struct {
	memory  uint32
	time    uint32
	threads uint8
}

func decodeHash(encoded string) (argonParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" {
		return argonParams{}, nil, nil, ErrInvalidHash
	}
	if parts[1] != "argon2id" {
		return argonParams{}, nil, nil, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return argonParams{}, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return argonParams{}, nil, nil, ErrIncompatibleVersion
	}

	var params argonParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d",
		&params.memory, &params.time, &params.threads); err != nil {
		return argonParams{}, nil, nil, ErrInvalidHash
	}
	// A credential store is trusted, but a bounded decode prevents a corrupt
	// row from allocating gigabytes on the authentication path.
	if params.memory > 1<<20 || params.time > 64 || params.threads > 64 {
		return argonParams{}, nil, nil, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return argonParams{}, nil, nil, ErrInvalidHash
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return argonParams{}, nil, nil, ErrInvalidHash
	}
	if len(salt) < 8 || len(key) < 16 {
		return argonParams{}, nil, nil, ErrInvalidHash
	}

	return params, salt, key, nil
}
