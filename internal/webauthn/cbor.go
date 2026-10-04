// Minimal CBOR decoder for the WebAuthn subset.
//
// Supports major types 0 (uint), 1 (negint), 2 (bytes), 3 (text), 4 (array),
// 5 (map), 7 (false/true/nil). Indefinite lengths rejected. Nesting and total
// size bounded to keep hostile attestation objects from exhausting memory.
package webauthn

import (
	"errors"
	"fmt"
)

var errCBOR = errors.New("webauthn: cbor decode")

const (
	maxNested = 8
	maxBytes  = 128 << 10
)

type kv struct {
	K    int64
	KStr string
	V    any // []byte | string | int64 | []any | []kv | bool | nil
}

// cborOne decodes exactly one CBOR item and returns its exact bytes.
func cborOne(raw []byte) ([]byte, error) {
	n, _, err := cborValue(raw, 0, 0)
	if err != nil {
		return nil, err
	}
	if n <= 0 || n > len(raw) {
		return nil, errCBOR
	}
	return raw[:n], nil
}

// cborMap decodes a top-level CBOR map into []kv (int keys and text keys).
func cborMap(raw []byte) ([]kv, error) {
	n, v, err := cborValue(raw, 0, 0)
	if err != nil {
		return nil, err
	}
	_ = n
	m, ok := v.([]kv)
	if !ok {
		return nil, fmt.Errorf("%w: top-level not a map", errCBOR)
	}
	return m, nil
}

func cborValue(raw []byte, off, depth int) (int, any, error) {
	if depth > maxNested {
		return 0, nil, fmt.Errorf("%w: nesting", errCBOR)
	}
	if off >= len(raw) {
		return 0, nil, fmt.Errorf("%w: truncated", errCBOR)
	}
	ib := raw[off]
	mt := ib >> 5
	ai := ib & 0x1f
	off++

	arg, off, err := cborArg(raw, off, ai)
	if err != nil {
		return 0, nil, err
	}
	switch mt {
	case 0:
		return off, int64(arg), nil
	case 1:
		return off, -1 - int64(arg), nil
	case 2:
		if arg > maxBytes || off+int(arg) > len(raw) {
			return 0, nil, fmt.Errorf("%w: bytes bounds", errCBOR)
		}
		out := append([]byte(nil), raw[off:off+int(arg)]...)
		return off + int(arg), out, nil
	case 3:
		if arg > maxBytes || off+int(arg) > len(raw) {
			return 0, nil, fmt.Errorf("%w: text bounds", errCBOR)
		}
		return off + int(arg), string(raw[off : off+int(arg)]), nil
	case 4:
		n := int(arg)
		if n < 0 || n > 256 {
			return 0, nil, fmt.Errorf("%w: array size", errCBOR)
		}
		out := make([]any, 0, n)
		cur := off
		for i := 0; i < n; i++ {
			used, v, err := cborValue(raw, cur, depth+1)
			if err != nil {
				return 0, nil, err
			}
			out = append(out, v)
			cur = used
		}
		return cur, out, nil
	case 5:
		n := int(arg)
		if n < 0 || n > 256 {
			return 0, nil, fmt.Errorf("%w: map size", errCBOR)
		}
		out := make([]kv, 0, n)
		cur := off
		for i := 0; i < n; i++ {
			ku, kvv, err := cborValue(raw, cur, depth+1)
			if err != nil {
				return 0, nil, err
			}
			vu, vvv, err := cborValue(raw, ku, depth+1)
			if err != nil {
				return 0, nil, err
			}
			var e kv
			switch k := kvv.(type) {
			case int64:
				e.K = k
			case string:
				e.KStr = k
			default:
				return 0, nil, fmt.Errorf("%w: map key type", errCBOR)
			}
			e.V = vvv
			out = append(out, e)
			cur = vu
		}
		return cur, out, nil
	case 7:
		switch ai {
		case 20:
			return off, false, nil
		case 21:
			return off, true, nil
		case 22:
			return off, nil, nil
		}
		return 0, nil, fmt.Errorf("%w: simple value %d", errCBOR, ai)
	}
	return 0, nil, fmt.Errorf("%w: major type %d", errCBOR, mt)
}

func cborArg(raw []byte, off int, ai byte) (uint64, int, error) {
	switch {
	case ai < 24:
		return uint64(ai), off, nil
	case ai == 24:
		if off+1 > len(raw) {
			return 0, 0, fmt.Errorf("%w: truncated arg", errCBOR)
		}
		return uint64(raw[off]), off + 1, nil
	case ai == 25:
		if off+2 > len(raw) {
			return 0, 0, fmt.Errorf("%w: truncated arg", errCBOR)
		}
		return uint64(raw[off])<<8 | uint64(raw[off+1]), off + 2, nil
	case ai == 26:
		if off+4 > len(raw) {
			return 0, 0, fmt.Errorf("%w: truncated arg", errCBOR)
		}
		var v uint64
		for i := 0; i < 4; i++ {
			v = v<<8 | uint64(raw[off+i])
		}
		return v, off + 4, nil
	case ai == 27:
		if off+8 > len(raw) {
			return 0, 0, fmt.Errorf("%w: truncated arg", errCBOR)
		}
		var v uint64
		for i := 0; i < 8; i++ {
			v = v<<8 | uint64(raw[off+i])
		}
		return v, off + 8, nil
	}
	return 0, 0, fmt.Errorf("%w: indefinite lengths rejected", errCBOR)
}
