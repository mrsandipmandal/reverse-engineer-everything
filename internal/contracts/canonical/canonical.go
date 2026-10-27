// Package canonical produces deterministic JSON bytes following RFC 8785
// (JSON Canonicalization Scheme) and computes SHA-256 digests over them.
//
// Canonical bytes are the hashing boundary for evidence payloads and bundles:
// identical observations must produce identical bytes regardless of input key
// order or insignificant whitespace.
//
// Input is untrusted. Callers get explicit size and nesting limits, and
// malformed or non-I-JSON input is rejected rather than repaired.
//
// Bytes and WithOptions are safe for concurrent use; the package has no
// mutable state.
package canonical

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

const (
	// DefaultMaxBytes bounds the input accepted by Bytes and WithOptions.
	DefaultMaxBytes = 4 << 20
	// DefaultMaxDepth bounds JSON object and array nesting.
	DefaultMaxDepth = 128
)

var (
	// ErrEmpty reports empty input.
	ErrEmpty = errors.New("canonical: empty input")
	// ErrTooLarge reports input above the configured byte limit.
	ErrTooLarge = errors.New("canonical: input too large")
	// ErrTooDeep reports nesting above the configured depth limit.
	ErrTooDeep = errors.New("canonical: nesting too deep")
	// ErrInvalid reports input that is not valid I-JSON.
	ErrInvalid = errors.New("canonical: invalid JSON")
)

// Options bounds canonicalization work. A zero or negative field selects the
// corresponding default.
type Options struct {
	MaxBytes int
	MaxDepth int
}

// DefaultOptions returns the default limits.
func DefaultOptions() Options {
	return Options{MaxBytes: DefaultMaxBytes, MaxDepth: DefaultMaxDepth}
}

// Bytes canonicalizes input using the default limits.
func Bytes(input []byte) ([]byte, error) {
	return WithOptions(input, DefaultOptions())
}

// WithOptions canonicalizes input under the given limits.
//
// The result follows RFC 8785: object member names are sorted by UTF-16 code
// units, numbers use ECMAScript serialization, strings are minimally escaped,
// and no insignificant whitespace is emitted. Canonicalizing canonical output
// again returns the same bytes.
func WithOptions(input []byte, opts Options) ([]byte, error) {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = DefaultMaxDepth
	}
	if len(input) == 0 {
		return nil, ErrEmpty
	}
	if len(input) > opts.MaxBytes {
		return nil, fmt.Errorf("%w: %d bytes exceeds %d", ErrTooLarge, len(input), opts.MaxBytes)
	}
	if err := checkDepth(input, opts.MaxDepth); err != nil {
		return nil, err
	}

	out, err := jcs.Transform(input)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if !utf8.Valid(out) {
		return nil, fmt.Errorf("%w: canonical output is not valid UTF-8", ErrInvalid)
	}
	return out, nil
}

// SHA256 returns the lowercase hexadecimal SHA-256 digest of data, which is
// normally canonical bytes.
func SHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ValidSHA256Hex reports whether s is exactly 64 lowercase hexadecimal
// characters, the only digest form accepted by the evidence and bundle
// schemas.
func ValidSHA256Hex(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// checkDepth rejects excessive nesting before the canonicalizer builds a
// parse tree. Braces and brackets inside strings are ignored. Malformed
// structure is left for the canonicalizer to reject.
func checkDepth(input []byte, limit int) error {
	depth := 0
	inString := false
	escaped := false
	for _, c := range input {
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > limit {
				return fmt.Errorf("%w: depth exceeds %d", ErrTooDeep, limit)
			}
		case '}', ']':
			if depth > 0 {
				depth--
			}
		}
	}
	return nil
}
