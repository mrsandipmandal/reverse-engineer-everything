// Package evidence defines schema ree.evidence/1, the unit of recorded
// reverse-engineering evidence.
//
// A record binds a provider's observation to an artifact by digest, states how
// the result was obtained and how complete it is, and carries an arbitrary
// JSON payload whose canonical bytes are covered by an integrity digest.
//
// Records are hashed and exchanged as canonical RFC 8785 JSON. Encode
// normalizes producer-supplied ordering and seals the payload digest. Decode
// accepts canonical bytes only, rejects unknown members and schema violations,
// and enforces byte, count, string, and nesting limits. Decode treats input as
// untrusted and never executes or resolves anything from it.
//
// Encode, Decode, and the value methods are safe for concurrent use.
package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/canonical"
)

const (
	// Schema identifies the evidence wire format.
	Schema = "ree.evidence/1"
	// AlgorithmSHA256 is the only digest algorithm accepted in this phase.
	AlgorithmSHA256 = "sha256"

	// MaxRecordBytes bounds the canonical bytes of one evidence record.
	MaxRecordBytes = 8 << 20
	// MaxPayloadBytes bounds the canonical bytes of a record payload.
	MaxPayloadBytes = 4 << 20
	// MaxStringBytes bounds every string and member name in a record.
	MaxStringBytes = 1 << 20
	// MaxObjectMembers bounds the members of any single payload object.
	MaxObjectMembers = 10_000
	// MaxArrayElements bounds the elements of any single array, including the
	// top-level limitations and unknowns lists.
	MaxArrayElements = 100_000
)

// envelopeDepth is the extra nesting added by the record object itself. Payload
// nesting is limited separately to canonical.DefaultMaxDepth.
const envelopeDepth = 1

var (
	// ErrInvalid reports a structurally invalid record.
	ErrInvalid = errors.New("evidence: invalid record")
	// ErrNotCanonical reports bytes that are not canonical RFC 8785 JSON.
	ErrNotCanonical = errors.New("evidence: record is not canonical")
	// ErrUnsupportedSchema reports a schema other than Schema.
	ErrUnsupportedSchema = errors.New("evidence: unsupported schema")
	// ErrUnsupportedAlgorithm reports a digest algorithm other than sha256.
	ErrUnsupportedAlgorithm = errors.New("evidence: unsupported digest algorithm")
	// ErrDigestMismatch reports a payload digest that does not match the
	// payload, or a record digest that does not match the record.
	ErrDigestMismatch = errors.New("evidence: digest mismatch")
	// ErrLimit reports input above a configured size, count, or depth limit.
	ErrLimit = errors.New("evidence: limit exceeded")
)

// Authority describes how directly a provider obtained the evidence.
type Authority string

// Supported authorities.
const (
	AuthorityObserved Authority = "observed"
	AuthorityDerived  Authority = "derived"
	AuthorityInferred Authority = "inferred"
)

// Coverage describes how much of the subject the evidence explains.
type Coverage string

// Supported coverage levels.
const (
	CoverageComplete Coverage = "complete"
	CoveragePartial  Coverage = "partial"
	CoverageUnknown  Coverage = "unknown"
)

// Subject identifies the artifact the evidence describes.
type Subject struct {
	// SHA256 is the lowercase hexadecimal SHA-256 digest of the artifact.
	SHA256 string `json:"sha256"`
	// Size is the artifact size in bytes; it must not be negative.
	Size int64 `json:"size"`
}

// Provider identifies the producer of the evidence.
type Provider struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Profile string `json:"profile"`
}

// Integrity seals the canonical payload bytes.
type Integrity struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
}

// Evidence is one validated ree.evidence/1 record.
type Evidence struct {
	Schema      string          `json:"schema"`
	Subject     Subject         `json:"subject"`
	Provider    Provider        `json:"provider"`
	Authority   Authority       `json:"authority"`
	Coverage    Coverage        `json:"coverage"`
	Limitations []string        `json:"limitations"`
	Unknowns    []string        `json:"unknowns"`
	Payload     json.RawMessage `json:"payload"`
	Integrity   Integrity       `json:"integrity"`
}

// Encode normalizes and seals a record, then returns its canonical bytes.
//
// Limitations and unknowns are sorted lexicographically by byte value.
// Duplicate entries are rejected rather than collapsed. Payload member order
// and insignificant whitespace are removed by canonicalization. An empty
// schema is filled with Schema; a supplied schema or digest must already
// match, otherwise Encode fails instead of silently rewriting the record.
func Encode(rec Evidence) ([]byte, error) {
	normalized, err := normalize(rec)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(toWire(normalized))
	if err != nil {
		return nil, fmt.Errorf("%w: cannot serialize record", ErrInvalid)
	}
	out, err := canonical.WithOptions(raw, canonical.Options{
		MaxBytes: MaxRecordBytes,
		MaxDepth: canonical.DefaultMaxDepth + envelopeDepth,
	})
	if err != nil {
		return nil, mapCanonicalError("record", err)
	}
	return out, nil
}

// Decode parses one canonical ree.evidence/1 record.
//
// Only canonical bytes are accepted, so the bytes that Decode hashes are
// exactly the bytes that were supplied. Unknown members, member names with the
// wrong case, missing or null limitations and unknowns, unsorted lists, and
// mismatched digests are rejected.
func Decode(data []byte) (Evidence, error) {
	if len(data) == 0 {
		return Evidence{}, fmt.Errorf("%w: empty document", ErrInvalid)
	}
	if len(data) > MaxRecordBytes {
		return Evidence{}, fmt.Errorf("%w: record exceeds %d bytes", ErrLimit, MaxRecordBytes)
	}
	canonicalRecord, err := canonical.WithOptions(data, canonical.Options{
		MaxBytes: MaxRecordBytes,
		MaxDepth: canonical.DefaultMaxDepth + envelopeDepth,
	})
	if err != nil {
		return Evidence{}, mapCanonicalError("record", err)
	}
	if !bytes.Equal(canonicalRecord, data) {
		return Evidence{}, fmt.Errorf("%w: record must be RFC 8785 canonical JSON", ErrNotCanonical)
	}
	if err := checkShape(canonicalRecord, recordSpec); err != nil {
		return Evidence{}, err
	}
	rec, err := decodeWire(data)
	if err != nil {
		return Evidence{}, err
	}
	if err := rec.Validate(); err != nil {
		return Evidence{}, err
	}
	return rec, nil
}

// Validate reports whether rec is a complete, sealed, canonically ordered
// record. It does not enforce the encoded byte limit; Encode and Decode do.
func (e Evidence) Validate() error {
	payload, err := canonicalPayload(e.Payload)
	if err != nil {
		return err
	}
	return e.validate(payload)
}

// Digest returns the lowercase hexadecimal SHA-256 digest of the record's
// canonical bytes. Bundles use it to order and deduplicate records.
func (e Evidence) Digest() (string, error) {
	data, err := Encode(e)
	if err != nil {
		return "", err
	}
	return canonical.SHA256(data), nil
}

func normalize(rec Evidence) (Evidence, error) {
	if rec.Schema == "" {
		rec.Schema = Schema
	}
	rec.Limitations = sortedCopy(rec.Limitations)
	rec.Unknowns = sortedCopy(rec.Unknowns)

	payload, err := canonicalPayload(rec.Payload)
	if err != nil {
		return Evidence{}, err
	}
	digest := canonical.SHA256(payload)

	if rec.Integrity.Algorithm != "" && rec.Integrity.Algorithm != AlgorithmSHA256 {
		return Evidence{}, fmt.Errorf("%w: only %q is supported", ErrUnsupportedAlgorithm, AlgorithmSHA256)
	}
	if rec.Integrity.Digest != "" && rec.Integrity.Digest != digest {
		return Evidence{}, fmt.Errorf("%w: payload does not match the supplied digest", ErrDigestMismatch)
	}

	rec.Payload = append(json.RawMessage(nil), payload...)
	rec.Integrity = Integrity{Algorithm: AlgorithmSHA256, Digest: digest}
	if err := rec.validate(payload); err != nil {
		return Evidence{}, err
	}
	return rec, nil
}

func (e Evidence) validate(payload []byte) error {
	if e.Schema != Schema {
		return fmt.Errorf("%w: want %q", ErrUnsupportedSchema, Schema)
	}
	if !canonical.ValidSHA256Hex(e.Subject.SHA256) {
		return fmt.Errorf("%w: subject.sha256 must be 64 lowercase hexadecimal characters", ErrInvalid)
	}
	if e.Subject.Size < 0 {
		return fmt.Errorf("%w: subject.size must not be negative", ErrInvalid)
	}
	if err := validateText("provider.id", e.Provider.ID); err != nil {
		return err
	}
	if err := validateText("provider.version", e.Provider.Version); err != nil {
		return err
	}
	if err := validateText("provider.profile", e.Provider.Profile); err != nil {
		return err
	}
	if !e.Authority.valid() {
		return fmt.Errorf("%w: authority must be observed, derived, or inferred", ErrInvalid)
	}
	if !e.Coverage.valid() {
		return fmt.Errorf("%w: coverage must be complete, partial, or unknown", ErrInvalid)
	}
	if err := validateList("limitations", e.Limitations); err != nil {
		return err
	}
	if err := validateList("unknowns", e.Unknowns); err != nil {
		return err
	}
	if e.Integrity.Algorithm != AlgorithmSHA256 {
		return fmt.Errorf("%w: only %q is supported", ErrUnsupportedAlgorithm, AlgorithmSHA256)
	}
	if !canonical.ValidSHA256Hex(e.Integrity.Digest) {
		return fmt.Errorf("%w: integrity.digest must be 64 lowercase hexadecimal characters", ErrInvalid)
	}
	if got := canonical.SHA256(payload); got != e.Integrity.Digest {
		return fmt.Errorf("%w: payload does not match integrity.digest", ErrDigestMismatch)
	}
	return nil
}

func (a Authority) valid() bool {
	switch a {
	case AuthorityObserved, AuthorityDerived, AuthorityInferred:
		return true
	default:
		return false
	}
}

func (c Coverage) valid() bool {
	switch c {
	case CoverageComplete, CoveragePartial, CoverageUnknown:
		return true
	default:
		return false
	}
}

func validateText(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: %s must not be empty", ErrInvalid, field)
	}
	if len(value) > MaxStringBytes {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrLimit, field, MaxStringBytes)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: %s is not valid UTF-8", ErrInvalid, field)
	}
	return nil
}

func validateList(field string, values []string) error {
	if len(values) > MaxArrayElements {
		return fmt.Errorf("%w: %s has more than %d entries", ErrLimit, field, MaxArrayElements)
	}
	for i, value := range values {
		if err := validateText(field, value); err != nil {
			return err
		}
		if i == 0 {
			continue
		}
		switch {
		case values[i-1] == value:
			return fmt.Errorf("%w: %s contains a duplicate entry", ErrInvalid, field)
		case values[i-1] > value:
			return fmt.Errorf("%w: %s must be sorted lexicographically", ErrInvalid, field)
		}
	}
	return nil
}

func sortedCopy(values []string) []string {
	out := make([]string, len(values))
	copy(out, values)
	sort.Strings(out)
	return out
}

func canonicalPayload(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: payload is required", ErrInvalid)
	}
	out, err := canonical.WithOptions(raw, canonical.Options{
		MaxBytes: MaxPayloadBytes,
		MaxDepth: canonical.DefaultMaxDepth,
	})
	if err != nil {
		return nil, mapCanonicalError("payload", err)
	}
	if err := checkPayloadStructure(out); err != nil {
		return nil, err
	}
	return out, nil
}

func mapCanonicalError(field string, err error) error {
	switch {
	case errors.Is(err, canonical.ErrTooLarge), errors.Is(err, canonical.ErrTooDeep):
		return fmt.Errorf("%w: %s", ErrLimit, field)
	case errors.Is(err, canonical.ErrEmpty):
		return fmt.Errorf("%w: %s is required", ErrInvalid, field)
	default:
		return fmt.Errorf("%w: %s is not valid JSON", ErrInvalid, field)
	}
}

// checkPayloadStructure enforces per-container member and element limits plus
// string sizes. Duplicate member names and invalid UTF-8 never reach this
// point because canonicalization rejects them.
func checkPayloadStructure(payload []byte) error {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return fmt.Errorf("%w: payload is not valid JSON", ErrInvalid)
	}
	return checkValue(value)
}

func checkValue(value any) error {
	switch v := value.(type) {
	case map[string]any:
		if len(v) > MaxObjectMembers {
			return fmt.Errorf("%w: payload object has more than %d members", ErrLimit, MaxObjectMembers)
		}
		for key, child := range v {
			if len(key) > MaxStringBytes {
				return fmt.Errorf("%w: payload member name exceeds %d bytes", ErrLimit, MaxStringBytes)
			}
			if err := checkValue(child); err != nil {
				return err
			}
		}
	case []any:
		if len(v) > MaxArrayElements {
			return fmt.Errorf("%w: payload array has more than %d elements", ErrLimit, MaxArrayElements)
		}
		for _, child := range v {
			if err := checkValue(child); err != nil {
				return err
			}
		}
	case string:
		if len(v) > MaxStringBytes {
			return fmt.Errorf("%w: payload string exceeds %d bytes", ErrLimit, MaxStringBytes)
		}
	}
	return nil
}

// memberSpec describes the exact member names allowed at one object level.
// A nil object accepts any JSON value; a non-nil object requires an object
// whose members all appear in object.
type memberSpec struct {
	object map[string]memberSpec
}

var (
	recordSpec = memberSpec{object: map[string]memberSpec{
		"schema":      {},
		"subject":     subjectSpec,
		"provider":    providerSpec,
		"authority":   {},
		"coverage":    {},
		"limitations": {},
		"unknowns":    {},
		"payload":     {},
		"integrity":   integritySpec,
	}}
	subjectSpec = memberSpec{object: map[string]memberSpec{
		"sha256": {},
		"size":   {},
	}}
	providerSpec = memberSpec{object: map[string]memberSpec{
		"id":      {},
		"version": {},
		"profile": {},
	}}
	integritySpec = memberSpec{object: map[string]memberSpec{
		"algorithm": {},
		"digest":    {},
	}}
)

// checkShape enforces case-sensitive member names. encoding/json matches
// struct fields case-insensitively, so without this check "AuthoritY" would be
// accepted and then re-encoded as "authority", giving one record two byte
// representations.
func checkShape(data []byte, spec memberSpec) error {
	if spec.object == nil {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%w: malformed document", ErrInvalid)
	}
	if tok != json.Delim('{') {
		return fmt.Errorf("%w: malformed document", ErrInvalid)
	}
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return fmt.Errorf("%w: malformed document", ErrInvalid)
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("%w: malformed document", ErrInvalid)
		}
		child, ok := spec.object[key]
		if !ok {
			return fmt.Errorf("%w: unknown member", ErrInvalid)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return fmt.Errorf("%w: malformed document", ErrInvalid)
		}
		if err := checkShape(raw, child); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("%w: malformed document", ErrInvalid)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	return nil
}

type wireEvidence struct {
	Schema      string          `json:"schema"`
	Subject     wireSubject     `json:"subject"`
	Provider    wireProvider    `json:"provider"`
	Authority   Authority       `json:"authority"`
	Coverage    Coverage        `json:"coverage"`
	Limitations []string        `json:"limitations"`
	Unknowns    []string        `json:"unknowns"`
	Payload     json.RawMessage `json:"payload"`
	Integrity   wireIntegrity   `json:"integrity"`
}

type wireSubject struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type wireProvider struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Profile string `json:"profile"`
}

type wireIntegrity struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
}

func toWire(e Evidence) wireEvidence {
	return wireEvidence{
		Schema:      e.Schema,
		Subject:     wireSubject{SHA256: e.Subject.SHA256, Size: e.Subject.Size},
		Provider:    wireProvider{ID: e.Provider.ID, Version: e.Provider.Version, Profile: e.Provider.Profile},
		Authority:   e.Authority,
		Coverage:    e.Coverage,
		Limitations: e.Limitations,
		Unknowns:    e.Unknowns,
		Payload:     e.Payload,
		Integrity:   wireIntegrity{Algorithm: e.Integrity.Algorithm, Digest: e.Integrity.Digest},
	}
}

// decodeWire uses pointers to distinguish absent or null members from present
// values before semantic validation.
type wireDecode struct {
	Schema      *string         `json:"schema"`
	Subject     *wireDecodeSub  `json:"subject"`
	Provider    *wireDecodeProv `json:"provider"`
	Authority   *Authority      `json:"authority"`
	Coverage    *Coverage       `json:"coverage"`
	Limitations *[]string       `json:"limitations"`
	Unknowns    *[]string       `json:"unknowns"`
	Payload     json.RawMessage `json:"payload"`
	Integrity   *wireDecodeInt  `json:"integrity"`
}

type wireDecodeSub struct {
	SHA256 *string `json:"sha256"`
	Size   *int64  `json:"size"`
}

type wireDecodeProv struct {
	ID      *string `json:"id"`
	Version *string `json:"version"`
	Profile *string `json:"profile"`
}

type wireDecodeInt struct {
	Algorithm *string `json:"algorithm"`
	Digest    *string `json:"digest"`
}

func decodeWire(data []byte) (Evidence, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var w wireDecode
	if err := dec.Decode(&w); err != nil {
		if strings.HasPrefix(err.Error(), "json: unknown field") {
			return Evidence{}, fmt.Errorf("%w: unknown member", ErrInvalid)
		}
		return Evidence{}, fmt.Errorf("%w: malformed document", ErrInvalid)
	}
	if err := dec.Decode(new(struct{})); !errors.Is(err, io.EOF) {
		return Evidence{}, fmt.Errorf("%w: trailing data", ErrInvalid)
	}

	if w.Schema == nil {
		return Evidence{}, missing("schema")
	}
	if w.Subject == nil {
		return Evidence{}, missing("subject")
	}
	if w.Subject.SHA256 == nil {
		return Evidence{}, missing("subject.sha256")
	}
	if w.Subject.Size == nil {
		return Evidence{}, missing("subject.size")
	}
	if w.Provider == nil {
		return Evidence{}, missing("provider")
	}
	if w.Provider.ID == nil {
		return Evidence{}, missing("provider.id")
	}
	if w.Provider.Version == nil {
		return Evidence{}, missing("provider.version")
	}
	if w.Provider.Profile == nil {
		return Evidence{}, missing("provider.profile")
	}
	if w.Authority == nil {
		return Evidence{}, missing("authority")
	}
	if w.Coverage == nil {
		return Evidence{}, missing("coverage")
	}
	if w.Limitations == nil {
		return Evidence{}, missing("limitations")
	}
	if w.Unknowns == nil {
		return Evidence{}, missing("unknowns")
	}
	if w.Payload == nil {
		return Evidence{}, missing("payload")
	}
	if w.Integrity == nil {
		return Evidence{}, missing("integrity")
	}
	if w.Integrity.Algorithm == nil {
		return Evidence{}, missing("integrity.algorithm")
	}
	if w.Integrity.Digest == nil {
		return Evidence{}, missing("integrity.digest")
	}

	return Evidence{
		Schema:      *w.Schema,
		Subject:     Subject{SHA256: *w.Subject.SHA256, Size: *w.Subject.Size},
		Provider:    Provider{ID: *w.Provider.ID, Version: *w.Provider.Version, Profile: *w.Provider.Profile},
		Authority:   *w.Authority,
		Coverage:    *w.Coverage,
		Limitations: append([]string{}, (*w.Limitations)...),
		Unknowns:    append([]string{}, (*w.Unknowns)...),
		Payload:     append(json.RawMessage(nil), w.Payload...),
		Integrity:   Integrity{Algorithm: *w.Integrity.Algorithm, Digest: *w.Integrity.Digest},
	}, nil
}

func missing(field string) error {
	return fmt.Errorf("%w: %s is required", ErrInvalid, field)
}
