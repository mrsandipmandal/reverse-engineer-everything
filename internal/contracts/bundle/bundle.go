// Package bundle defines the deterministic ree.bundle/1 document used to move
// evidence records between machines without a network service.
//
// A bundle is one canonical RFC 8785 JSON object. Records are canonical
// ree.evidence/1 documents sorted by their SHA-256 record digest, duplicates
// are rejected, and the bundle integrity digest covers the canonical bundle
// with the integrity member omitted.
//
// Import is in-memory. It accepts canonical bytes only, validates the bundle
// and every record, and never extracts files, resolves paths, or executes
// content. Imported content remains untrusted after validation.
//
// Export and Import are safe for concurrent use; the package has no mutable
// state.
package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/canonical"
	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
)

const (
	// Schema identifies the bundle wire format.
	Schema = "ree.bundle/1"
	// AlgorithmSHA256 is the only digest algorithm accepted in this phase.
	AlgorithmSHA256 = "sha256"

	// MaxBytes bounds the canonical bytes of a bundle.
	MaxBytes = 64 << 20
	// MaxRecords bounds the number of records in a bundle.
	MaxRecords = 10_000
)

// envelopeDepth is the extra nesting added by the bundle object and its records
// array on top of a record's own envelope. A record already allows its payload
// to reach canonical.DefaultMaxDepth, so the bundle adds three levels: the
// bundle object, the records array, and the record object.
const envelopeDepth = 3

var (
	// ErrInvalid reports a structurally invalid bundle.
	ErrInvalid = errors.New("bundle: invalid bundle")
	// ErrNotCanonical reports bytes that are not canonical RFC 8785 JSON.
	ErrNotCanonical = errors.New("bundle: bundle is not canonical")
	// ErrUnsupportedSchema reports a schema other than Schema.
	ErrUnsupportedSchema = errors.New("bundle: unsupported schema")
	// ErrUnsupportedAlgorithm reports a digest algorithm other than sha256.
	ErrUnsupportedAlgorithm = errors.New("bundle: unsupported digest algorithm")
	// ErrDigestMismatch reports a bundle digest that does not match the bundle.
	ErrDigestMismatch = errors.New("bundle: digest mismatch")
	// ErrLimit reports input above a configured size, count, or depth limit.
	ErrLimit = errors.New("bundle: limit exceeded")
	// ErrDuplicateRecord reports two records with the same record digest.
	ErrDuplicateRecord = errors.New("bundle: duplicate record")
	// ErrUnsortedRecords reports records that are not in record-digest order.
	ErrUnsortedRecords = errors.New("bundle: records are not sorted")
)

type integrity struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
}

type wireBundle struct {
	Schema    string            `json:"schema"`
	Records   []json.RawMessage `json:"records"`
	Integrity integrity         `json:"integrity"`
}

// digestDocument is the canonical content covered by the bundle digest. It
// intentionally has no integrity member.
type digestDocument struct {
	Schema  string            `json:"schema"`
	Records []json.RawMessage `json:"records"`
}

// Export encodes records, sorts them by record digest, and returns the
// canonical bundle bytes.
//
// Records are sealed by evidence.Encode, so limitations and unknowns are
// normalized and payload digests are computed. Duplicate records and bundles
// over the record or byte limit are rejected.
func Export(records []evidence.Evidence) ([]byte, error) {
	if len(records) > MaxRecords {
		return nil, fmt.Errorf("%w: %d records exceeds %d", ErrLimit, len(records), MaxRecords)
	}

	type encodedRecord struct {
		data   json.RawMessage
		digest string
	}
	encoded := make([]encodedRecord, 0, len(records))
	seen := make(map[string]struct{}, len(records))
	total := 0
	for i, record := range records {
		data, err := evidence.Encode(record)
		if err != nil {
			return nil, wrapRecordError(i, err)
		}
		digest := canonical.SHA256(data)
		if _, ok := seen[digest]; ok {
			return nil, fmt.Errorf("%w at index %d", ErrDuplicateRecord, i)
		}
		seen[digest] = struct{}{}
		total += len(data)
		if total > MaxBytes {
			return nil, fmt.Errorf("%w: records exceed %d bytes", ErrLimit, MaxBytes)
		}
		encoded = append(encoded, encodedRecord{data: data, digest: digest})
	}

	sort.Slice(encoded, func(i, j int) bool {
		return encoded[i].digest < encoded[j].digest
	})
	rawRecords := make([]json.RawMessage, len(encoded))
	for i := range encoded {
		rawRecords[i] = encoded[i].data
	}
	digest, err := documentDigest(rawRecords)
	if err != nil {
		return nil, err
	}
	return encodeDocument(rawRecords, integrity{Algorithm: AlgorithmSHA256, Digest: digest})
}

// Import parses one canonical ree.bundle/1 document and returns its records in
// record-digest order.
//
// The bundle digest is verified before records are exposed. Records must be
// sorted by digest without duplicates, and each record must pass
// evidence.Decode. Input that is not canonical is rejected rather than
// repaired.
func Import(data []byte) ([]evidence.Evidence, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty document", ErrInvalid)
	}
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("%w: bundle exceeds %d bytes", ErrLimit, MaxBytes)
	}
	canonicalData, err := canonical.WithOptions(data, options())
	if err != nil {
		return nil, mapCanonicalError("bundle", err)
	}
	if !bytes.Equal(canonicalData, data) {
		return nil, fmt.Errorf("%w: bundle must be RFC 8785 canonical JSON", ErrNotCanonical)
	}

	doc, err := decodeDocument(data)
	if err != nil {
		return nil, err
	}
	if len(doc.records) > MaxRecords {
		return nil, fmt.Errorf("%w: %d records exceeds %d", ErrLimit, len(doc.records), MaxRecords)
	}
	want, err := documentDigest(doc.records)
	if err != nil {
		return nil, err
	}
	if doc.integrity.Digest != want {
		return nil, fmt.Errorf("%w: bundle content does not match integrity.digest", ErrDigestMismatch)
	}

	records := make([]evidence.Evidence, 0, len(doc.records))
	previous := ""
	for i, raw := range doc.records {
		record, err := evidence.Decode(raw)
		if err != nil {
			return nil, wrapRecordError(i, err)
		}
		digest := canonical.SHA256(raw)
		switch {
		case i > 0 && digest == previous:
			return nil, fmt.Errorf("%w at index %d", ErrDuplicateRecord, i)
		case i > 0 && digest < previous:
			return nil, fmt.Errorf("%w: record %d is out of order", ErrUnsortedRecords, i)
		}
		previous = digest
		records = append(records, record)
	}
	return records, nil
}

func options() canonical.Options {
	return canonical.Options{
		MaxBytes: MaxBytes,
		MaxDepth: canonical.DefaultMaxDepth + envelopeDepth,
	}
}

func documentDigest(records []json.RawMessage) (string, error) {
	raw, err := json.Marshal(digestDocument{Schema: Schema, Records: records})
	if err != nil {
		return "", fmt.Errorf("%w: cannot serialize bundle content", ErrInvalid)
	}
	canonicalContent, err := canonical.WithOptions(raw, options())
	if err != nil {
		return "", mapCanonicalError("bundle content", err)
	}
	return canonical.SHA256(canonicalContent), nil
}

func encodeDocument(records []json.RawMessage, sum integrity) ([]byte, error) {
	raw, err := json.Marshal(wireBundle{Schema: Schema, Records: records, Integrity: sum})
	if err != nil {
		return nil, fmt.Errorf("%w: cannot serialize bundle", ErrInvalid)
	}
	out, err := canonical.WithOptions(raw, options())
	if err != nil {
		return nil, mapCanonicalError("bundle", err)
	}
	return out, nil
}

func wrapRecordError(index int, err error) error {
	if errors.Is(err, evidence.ErrLimit) {
		return fmt.Errorf("%w: record %d: %w", ErrLimit, index, err)
	}
	return fmt.Errorf("%w: record %d: %w", ErrInvalid, index, err)
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

type document struct {
	records   []json.RawMessage
	integrity integrity
}

// decodeDocument checks exact, case-sensitive member names before reading
// values. encoding/json field matching is case-insensitive, which would
// otherwise admit a bundle that re-encodes under different member names.
func decodeDocument(data []byte) (document, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return document{}, fmt.Errorf("%w: bundle must be a JSON object", ErrInvalid)
	}
	if len(members) != 3 {
		return document{}, fmt.Errorf("%w: bundle must contain exactly schema, records, and integrity", ErrInvalid)
	}
	rawSchema, ok := members["schema"]
	if !ok {
		return document{}, missing("schema")
	}
	rawRecords, ok := members["records"]
	if !ok {
		return document{}, missing("records")
	}
	rawIntegrity, ok := members["integrity"]
	if !ok {
		return document{}, missing("integrity")
	}

	var schema string
	if err := json.Unmarshal(rawSchema, &schema); err != nil {
		return document{}, fmt.Errorf("%w: schema must be a string", ErrInvalid)
	}
	if schema != Schema {
		return document{}, fmt.Errorf("%w: want %q", ErrUnsupportedSchema, Schema)
	}

	if string(rawRecords) == "null" {
		return document{}, missing("records")
	}
	var records []json.RawMessage
	if err := json.Unmarshal(rawRecords, &records); err != nil {
		return document{}, fmt.Errorf("%w: records must be an array", ErrInvalid)
	}

	sum, err := decodeIntegrity(rawIntegrity)
	if err != nil {
		return document{}, err
	}
	if sum.Algorithm != AlgorithmSHA256 {
		return document{}, fmt.Errorf("%w: only %q is supported", ErrUnsupportedAlgorithm, AlgorithmSHA256)
	}
	if !canonical.ValidSHA256Hex(sum.Digest) {
		return document{}, fmt.Errorf("%w: integrity.digest must be 64 lowercase hexadecimal characters", ErrInvalid)
	}
	return document{records: records, integrity: sum}, nil
}

func decodeIntegrity(raw json.RawMessage) (integrity, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return integrity{}, fmt.Errorf("%w: integrity must be a JSON object", ErrInvalid)
	}
	if len(members) != 2 {
		return integrity{}, fmt.Errorf("%w: integrity must contain exactly algorithm and digest", ErrInvalid)
	}
	rawAlgorithm, ok := members["algorithm"]
	if !ok {
		return integrity{}, missing("integrity.algorithm")
	}
	rawDigest, ok := members["digest"]
	if !ok {
		return integrity{}, missing("integrity.digest")
	}
	var sum integrity
	if err := json.Unmarshal(rawAlgorithm, &sum.Algorithm); err != nil {
		return integrity{}, fmt.Errorf("%w: integrity.algorithm must be a string", ErrInvalid)
	}
	if err := json.Unmarshal(rawDigest, &sum.Digest); err != nil {
		return integrity{}, fmt.Errorf("%w: integrity.digest must be a string", ErrInvalid)
	}
	return sum, nil
}

func missing(field string) error {
	return fmt.Errorf("%w: %s is required", ErrInvalid, field)
}
