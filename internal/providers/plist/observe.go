// Package plist turns a bounded Apple property list read into ree.evidence/1
// evidence with a ree.payload.plist/1 payload.
//
// Observe hashes the whole artifact, parses it with the read-only reader in
// internal/formats/plist, and projects every inventoried object into a
// deterministic payload. It never executes or materializes a live object
// graph, and it never writes to the filesystem.
//
// Text in the payload comes from reader-validated strings; other raw bytes
// appear only as bounded hexadecimal.
package plist

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	replist "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/plist"
)

// ErrOptions reports an invalid adapter configuration.
var ErrOptions = errors.New("plist provider: invalid options")

const maxRecordLimitations = 128

// Options configure Observe.
type Options struct {
	// ProviderVersion is recorded in provider.version. It is required.
	ProviderVersion string
	// Limits bounds the property list read. Zero fields select the reader
	// defaults.
	Limits replist.Limits
	// PayloadBytes bounds the variable part of the payload. Zero selects
	// DefaultPayloadBytes; values are clamped to MinPayloadBytes and
	// MaxPayloadBytes.
	PayloadBytes int
}

func (o Options) withDefaults() Options {
	if o.PayloadBytes <= 0 {
		o.PayloadBytes = DefaultPayloadBytes
	}
	if o.PayloadBytes < MinPayloadBytes {
		o.PayloadBytes = MinPayloadBytes
	}
	if o.PayloadBytes > MaxPayloadBytes {
		o.PayloadBytes = MaxPayloadBytes
	}
	return o
}

// Observe reads one property list artifact and returns one ree.evidence/1
// record.
//
// The subject digest covers the whole artifact, so a consumer can recompute it
// from the file. A reader failure on the artifact is returned as an error,
// because a record built from a partial read would understate the artifact
// without saying so.
func Observe(r io.ReaderAt, size int64, opts Options) (evidence.Evidence, error) {
	opts = opts.withDefaults()
	if opts.ProviderVersion == "" {
		return evidence.Evidence{}, fmt.Errorf("%w: provider version is required", ErrOptions)
	}

	artifact, err := replist.ParseWithLimits(r, size, opts.Limits)
	if err != nil {
		return evidence.Evidence{}, fmt.Errorf("plist provider: parse: %w", err)
	}
	digest, err := hashArtifact(r, size)
	if err != nil {
		return evidence.Evidence{}, fmt.Errorf("plist provider: subject digest: %w", err)
	}

	notes := &collector{}
	payload := buildPayload(artifact, opts, notes)
	raw, err := json.Marshal(payload)
	if err != nil {
		return evidence.Evidence{}, fmt.Errorf("plist provider: payload encoding: %w", err)
	}
	limitations := notes.finish()

	coverage := evidence.CoverageComplete
	if len(limitations) > 0 {
		coverage = evidence.CoveragePartial
	}
	record := evidence.Evidence{
		Schema: evidence.Schema,
		Subject: evidence.Subject{
			SHA256: digest,
			Size:   size,
		},
		Provider: evidence.Provider{
			ID:      ProviderID,
			Version: opts.ProviderVersion,
			Profile: ProviderProfile,
		},
		Authority:   evidence.AuthorityObserved,
		Coverage:    coverage,
		Limitations: limitations,
		Payload:     raw,
	}
	if _, err := evidence.Encode(record); err != nil {
		return evidence.Evidence{}, fmt.Errorf("plist provider: record: %w", err)
	}
	return record, nil
}

// hashArtifact returns the lowercase SHA-256 of the whole artifact.
func hashArtifact(r io.ReaderAt, size int64) (string, error) {
	hasher := sha256.New()
	written, err := io.CopyBuffer(hasher, io.NewSectionReader(r, 0, size), make([]byte, 32<<10))
	if err != nil {
		return "", fmt.Errorf("%w: reading artifact: %w", replist.ErrRead, err)
	}
	if written != size {
		return "", fmt.Errorf("%w: hashed %d of %d bytes", replist.ErrRead, written, size)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// collector aggregates record limitations with bounded output.
type collector struct {
	limitations []string
	seenLimits  map[string]struct{}
	dropped     bool
}

func (c *collector) addLimitation(reason string) {
	if reason == "" {
		return
	}
	if c.seenLimits == nil {
		c.seenLimits = make(map[string]struct{})
	}
	if _, ok := c.seenLimits[reason]; ok {
		return
	}
	if len(c.limitations) >= maxRecordLimitations-1 {
		c.dropped = true
		return
	}
	c.seenLimits[reason] = struct{}{}
	c.limitations = append(c.limitations, reason)
}

func (c *collector) finish() []string {
	limitations := append([]string(nil), c.limitations...)
	if c.dropped {
		limitations = append(limitations, "additional limitations omitted")
	}
	return limitations
}
