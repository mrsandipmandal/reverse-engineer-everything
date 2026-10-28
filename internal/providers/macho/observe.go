// Package macho turns a bounded Mach-O or universal binary read into
// ree.evidence/1 evidence with a ree.payload.macho/1 payload.
//
// Observe hashes the whole artifact, parses it with the read-only reader in
// internal/formats/macho, and projects the artifact header, every slice, its
// segments and sections, dylib commands, build metadata, entry point, symbol
// table, and code signature blob headers into a deterministic payload. It never
// executes, maps, decompresses, or writes artifact content, and it never
// validates a signature. Text in the payload comes from reader-validated UTF-8
// names; other raw bytes appear only as SHA-256 digests or bounded hexadecimal.
package macho

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	remacho "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/macho"
)

// ErrOptions reports an invalid adapter configuration.
var ErrOptions = errors.New("macho provider: invalid options")

const (
	maxRecordLimitations = 128
	maxRecordUnknowns    = 32
)

// Options configure Observe.
type Options struct {
	// ProviderVersion is recorded in provider.version. It is required.
	ProviderVersion string
	// Limits bounds the Mach-O read. Zero fields select the reader defaults.
	Limits remacho.Limits
	// PayloadBytes bounds the variable part of the payload. Zero selects
	// DefaultPayloadBytes; values are clamped to MinPayloadBytes and
	// MaxPayloadBytes.
	PayloadBytes int
	// ContentBytes bounds section bytes hashed for payload digests. Zero
	// selects DefaultContentBytes; values are clamped to MaxContentBytes.
	ContentBytes int64
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
	if o.ContentBytes <= 0 {
		o.ContentBytes = DefaultContentBytes
	}
	if o.ContentBytes > MaxContentBytes {
		o.ContentBytes = MaxContentBytes
	}
	return o
}

// Observe reads one Mach-O or universal binary artifact and returns one
// ree.evidence/1 record.
//
// The subject digest covers the whole artifact, so a universal binary is one
// record with every architecture listed rather than one record per slice. A
// slice that cannot be parsed keeps its status in the payload and becomes a
// record limitation; it does not fail the record. Reader failures wrap the
// reader's sentinel, and a payload that cannot be encoded is an error.
func Observe(r io.ReaderAt, size int64, opts Options) (evidence.Evidence, error) {
	opts = opts.withDefaults()
	if opts.ProviderVersion == "" {
		return evidence.Evidence{}, fmt.Errorf("%w: provider version is required", ErrOptions)
	}

	artifact, err := remacho.ParseWithLimits(r, size, opts.Limits)
	if err != nil {
		return evidence.Evidence{}, fmt.Errorf("macho provider: parse: %w", err)
	}
	digest, err := hashArtifact(r, size)
	if err != nil {
		return evidence.Evidence{}, fmt.Errorf("macho provider: subject digest: %w", err)
	}

	notes := &collector{}
	payload, err := buildPayload(artifact, opts, notes)
	if err != nil {
		return evidence.Evidence{}, fmt.Errorf("macho provider: payload: %w", err)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return evidence.Evidence{}, fmt.Errorf("macho provider: payload encoding: %w", err)
	}
	limitations, unknowns := notes.finish()

	coverage := evidence.CoverageComplete
	if len(limitations) > 0 || len(unknowns) > 0 {
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
		Unknowns:    unknowns,
		Payload:     raw,
	}
	if _, err := evidence.Encode(record); err != nil {
		return evidence.Evidence{}, fmt.Errorf("macho provider: record: %w", err)
	}
	return record, nil
}

// hashArtifact returns the lowercase SHA-256 of the whole artifact.
func hashArtifact(r io.ReaderAt, size int64) (string, error) {
	hasher := sha256.New()
	written, err := io.CopyBuffer(hasher, io.NewSectionReader(r, 0, size), make([]byte, 32<<10))
	if err != nil {
		return "", fmt.Errorf("%w: reading artifact: %w", remacho.ErrRead, err)
	}
	if written != size {
		return "", fmt.Errorf("%w: hashed %d of %d bytes", remacho.ErrRead, written, size)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// collector aggregates record limitations and unknowns with bounded output.
type collector struct {
	limitations []string
	unknowns    []string
	seenLimits  map[string]struct{}
	seenUnknown map[string]struct{}
	dropped     bool
	droppedQ    bool
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

func (c *collector) addUnknown(reason string) {
	if reason == "" {
		return
	}
	if c.seenUnknown == nil {
		c.seenUnknown = make(map[string]struct{})
	}
	if _, ok := c.seenUnknown[reason]; ok {
		return
	}
	if len(c.unknowns) >= maxRecordUnknowns-1 {
		c.droppedQ = true
		return
	}
	c.seenUnknown[reason] = struct{}{}
	c.unknowns = append(c.unknowns, reason)
}

func (c *collector) finish() ([]string, []string) {
	limitations := append([]string(nil), c.limitations...)
	unknowns := append([]string(nil), c.unknowns...)
	if c.dropped {
		limitations = append(limitations, "additional limitations omitted")
	}
	if c.droppedQ {
		unknowns = append(unknowns, "additional unknowns omitted")
	}
	return limitations, unknowns
}
