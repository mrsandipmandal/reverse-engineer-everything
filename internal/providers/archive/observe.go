// Package archive turns a bounded ZIP, tar, or gzip read into ree.evidence/1
// evidence with a ree.payload.archive/1 payload.
//
// Observe hashes the whole artifact, parses it with the read-only reader in
// internal/formats/archive, and projects the container header and every entry
// into a deterministic payload. Entries that hold another container are parsed
// in memory under depth, member count, and byte budgets, so a nested archive is
// described without being extracted. It never executes, links, maps,
// decompresses, or writes entry content outside a bounded read, and it never
// follows a link.
//
// Text in the payload comes from reader-validated UTF-8 names; other raw bytes
// appear only as bounded hexadecimal.
package archive

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	rearchive "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/archive"
)

// ErrOptions reports an invalid adapter configuration.
var ErrOptions = errors.New("archive provider: invalid options")

const (
	maxRecordLimitations = 128
	maxRecordUnknowns    = 32
)

// Options configure Observe.
type Options struct {
	// ProviderVersion is recorded in provider.version. It is required.
	ProviderVersion string
	// Limits bounds the archive read. Zero fields select the reader defaults.
	Limits rearchive.Limits
	// PayloadBytes bounds the variable part of the payload. Zero selects
	// DefaultPayloadBytes; values are clamped to MinPayloadBytes and
	// MaxPayloadBytes.
	PayloadBytes int
	// NestedDepth bounds how many container levels are inspected below the
	// artifact. Zero selects DefaultNestedDepth, a negative value disables
	// nested detection, and a value above MaxNestedDepth is clamped.
	NestedDepth int
	// NestedBytes bounds the total entry bytes decoded for nested detection.
	// Zero selects DefaultNestedBytes; values are clamped to MinNestedBytes and
	// MaxNestedBytes.
	NestedBytes int64
	// NestedMembers bounds how many entries are parsed as nested containers.
	// Zero selects DefaultNestedMembers; values above MaxNestedMembers are
	// clamped.
	NestedMembers int
	// Container selects the accepted container: "zip", "tar", or "gzip". The
	// empty string accepts whatever the reader detects. A mismatch is an error,
	// so an explicit format selection is never silently reinterpreted.
	Container string
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
	if o.NestedDepth == 0 {
		o.NestedDepth = DefaultNestedDepth
	}
	if o.NestedDepth > MaxNestedDepth {
		o.NestedDepth = MaxNestedDepth
	}
	if o.NestedBytes <= 0 {
		o.NestedBytes = DefaultNestedBytes
	}
	if o.NestedBytes < MinNestedBytes {
		o.NestedBytes = MinNestedBytes
	}
	if o.NestedBytes > MaxNestedBytes {
		o.NestedBytes = MaxNestedBytes
	}
	if o.NestedMembers <= 0 {
		o.NestedMembers = DefaultNestedMembers
	}
	if o.NestedMembers > MaxNestedMembers {
		o.NestedMembers = MaxNestedMembers
	}
	return o
}

// Observe reads one ZIP, tar, or gzip artifact and returns one ree.evidence/1
// record.
//
// The subject digest covers the whole artifact. A nested container is described
// below the entry that declares it and never becomes a second record, so the
// subject digest stays something a consumer can recompute from the file.
//
// A nested member that cannot be read or parsed keeps its status and a
// limitation; it does not fail the record or hide the other members. A reader
// failure on the artifact itself is returned as an error, because a record
// built from a partial read would understate the artifact without saying so.
func Observe(r io.ReaderAt, size int64, opts Options) (evidence.Evidence, error) {
	opts = opts.withDefaults()
	if opts.ProviderVersion == "" {
		return evidence.Evidence{}, fmt.Errorf("%w: provider version is required", ErrOptions)
	}

	artifact, err := rearchive.ParseWithLimits(r, size, opts.Limits)
	if err != nil {
		return evidence.Evidence{}, fmt.Errorf("archive provider: parse: %w", err)
	}
	if opts.Container != "" && artifact.Container.String() != opts.Container {
		return evidence.Evidence{}, fmt.Errorf("%w: artifact is %s, want %s",
			ErrOptions, artifact.Container, opts.Container)
	}
	digest, err := hashArtifact(r, size)
	if err != nil {
		return evidence.Evidence{}, fmt.Errorf("archive provider: subject digest: %w", err)
	}

	notes := &collector{}
	payload := buildPayload(artifact, opts, notes)
	raw, err := json.Marshal(payload)
	if err != nil {
		return evidence.Evidence{}, fmt.Errorf("archive provider: payload encoding: %w", err)
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
		return evidence.Evidence{}, fmt.Errorf("archive provider: record: %w", err)
	}
	return record, nil
}

// hashArtifact returns the lowercase SHA-256 of the whole artifact.
func hashArtifact(r io.ReaderAt, size int64) (string, error) {
	hasher := sha256.New()
	written, err := io.CopyBuffer(hasher, io.NewSectionReader(r, 0, size), make([]byte, 32<<10))
	if err != nil {
		return "", fmt.Errorf("%w: reading artifact: %w", rearchive.ErrRead, err)
	}
	if written != size {
		return "", fmt.Errorf("%w: hashed %d of %d bytes", rearchive.ErrRead, written, size)
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
