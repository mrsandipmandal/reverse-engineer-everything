package asar

import (
	"encoding/hex"
	"encoding/json"
	"strconv"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	reasar "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/asar"
)

const (
	// PayloadSchema identifies the ASAR evidence payload.
	PayloadSchema = "ree.payload.asar/1"
	// ProviderID is the stable identifier of the built-in ASAR provider.
	ProviderID = "builtin.asar"
	// ProviderProfile names the provider's analysis profile.
	ProviderProfile = "default"

	// DefaultPayloadBytes bounds the variable part of a payload. It leaves
	// headroom below evidence.MaxPayloadBytes for the record envelope.
	DefaultPayloadBytes = 3_500_000
	// MinPayloadBytes is the smallest configurable payload budget. The fixed
	// artifact envelope is always emitted even when this leaves no room for
	// entries.
	MinPayloadBytes = 4 << 10
	// MaxPayloadBytes is the largest configurable payload budget.
	MaxPayloadBytes = evidence.MaxPayloadBytes - (64 << 10)
)

// Payload is the ree.payload.asar/1 observation of one ASAR artifact.
//
// Unsigned 64-bit sizes and offsets are decimal strings so values above 2^53
// survive canonical JSON unchanged. Raw paths are lowercase hexadecimal, and
// decoded paths are text the reader validated without repair.
//
// Entries are emitted once, at the top level; artifact.entries is not a second
// copy.
type Payload struct {
	Schema   string          `json:"schema"`
	Artifact PayloadArtifact `json:"artifact"`
	Entries  []PayloadEntry  `json:"entries"`
}

// PayloadArtifact is the inventoried header of the artifact.
type PayloadArtifact struct {
	// HeaderBytes is the declared header pickle payload size.
	HeaderBytes string `json:"header_bytes"`
	// JSONBytes is the declared JSON string payload size, including padding.
	JSONBytes string `json:"json_bytes"`
	// DataOffset is the absolute offset where file data begins.
	DataOffset string `json:"data_offset"`
	// EntryCount is the number of entries the reader loaded, and
	// LoadedEntryCount is the number projected into this payload. The second can
	// be smaller when the payload budget was exhausted.
	EntryCount       int  `json:"entry_count"`
	LoadedEntryCount int  `json:"loaded_entry_count"`
	Truncated        bool `json:"truncated"`
	// Status is "parsed" when the header and directory were decoded.
	Status string `json:"status"`
	// Limitations states, in deterministic order, why this artifact's view is
	// incomplete.
	Limitations []string `json:"limitations"`
}

// PayloadEntry is one directory, file, or link declared by the archive.
type PayloadEntry struct {
	Index int `json:"index"`
	// Path is the decoded path, empty when PathAvailable is false. PathHex is
	// the raw path bytes, capped by the reader's path limit.
	Path          string `json:"path"`
	PathAvailable bool   `json:"path_available"`
	PathHex       string `json:"path_hex"`
	Unsafe        string `json:"unsafe"`
	Type          string `json:"type"`
	// Size and Offset are the declared file fields, null when absent.
	Size   *string `json:"size"`
	Offset *string `json:"offset"`
	// DataOffset is the absolute artifact offset of the file data, null when
	// the declared range is missing or outside the artifact.
	DataOffset *string `json:"data_offset"`
	Executable bool    `json:"executable"`
	Unpacked   bool    `json:"unpacked"`
	// RangeOutside reports that the declared range lies outside the artifact.
	RangeOutside bool `json:"range_outside"`
	// Integrity is the declared content integrity metadata, null when absent.
	Integrity *PayloadIntegrity `json:"integrity"`
	// LinkTarget is the declared link target, never followed.
	LinkTarget          string `json:"link_target"`
	LinkTargetAvailable bool   `json:"link_target_available"`
	// Limitations states, in deterministic order, why this entry's view is
	// incomplete or why its content cannot be read.
	Limitations []string `json:"limitations"`
}

// PayloadIntegrity mirrors the declared integrity metadata of one file.
type PayloadIntegrity struct {
	Algorithm          string `json:"algorithm"`
	AlgorithmAvailable bool   `json:"algorithm_available"`
	Hash               string `json:"hash"`
	HashAvailable      bool   `json:"hash_available"`
	BlockCount         int    `json:"block_count"`
}

// projectArtifact converts the reader header and counts into a payload view.
func projectArtifact(source *reasar.Archive, status string) PayloadArtifact {
	return PayloadArtifact{
		HeaderBytes: int64String(source.HeaderBytes),
		JSONBytes:   int64String(source.JSONBytes),
		DataOffset:  int64String(source.DataOffset),
		EntryCount:  len(source.Entries),
		Truncated:   source.Truncated,
		Status:      status,
		Limitations: append([]string(nil), source.Limitations...),
	}
}

// projectEntry converts one reader entry into a payload value.
func projectEntry(entry reasar.Entry) PayloadEntry {
	out := PayloadEntry{
		Index:               entry.Index,
		Path:                entry.Path,
		PathAvailable:       entry.PathAvailable,
		PathHex:             hex.EncodeToString(entry.PathBytes),
		Unsafe:              entry.PathUnsafe,
		Type:                entry.Type.String(),
		Executable:          entry.Executable,
		Unpacked:            entry.Unpacked,
		RangeOutside:        entry.RangeOutside,
		LinkTarget:          entry.LinkTarget,
		LinkTargetAvailable: entry.LinkTargetAvailable,
		Limitations:         append([]string(nil), entry.Limitations...),
	}
	if entry.SizeKnown {
		value := uint64String(entry.Size)
		out.Size = &value
	}
	if entry.OffsetKnown {
		value := uint64String(entry.Offset)
		out.Offset = &value
	}
	if entry.DataKnown {
		value := int64String(entry.DataOffset)
		out.DataOffset = &value
	}
	if entry.Integrity != nil {
		out.Integrity = &PayloadIntegrity{
			Algorithm:          entry.Integrity.Algorithm,
			AlgorithmAvailable: entry.Integrity.AlgorithmAvailable,
			Hash:               entry.Integrity.Hash,
			HashAvailable:      entry.Integrity.HashAvailable,
			BlockCount:         entry.Integrity.BlockCount,
		}
	}
	return out
}

// uint64String renders an unsigned 64-bit value as a decimal string so it
// survives canonical JSON unchanged.
func uint64String(value uint64) string {
	return strconv.FormatUint(value, 10)
}

// int64String renders a signed 64-bit value as a decimal string so it survives
// canonical JSON unchanged.
func int64String(value int64) string {
	return strconv.FormatInt(value, 10)
}

// jsonSize returns the canonical length of a projected value, or zero when it
// cannot be measured.
func jsonSize(value any) int {
	raw, err := json.Marshal(value)
	if err != nil {
		return 0
	}
	return len(raw)
}

// payloadBudget hands the entry table a fair share of the remaining payload
// bytes.
type payloadBudget struct {
	remaining int
	shares    int
	allowance int
	used      int
}

func newPayloadBudget(total int) *payloadBudget {
	if total < 0 {
		total = 0
	}
	return &payloadBudget{remaining: total, shares: 100}
}

// start opens a table allowance from the remaining bytes.
func (b *payloadBudget) start(share int) {
	b.allowance = b.remaining * share / b.shares
	b.used = 0
	b.shares -= share
}

// reserve charges a fixed cost before any share is computed.
func (b *payloadBudget) reserve(size int) {
	b.remaining -= size
	if b.remaining < 0 {
		b.remaining = 0
	}
}

// fits reports whether size still fits the open allowance.
func (b *payloadBudget) fits(size int) bool {
	return b.used+size <= b.allowance
}

// add charges size against the open allowance.
func (b *payloadBudget) add(size int) {
	b.used += size
}

// finish closes the allowance and returns the unspent bytes to the budget.
func (b *payloadBudget) finish() {
	b.remaining -= b.used
	if b.remaining < 0 {
		b.remaining = 0
	}
	b.allowance = 0
	b.used = 0
}
