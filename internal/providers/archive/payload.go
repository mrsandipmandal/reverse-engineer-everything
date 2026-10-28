package archive

import (
	"encoding/hex"
	"encoding/json"
	"strconv"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	rearchive "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/archive"
)

const (
	// PayloadSchema identifies the archive evidence payload.
	PayloadSchema = "ree.payload.archive/1"
	// ProviderID is the stable identifier of the built-in archive provider.
	ProviderID = "builtin.archive"
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

// Payload is the ree.payload.archive/1 observation of one ZIP, tar, or gzip
// artifact.
//
// Unsigned 64-bit sizes and offsets are decimal strings so values above 2^53
// survive canonical JSON unchanged. Raw name fields are lowercase hexadecimal,
// and decoded names are text the reader validated without repair.
//
// A nested container is reported as a PayloadArchive below the entry that
// declares it. Detection is bounded by depth, member count, and an aggregate
// byte budget, so an archive that contains an archive cannot fan out without
// limit.
type Payload struct {
	Schema   string         `json:"schema"`
	Artifact PayloadArchive `json:"artifact"`
	Entries  []PayloadEntry `json:"entries"`
}

// PayloadArchive is one inventoried container: the artifact itself or a nested
// member.
type PayloadArchive struct {
	// Depth is zero for the artifact and one or more for nested members.
	Depth int `json:"depth"`
	// Container is "zip", "tar", or "gzip".
	Container string `json:"container"`
	// Size is the artifact size. It is null for a nested member, whose size is
	// the enclosing entry's decoded size.
	Size *string `json:"size"`
	// EntryCount is the number of entries the reader loaded, and
	// LoadedEntryCount is the number projected into this payload. The second
	// can be smaller when the payload budget was exhausted.
	EntryCount       int  `json:"entry_count"`
	LoadedEntryCount int  `json:"loaded_entry_count"`
	Truncated        bool `json:"truncated"`
	// Status is "parsed", or the sentinel class that stopped a nested parse:
	// "invalid", "truncated", "limit", "unavailable", or "read".
	Status string `json:"status"`
	// GZIP is the first member header of a gzip container, null otherwise.
	GZIP *PayloadGZIP `json:"gzip"`
	// Limitations states, in deterministic order, why this container's view is
	// incomplete.
	Limitations []string       `json:"limitations"`
	Entries     []PayloadEntry `json:"entries"`
}

// PayloadGZIP mirrors the parsed header of the first gzip member.
type PayloadGZIP struct {
	Name             string  `json:"name"`
	NameAvailable    bool    `json:"name_available"`
	NameHex          string  `json:"name_hex"`
	Comment          string  `json:"comment"`
	CommentAvailable bool    `json:"comment_available"`
	ModifiedUnix     *string `json:"modified_unix"`
	OS               uint8   `json:"os"`
	ExtraBytes       uint16  `json:"extra_bytes"`
	HeaderBytes      string  `json:"header_bytes"`
}

// PayloadEntry is one file, directory, or link declared by a container.
type PayloadEntry struct {
	Index int `json:"index"`
	// Name is the decoded name, empty when NameAvailable is false. NameHex is
	// the raw stored name, capped by the reader's name limit.
	Name             string  `json:"name"`
	NameAvailable    bool    `json:"name_available"`
	NameHex          string  `json:"name_hex"`
	Unsafe           string  `json:"unsafe"`
	Type             string  `json:"type"`
	Method           string  `json:"method"`
	Mode             *uint32 `json:"mode"`
	Encrypted        bool    `json:"encrypted"`
	CompressedSize   *string `json:"compressed_size"`
	UncompressedSize *string `json:"uncompressed_size"`
	// CRC32 is the declared checksum of the uncompressed bytes, null when the
	// container stores none.
	CRC32 *uint32 `json:"crc32"`
	// ModifiedUnix is the declared modification time in Unix seconds, null when
	// absent.
	ModifiedUnix        *string `json:"modified_unix"`
	HeaderOffset        string  `json:"header_offset"`
	DataOffset          string  `json:"data_offset"`
	LinkTarget          string  `json:"link_target"`
	LinkTargetAvailable bool    `json:"link_target_available"`
	Sparse              bool    `json:"sparse"`
	// Limitations states, in deterministic order, why this entry's view is
	// incomplete or why its content cannot be read.
	Limitations []string `json:"limitations"`
	// Nested is the container this entry holds, null when the entry is not a
	// container or nested detection is disabled.
	Nested *PayloadArchive `json:"nested"`
}

// projectArchive converts a reader inventory into a payload view. It projects
// only the container-level fields; entries are added by the caller so it can
// charge each one against the payload budget.
func projectArchive(source *rearchive.Archive, depth int, size *string, status string) PayloadArchive {
	out := PayloadArchive{
		Depth:       depth,
		Container:   source.Container.String(),
		Size:        size,
		EntryCount:  len(source.Entries),
		Status:      status,
		Truncated:   source.Truncated,
		Limitations: append([]string(nil), source.Limitations...),
		GZIP:        projectGZIP(source.GZIP),
	}
	return out
}

// projectGZIP converts a gzip member header into a payload value.
func projectGZIP(header *rearchive.GZIPHeader) *PayloadGZIP {
	if header == nil {
		return nil
	}
	out := &PayloadGZIP{
		Name:             header.Name,
		NameAvailable:    header.NameAvailable,
		NameHex:          hex.EncodeToString(header.NameBytes),
		Comment:          header.Comment,
		CommentAvailable: header.CommentAvailable,
		OS:               header.OS,
		ExtraBytes:       header.ExtraBytes,
		HeaderBytes:      int64String(header.HeaderBytes),
	}
	if header.ModifiedAvailable {
		value := int64String(header.ModifiedUnix)
		out.ModifiedUnix = &value
	}
	return out
}

// projectEntry converts one reader entry into a payload value.
func projectEntry(entry rearchive.Entry) PayloadEntry {
	out := PayloadEntry{
		Index:               entry.Index,
		Name:                entry.Name,
		NameAvailable:       entry.NameAvailable,
		NameHex:             hex.EncodeToString(entry.NameBytes),
		Unsafe:              entry.NameUnsafe,
		Type:                entry.Type.String(),
		Method:              entry.Method.String(),
		Encrypted:           entry.Encrypted,
		HeaderOffset:        int64String(entry.HeaderOffset),
		DataOffset:          int64String(entry.DataOffset),
		LinkTarget:          entry.LinkTarget,
		LinkTargetAvailable: entry.LinkTargetAvailable,
		Sparse:              entry.Sparse,
		Limitations:         append([]string(nil), entry.Limitations...),
	}
	if entry.ModeAvailable {
		mode := entry.Mode
		out.Mode = &mode
	}
	if entry.CompressedSizeKnown {
		value := uint64String(entry.CompressedSize)
		out.CompressedSize = &value
	}
	if entry.UncompressedSizeKnown {
		value := uint64String(entry.UncompressedSize)
		out.UncompressedSize = &value
	}
	if entry.CRC32Available {
		crc := entry.CRC32
		out.CRC32 = &crc
	}
	if entry.ModifiedAvailable {
		value := int64String(entry.ModifiedUnix)
		out.ModifiedUnix = &value
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

// payloadBudget hands each table a fair share of the remaining payload bytes.
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

// take charges bytes that were spent outside a table allowance.
func (b *payloadBudget) take(size int) {
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
