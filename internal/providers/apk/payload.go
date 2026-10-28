package apk

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	reapk "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/apk"
	"github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/archive"
)

const (
	// PayloadSchema identifies the APK evidence payload.
	PayloadSchema = "ree.payload.apk/1"
	// ProviderID is the stable identifier of the built-in APK provider.
	ProviderID = "builtin.apk"
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

// Payload is the ree.payload.apk/1 observation of one Android package.
//
// Sizes are decimal strings so values above 2^53 survive canonical JSON
// unchanged. Raw names are lowercase hexadecimal, and decoded names are text
// the ZIP reader validated without repair.
//
// Entries are emitted once, at the top level; the artifact counts summarise
// them but do not repeat them.
type Payload struct {
	Schema   string          `json:"schema"`
	Artifact PayloadArtifact `json:"artifact"`
	Entries  []PayloadEntry  `json:"entries"`
}

// PayloadArtifact is the inventoried package envelope.
type PayloadArtifact struct {
	// EntryCount is the number of ZIP entries the reader loaded, and
	// LoadedEntryCount is the number projected into this payload.
	EntryCount       int  `json:"entry_count"`
	LoadedEntryCount int  `json:"loaded_entry_count"`
	Truncated        bool `json:"truncated"`
	// Status is "parsed" when the ZIP directory, the Android layout, and the
	// signing block were decoded.
	Status string `json:"status"`
	// Counts summarises the entry kinds in this package.
	Counts PayloadCounts `json:"counts"`
	// Signing is the APK Signing Block, absent when the package carries only
	// a scheme v1 signature.
	Signing PayloadSigning `json:"signing"`
	// Limitations states, in deterministic order, why this artifact's view is
	// incomplete.
	Limitations []string `json:"limitations"`
}

// PayloadCounts summarises the Android roles of the loaded entries.
type PayloadCounts struct {
	Manifest      int `json:"manifest"`
	DEX           int `json:"dex"`
	Resources     int `json:"resources"`
	NativeLibrary int `json:"native_library"`
	ResourceEntry int `json:"resource_entry"`
	Asset         int `json:"asset"`
	SignatureFile int `json:"signature_file"`
	Other         int `json:"other"`
}

// PayloadSigning is the APK Signing Block view.
type PayloadSigning struct {
	Present bool `json:"present"`
	// Offset and Size are absolute artifact values, null when absent.
	Offset *string `json:"offset"`
	Size   *string `json:"size"`
	// PairCount is the number of pairs decoded and Pairs are those pairs.
	PairCount   int           `json:"pair_count"`
	Truncated   bool          `json:"truncated"`
	Pairs       []PayloadPair `json:"pairs"`
	Limitations []string      `json:"limitations"`
}

// PayloadPair is one identification pair in the signing block.
type PayloadPair struct {
	// ID is the pair identifier as a hexadecimal string, so the value stays
	// exact in JSON.
	ID string `json:"id"`
	// Scheme names a known signing scheme, empty when the identifier is
	// unrecognized.
	Scheme string `json:"scheme"`
	// Size is the declared value length.
	Size string `json:"size"`
	// Digest is the lowercase SHA-256 of the value, null when unavailable.
	Digest          *string `json:"digest"`
	DigestAvailable bool    `json:"digest_available"`
}

// PayloadEntry is one ZIP entry with its Android role.
type PayloadEntry struct {
	Index int `json:"index"`
	// Name is the decoded name, empty when NameAvailable is false. NameHex is
	// the raw name bytes, capped by the ZIP reader's name limit.
	Name          string `json:"name"`
	NameAvailable bool   `json:"name_available"`
	NameHex       string `json:"name_hex"`
	Unsafe        string `json:"unsafe"`
	Kind          string `json:"kind"`
	// ABI is the native library ABI, empty for every other kind.
	ABI string `json:"abi"`
	// CompressedSize and UncompressedSize are the declared ZIP sizes, null
	// when the container does not store them.
	CompressedSize   *string `json:"compressed_size"`
	UncompressedSize *string `json:"uncompressed_size"`
	// Digest is the lowercase SHA-256 of a well-known member, null when the
	// member was not hashed.
	Digest          *string `json:"digest"`
	DigestAvailable bool    `json:"digest_available"`
	// Limitations states, in deterministic order, why this entry's view is
	// incomplete.
	Limitations []string `json:"limitations"`
}

// projectArtifact converts the package envelope into a payload view.
func projectArtifact(source *reapk.APK, status string) PayloadArtifact {
	counts := PayloadCounts{}
	for _, entry := range source.Entries {
		switch entry.Kind {
		case reapk.KindManifest:
			counts.Manifest++
		case reapk.KindDEX:
			counts.DEX++
		case reapk.KindResources:
			counts.Resources++
		case reapk.KindNativeLibrary:
			counts.NativeLibrary++
		case reapk.KindResource:
			counts.ResourceEntry++
		case reapk.KindAsset:
			counts.Asset++
		case reapk.KindSignature:
			counts.SignatureFile++
		default:
			counts.Other++
		}
	}
	return PayloadArtifact{
		EntryCount:  len(source.Entries),
		Truncated:   source.Truncated,
		Status:      status,
		Counts:      counts,
		Signing:     projectSigning(source.Signing),
		Limitations: append([]string(nil), source.Limitations...),
	}
}

// projectSigning converts the signing block into a payload view.
func projectSigning(source reapk.SigningBlock) PayloadSigning {
	out := PayloadSigning{
		Present:     source.Present,
		Truncated:   source.Truncated,
		Pairs:       []PayloadPair{},
		Limitations: append([]string(nil), source.Limitations...),
	}
	if source.Present {
		offset := int64String(source.Offset)
		size := uint64String(source.Size)
		out.Offset, out.Size = &offset, &size
	}
	for _, pair := range source.Pairs {
		projected := PayloadPair{
			ID:              fmt.Sprintf("0x%08x", pair.ID),
			Scheme:          pair.Scheme,
			Size:            uint64String(pair.ValueBytes),
			DigestAvailable: pair.DigestAvailable,
		}
		if pair.DigestAvailable {
			digest := pair.Digest
			projected.Digest = &digest
		}
		out.Pairs = append(out.Pairs, projected)
	}
	out.PairCount = len(out.Pairs)
	return out
}

// projectEntry converts one ZIP entry and its classification.
func projectEntry(entry *archive.Entry, class reapk.Entry) PayloadEntry {
	out := PayloadEntry{
		Index:           entry.Index,
		Name:            entry.Name,
		NameAvailable:   entry.NameAvailable,
		NameHex:         hex.EncodeToString(entry.NameBytes),
		Unsafe:          entry.NameUnsafe,
		Kind:            class.Kind.String(),
		ABI:             class.ABI,
		DigestAvailable: class.DigestAvailable,
		Limitations:     append([]string(nil), class.Limitations...),
	}
	if entry.CompressedSizeKnown {
		value := uint64String(entry.CompressedSize)
		out.CompressedSize = &value
	}
	if entry.UncompressedSizeKnown {
		value := uint64String(entry.UncompressedSize)
		out.UncompressedSize = &value
	}
	if class.DigestAvailable {
		digest := class.Digest
		out.Digest = &digest
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
