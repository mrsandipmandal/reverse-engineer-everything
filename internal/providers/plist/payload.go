package plist

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"strconv"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	replist "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/plist"
)

const (
	// PayloadSchema identifies the property list evidence payload.
	PayloadSchema = "ree.payload.plist/1"
	// ProviderID is the stable identifier of the built-in plist provider.
	ProviderID = "builtin.plist"
	// ProviderProfile names the provider's analysis profile.
	ProviderProfile = "default"

	// DefaultPayloadBytes bounds the variable part of a payload. It leaves
	// headroom below evidence.MaxPayloadBytes for the record envelope.
	DefaultPayloadBytes = 3_500_000
	// MinPayloadBytes is the smallest configurable payload budget. The fixed
	// artifact envelope is always emitted even when this leaves no room for
	// objects.
	MinPayloadBytes = 4 << 10
	// MaxPayloadBytes is the largest configurable payload budget.
	MaxPayloadBytes = evidence.MaxPayloadBytes - (64 << 10)
)

// Payload is the ree.payload.plist/1 observation of one property list.
//
// Signed and unsigned 64-bit values are decimal strings so values above 2^53
// survive canonical JSON unchanged. Raw string bytes are lowercase hexadecimal.
//
// Objects are emitted once, at the top level, in document or object-table
// order; artifact.objects is not a second copy.
type Payload struct {
	Schema   string          `json:"schema"`
	Artifact PayloadArtifact `json:"artifact"`
	Objects  []PayloadObject `json:"objects"`
}

// PayloadArtifact is the inventoried header of the artifact.
type PayloadArtifact struct {
	// Format is "binary" or "xml".
	Format string `json:"format"`
	// Version is the binary plist version such as "00", empty for XML.
	Version string `json:"version"`
	// ObjectCount is the number of objects the reader loaded, and
	// LoadedObjectCount is the number projected into this payload. The second
	// can be smaller when the payload budget was exhausted.
	ObjectCount       int `json:"object_count"`
	LoadedObjectCount int `json:"loaded_object_count"`
	// TopObject is the index of the root value, or -1 when the root was
	// skipped by a limit.
	TopObject int `json:"top_object"`
	// Truncated reports that the inventory is incomplete.
	Truncated bool `json:"truncated"`
	// Status is "parsed" when the structure was decoded.
	Status string `json:"status"`
	// Limitations states, in deterministic order, why this artifact's view is
	// incomplete.
	Limitations []string `json:"limitations"`
}

// PayloadObject is one value in the inventory.
type PayloadObject struct {
	Index int    `json:"index"`
	Type  string `json:"type"`
	// Reachable reports that the object is reachable from TopObject within the
	// depth limit. Unreachable objects are still inventoried.
	Reachable bool `json:"reachable"`
	// Depth is the distance from TopObject, or -1 when the object is not
	// reachable.
	Depth int `json:"depth"`
	// Keys and Values are the parallel reference lists of a dictionary.
	Keys   []int `json:"keys,omitempty"`
	Values []int `json:"values,omitempty"`
	// Refs is the element list of an array or set.
	Refs []int `json:"refs,omitempty"`

	// Text is the decoded string, empty when TextAvailable is false. TextHex is
	// the raw stored bytes, capped by the reader's string limit.
	Text          string `json:"text"`
	TextAvailable bool   `json:"text_available"`
	TextHex       string `json:"text_hex"`

	Boolean bool `json:"boolean"`
	// Integer is the canonical decimal text of an integer object.
	Integer string `json:"integer"`
	// Real is the value of a finite real object, null otherwise.
	Real *float64 `json:"real"`
	// DateUnix is a date object's value in Unix seconds, null when the object
	// is not a date or the date is not finite.
	DateUnix *string `json:"date_unix"`
	// DataBytes is the declared length of a data object, null otherwise.
	DataBytes *string `json:"data_bytes"`
	// UID is the value of a UID object, null otherwise.
	UID *string `json:"uid"`

	// Limitations states, in deterministic order, why this object's view is
	// incomplete.
	Limitations []string `json:"limitations"`
}

// projectArtifact converts the reader header and counts into a payload view.
func projectArtifact(source *replist.Plist, status string) PayloadArtifact {
	return PayloadArtifact{
		Format:      source.Format.String(),
		Version:     source.Version,
		ObjectCount: len(source.Objects),
		TopObject:   source.TopObject,
		Truncated:   source.Truncated,
		Status:      status,
		Limitations: append([]string(nil), source.Limitations...),
	}
}

// projectObject converts one reader object into a payload value.
func projectObject(object replist.Object) PayloadObject {
	out := PayloadObject{
		Index:         object.Index,
		Type:          object.Type.String(),
		Reachable:     object.Reachable,
		Depth:         object.Depth,
		Keys:          ints(object.Keys),
		Values:        ints(object.Values),
		Refs:          ints(object.Refs),
		Text:          object.Text,
		TextAvailable: object.TextAvailable,
		TextHex:       hex.EncodeToString(object.TextBytes),
		Boolean:       object.Boolean,
		Integer:       object.Integer,
		Limitations:   append([]string(nil), object.Limitations...),
	}
	if object.Type == replist.TypeReal && !math.IsNaN(object.Real) && !math.IsInf(object.Real, 0) {
		value := object.Real
		out.Real = &value
	}
	if object.Type == replist.TypeDate && object.DateAvailable {
		value := int64String(object.DateUnix)
		out.DateUnix = &value
	}
	if object.Type == replist.TypeData {
		value := uint64String(object.DataBytes)
		out.DataBytes = &value
	}
	if object.Type == replist.TypeUID {
		value := uint64String(object.UID)
		out.UID = &value
	}
	return out
}

// ints converts reference indices into the payload representation. The reader
// validates every reference against the object table, so the conversion is
// always in range.
func ints(refs []uint64) []int {
	if len(refs) == 0 {
		return nil
	}
	out := make([]int, len(refs))
	for i, ref := range refs {
		out[i] = int(ref)
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

// payloadBudget hands the object table a fair share of the remaining payload
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
