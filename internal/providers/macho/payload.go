package macho

import (
	"encoding/json"
	"strconv"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	remacho "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/macho"
)

const (
	// PayloadSchema identifies the Mach-O evidence payload.
	PayloadSchema = "ree.payload.macho/1"
	// ProviderID is the stable identifier of the built-in Mach-O provider.
	ProviderID = "builtin.macho"
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
	// DefaultContentBytes bounds section bytes hashed for payload digests.
	DefaultContentBytes int64 = 128 << 20
	// MaxContentBytes bounds the configurable content hashing budget.
	MaxContentBytes int64 = remacho.MaxArtifactBytes
)

// Payload is the ree.payload.macho/1 observation of one thin or universal
// Mach-O artifact.
//
// Unsigned 64-bit fields are decimal strings so values above 2^53 survive
// canonical JSON unchanged. Raw 32-bit and 16-bit fields stay JSON numbers.
// Digests, identifiers, and raw name fields are lowercase hexadecimal.
//
// A thin artifact carries exactly one slice. A universal artifact carries one
// entry per architecture, and a slice that could not be parsed keeps its status
// and its record-level limitation instead of disappearing.
type Payload struct {
	Schema   string          `json:"schema"`
	Artifact PayloadArtifact `json:"artifact"`
	Slices   []PayloadSlice  `json:"slices"`
}

// PayloadArtifact mirrors the validated thin or universal header.
type PayloadArtifact struct {
	// Magic is the canonical magic as a number, and MagicName spells it.
	Magic     uint32 `json:"magic"`
	MagicName string `json:"magic_name"`
	// Fat reports a universal header. ByteOrder is the header byte order;
	// each slice reports its own image byte order.
	Fat       bool   `json:"fat"`
	ByteOrder string `json:"byte_order"`

	Size             string `json:"size"`
	SliceCount       int    `json:"slice_count"`
	LoadedSliceCount int    `json:"loaded_slice_count"`
	Truncated        bool   `json:"truncated"`
}

// PayloadSlice is one architecture image of the artifact.
type PayloadSlice struct {
	Index      int    `json:"index"`
	CPUType    uint32 `json:"cpu_type"`
	CPUSubtype uint32 `json:"cpu_subtype"`
	Offset     string `json:"offset"`
	Size       string `json:"size"`
	Alignment  uint32 `json:"alignment"`
	// Status is "parsed" or the sentinel class that prevented parsing:
	// "invalid", "truncated", "limit", "unavailable", or "read".
	Status string `json:"status"`

	Header        *PayloadHeader        `json:"header"`
	Segments      []PayloadSegment      `json:"segments"`
	Sections      []PayloadSection      `json:"sections"`
	Dylibs        *PayloadDylibs        `json:"dylibs"`
	Build         *PayloadBuild         `json:"build"`
	Entry         *PayloadEntry         `json:"entry"`
	Symbols       *PayloadSymbols       `json:"symbols"`
	CodeSignature *PayloadCodeSignature `json:"code_signature"`

	Limitations []string `json:"limitations"`
}

// PayloadHeader mirrors the validated image header.
type PayloadHeader struct {
	Magic     uint32 `json:"magic"`
	MagicName string `json:"magic_name"`
	Is64      bool   `json:"is_64"`
	ByteOrder string `json:"byte_order"`

	CPUType      uint32 `json:"cpu_type"`
	CPUSubtype   uint32 `json:"cpu_subtype"`
	FileType     uint32 `json:"file_type"`
	FileTypeName string `json:"file_type_name"`
	Flags        uint32 `json:"flags"`
	Reserved     uint32 `json:"reserved"`

	DeclaredCommandCount uint32 `json:"declared_command_count"`
	LoadedCommandCount   int    `json:"loaded_command_count"`
	LoadedSegmentCount   int    `json:"loaded_segment_count"`
	LoadedSectionCount   int    `json:"loaded_section_count"`
	// SizeOfCommands is the declared load command byte count.
	SizeOfCommands uint32 `json:"size_of_commands"`
	Truncated      bool   `json:"truncated"`
}

// PayloadSegment mirrors one decoded LC_SEGMENT or LC_SEGMENT_64 command.
type PayloadSegment struct {
	Index         int    `json:"index"`
	Command       uint32 `json:"command"`
	Name          string `json:"name"`
	NameAvailable bool   `json:"name_available"`
	NameHex       string `json:"name_hex"`

	VMAddress  string `json:"vm_address"`
	VMSize     string `json:"vm_size"`
	FileOffset string `json:"file_offset"`
	FileSize   string `json:"file_size"`

	MaxProtection  uint32 `json:"max_protection"`
	InitProtection uint32 `json:"init_protection"`
	Flags          uint32 `json:"flags"`

	DeclaredSectionCount uint32 `json:"declared_section_count"`
	FirstSection         int    `json:"first_section"`
	SectionCount         int    `json:"section_count"`
}

// PayloadSection mirrors one section record.
type PayloadSection struct {
	Index         int    `json:"index"`
	SegmentIndex  int    `json:"segment_index"`
	Name          string `json:"name"`
	NameAvailable bool   `json:"name_available"`
	NameHex       string `json:"name_hex"`

	Address             string `json:"address"`
	Size                string `json:"size"`
	Offset              uint32 `json:"offset"`
	Alignment           uint32 `json:"alignment"`
	RelocationOffset    uint32 `json:"relocation_offset"`
	NumberOfRelocations uint32 `json:"number_of_relocations"`
	Flags               uint32 `json:"flags"`
	Reserved1           uint32 `json:"reserved1"`
	Reserved2           uint32 `json:"reserved2"`
	Reserved3           uint32 `json:"reserved3"`

	// DataSHA256 is the digest of the stored section bytes, absent when the
	// section is empty, over the content budget, or unavailable.
	DataSHA256 *string `json:"data_sha256,omitempty"`
}

// PayloadDylibs is the dylib command table of one image.
type PayloadDylibs struct {
	// InstallName is the LC_ID_DYLIB name, absent when the image has none.
	InstallName          *string        `json:"install_name,omitempty"`
	InstallNameAvailable bool           `json:"install_name_available"`
	Dylibs               []PayloadDylib `json:"dylibs"`
	Truncated            bool           `json:"truncated"`
}

// PayloadDylib mirrors one dylib load command.
type PayloadDylib struct {
	Index         int    `json:"index"`
	Command       uint32 `json:"command"`
	CommandName   string `json:"command_name"`
	Kind          string `json:"kind"`
	Name          string `json:"name"`
	NameAvailable bool   `json:"name_available"`
	NameOffset    uint32 `json:"name_offset"`

	Timestamp            uint32 `json:"timestamp"`
	CurrentVersion       uint32 `json:"current_version"`
	CompatibilityVersion uint32 `json:"compatibility_version"`
}

// PayloadBuild mirrors LC_BUILD_VERSION or a legacy version-min command.
type PayloadBuild struct {
	Command           uint32             `json:"command"`
	CommandName       string             `json:"command_name"`
	Platform          uint32             `json:"platform"`
	PlatformAvailable bool               `json:"platform_available"`
	PlatformName      string             `json:"platform_name"`
	MinimumOS         uint32             `json:"minimum_os"`
	SDK               uint32             `json:"sdk"`
	Tools             []PayloadBuildTool `json:"tools"`
}

// PayloadBuildTool is one tool record of LC_BUILD_VERSION.
type PayloadBuildTool struct {
	Tool     uint32 `json:"tool"`
	ToolName string `json:"tool_name"`
	Version  uint32 `json:"version"`
}

// PayloadEntry mirrors LC_MAIN.
type PayloadEntry struct {
	// EntryOffset is a file offset, not a virtual address.
	EntryOffset string `json:"entry_offset"`
	StackSize   string `json:"stack_size"`
}

// PayloadSymbols is the decoded LC_SYMTAB table of one image.
type PayloadSymbols struct {
	DeclaredCount uint32          `json:"declared_count"`
	LoadedCount   int             `json:"loaded_count"`
	StringBytes   string          `json:"string_bytes"`
	Truncated     bool            `json:"truncated"`
	Symbols       []PayloadSymbol `json:"symbols"`
}

// PayloadSymbol mirrors one nlist or nlist_64 entry.
type PayloadSymbol struct {
	Index         int    `json:"index"`
	StringIndex   uint32 `json:"string_index"`
	Name          string `json:"name"`
	NameAvailable bool   `json:"name_available"`
	Type          uint8  `json:"type"`
	Section       uint8  `json:"section"`
	Description   uint16 `json:"description"`
	Value         string `json:"value"`
}

// PayloadCodeSignature is the LC_CODE_SIGNATURE record and its superblob
// headers.
//
// Presence proves nothing about trust: no signature, certificate, or
// entitlement is verified or decoded.
type PayloadCodeSignature struct {
	DataOffset string `json:"data_offset"`
	DataSize   string `json:"data_size"`

	Magic  uint32 `json:"magic"`
	Length uint32 `json:"length"`
	Count  uint32 `json:"count"`

	Blobs     []PayloadCodeSignatureBlob `json:"blobs"`
	Truncated bool                       `json:"truncated"`
}

// PayloadCodeSignatureBlob is one superblob index entry and its blob header.
type PayloadCodeSignatureBlob struct {
	Index  int    `json:"index"`
	Type   uint32 `json:"type"`
	Offset uint32 `json:"offset"`
	Magic  uint32 `json:"magic"`
	Length uint32 `json:"length"`
}

// uint64String renders an unsigned 64-bit value as a decimal string so it
// survives canonical JSON unchanged.
func uint64String(value uint64) string {
	return strconv.FormatUint(value, 10)
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
