package elf

import (
	"encoding/json"
	"strconv"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	reeelf "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/elf"
)

const (
	// PayloadSchema identifies the ELF evidence payload.
	PayloadSchema = "ree.payload.elf/1"
	// ProviderID is the stable identifier of the built-in ELF provider.
	ProviderID = "builtin.elf"
	// ProviderProfile names the provider's analysis profile.
	ProviderProfile = "default"

	// DefaultPayloadBytes bounds the variable part of a payload. It leaves
	// headroom below evidence.MaxPayloadBytes for the record envelope.
	DefaultPayloadBytes = 3_500_000
	// MinPayloadBytes is the smallest configurable payload budget. The fixed
	// header is always emitted even when this leaves no room for entries.
	MinPayloadBytes = 4 << 10
	// MaxPayloadBytes is the largest configurable payload budget.
	MaxPayloadBytes = evidence.MaxPayloadBytes - (64 << 10)
	// DefaultContentBytes bounds section and segment bytes hashed for payload
	// digests.
	DefaultContentBytes int64 = 128 << 20
	// MaxContentBytes bounds the configurable content hashing budget.
	MaxContentBytes int64 = reeelf.MaxArtifactBytes

	// ELF section types used by the adapter but not exported by the reader.
	sectionTypeNoBits     = 8
	sectionTypeGNUVerdef  = 0x6ffffffd
	sectionTypeGNUVerneed = 0x6ffffffe
	sectionTypeGNUVersym  = 0x6fffffff
)

// Payload is the ree.payload.elf/1 observation of one ELF artifact.
//
// Unsigned 64-bit ELF fields are decimal strings so values above 2^53 survive
// canonical JSON unchanged. Signed 64-bit addends are decimal strings too.
// Digests and note descriptors are lowercase hexadecimal.
type Payload struct {
	Schema      string              `json:"schema"`
	Header      PayloadHeader       `json:"header"`
	Sections    []PayloadSection    `json:"sections"`
	Segments    []PayloadSegment    `json:"segments"`
	Symbols     []PayloadSymbol     `json:"symbols"`
	Relocations []PayloadRelocation `json:"relocations"`
	Notes       []PayloadNote       `json:"notes"`
	BuildID     *PayloadBuildID     `json:"build_id"`
	Comments    []string            `json:"comments"`
}

// PayloadHeader mirrors the validated ELF file header.
type PayloadHeader struct {
	Class        string `json:"class"`
	Data         string `json:"data"`
	IdentVersion uint8  `json:"ident_version"`
	OSABI        uint8  `json:"osabi"`
	ABIVersion   uint8  `json:"abi_version"`

	Type    uint16 `json:"type"`
	Machine uint16 `json:"machine"`
	Version uint32 `json:"version"`
	Entry   string `json:"entry"`
	Flags   uint32 `json:"flags"`

	HeaderSize             uint16 `json:"header_size"`
	ProgramHeaderOffset    string `json:"program_header_offset"`
	SectionHeaderOffset    string `json:"section_header_offset"`
	ProgramHeaderEntrySize uint16 `json:"program_header_entry_size"`
	SectionHeaderEntrySize uint16 `json:"section_header_entry_size"`

	ProgramHeaderCount string `json:"program_header_count"`
	SectionHeaderCount string `json:"section_header_count"`
	SectionNameIndex   uint32 `json:"section_name_index"`

	LoadedProgramHeaderCount int `json:"loaded_program_header_count"`
	LoadedSectionHeaderCount int `json:"loaded_section_header_count"`

	ExtendedProgramHeaderCount bool `json:"extended_program_header_count"`
	ExtendedSectionHeaderCount bool `json:"extended_section_header_count"`
	ExtendedSectionNameIndex   bool `json:"extended_section_name_index"`
}

// PayloadSection is one section header observation.
type PayloadSection struct {
	Index         int     `json:"index"`
	Name          string  `json:"name"`
	NameAvailable bool    `json:"name_available"`
	Type          uint32  `json:"type"`
	Flags         string  `json:"flags"`
	Address       string  `json:"address"`
	Offset        string  `json:"offset"`
	Size          string  `json:"size"`
	Link          uint32  `json:"link"`
	Info          uint32  `json:"info"`
	AddressAlign  string  `json:"address_align"`
	EntrySize     string  `json:"entry_size"`
	DataSHA256    *string `json:"data_sha256,omitempty"`
}

// PayloadSegment is one program header observation.
type PayloadSegment struct {
	Index           int     `json:"index"`
	Type            uint32  `json:"type"`
	Flags           uint32  `json:"flags"`
	Offset          string  `json:"offset"`
	VirtualAddress  string  `json:"virtual_address"`
	PhysicalAddress string  `json:"physical_address"`
	FileSize        string  `json:"file_size"`
	MemorySize      string  `json:"memory_size"`
	Align           string  `json:"align"`
	DataSHA256      *string `json:"data_sha256,omitempty"`
}

// PayloadSymbol is one symbol table entry.
type PayloadSymbol struct {
	TableIndex           int    `json:"table_index"`
	Index                int    `json:"index"`
	Name                 string `json:"name"`
	NameOffset           uint32 `json:"name_offset"`
	Info                 uint8  `json:"info"`
	Other                uint8  `json:"other"`
	SectionIndex         uint32 `json:"section_index"`
	ExtendedSectionIndex bool   `json:"extended_section_index"`
	Value                string `json:"value"`
	Size                 string `json:"size"`
}

// PayloadRelocation is one relocation section entry.
type PayloadRelocation struct {
	SectionIndex       int    `json:"section_index"`
	TargetSectionIndex uint32 `json:"target_section_index"`
	Index              int    `json:"index"`
	Offset             string `json:"offset"`
	Info               string `json:"info"`
	SymbolIndex        uint32 `json:"symbol_index"`
	Type               uint32 `json:"type"`
	Addend             string `json:"addend"`
	HasAddend          bool   `json:"has_addend"`
}

// PayloadNote is one SHT_NOTE entry.
//
// The descriptor digest is always present. DescriptorHex is omitted for
// descriptors above the payload descriptor limit so one large note cannot
// exceed the evidence string limit.
type PayloadNote struct {
	SectionIndex     int     `json:"section_index"`
	Name             string  `json:"name"`
	Type             uint32  `json:"type"`
	DescriptorSize   int     `json:"descriptor_size"`
	DescriptorSHA256 string  `json:"descriptor_sha256"`
	DescriptorHex    *string `json:"descriptor_hex,omitempty"`
}

// PayloadBuildID is the GNU build-id descriptor.
type PayloadBuildID struct {
	Hex  string `json:"hex"`
	Size int    `json:"size"`
}

func uint64String(value uint64) string { return strconv.FormatUint(value, 10) }

func int64String(value int64) string { return strconv.FormatInt(value, 10) }

func jsonSize(value any) int {
	raw, err := json.Marshal(value)
	if err != nil {
		return 0
	}
	return len(raw)
}

// payloadBudget divides a byte budget across tables by share. A table that
// uses less than its allowance leaves the remainder for later tables.
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

func (b *payloadBudget) start(share int) {
	if b.shares <= 0 || b.remaining <= 0 {
		b.allowance = 0
		b.used = 0
		return
	}
	b.allowance = b.remaining * share / b.shares
	b.used = 0
	b.shares -= share
}

// reserve charges a fixed cost before any table share is computed.
func (b *payloadBudget) reserve(size int) {
	b.remaining -= size
	if b.remaining < 0 {
		b.remaining = 0
	}
}

func (b *payloadBudget) fits(size int) bool { return b.used+size <= b.allowance }

func (b *payloadBudget) add(size int) { b.used += size }

func (b *payloadBudget) finish() {
	b.remaining -= b.used
	if b.remaining < 0 {
		b.remaining = 0
	}
}
