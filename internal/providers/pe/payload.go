package pe

import (
	"encoding/json"
	"strconv"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	repe "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/pe"
)

const (
	// PayloadSchema identifies the PE evidence payload.
	PayloadSchema = "ree.payload.pe/1"
	// ProviderID is the stable identifier of the built-in PE provider.
	ProviderID = "builtin.pe"
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
	// DefaultContentBytes bounds section bytes hashed for payload digests.
	DefaultContentBytes int64 = 128 << 20
	// MaxContentBytes bounds the configurable content hashing budget.
	MaxContentBytes int64 = repe.MaxArtifactBytes
)

// Payload is the ree.payload.pe/1 observation of one PE32 or PE32+ artifact.
//
// Unsigned 64-bit fields are decimal strings so values above 2^53 survive
// canonical JSON unchanged. Raw 32-bit and 16-bit fields stay JSON numbers.
// Digests and raw section name fields are lowercase hexadecimal.
type Payload struct {
	Schema          string                 `json:"schema"`
	Header          PayloadHeader          `json:"header"`
	DataDirectories []PayloadDataDirectory `json:"data_directories"`
	Sections        []PayloadSection       `json:"sections"`
	Overlay         *PayloadOverlay        `json:"overlay"`
	Imports         *PayloadImports        `json:"imports"`
	Exports         *PayloadExports        `json:"exports"`
	Resources       *PayloadResources      `json:"resources"`
	Certificates    *PayloadCertificates   `json:"certificates"`
}

// PayloadHeader mirrors the validated DOS, PE, and COFF header.
type PayloadHeader struct {
	DOSMagic       uint16 `json:"dos_magic"`
	PEHeaderOffset uint32 `json:"pe_header_offset"`

	Machine              uint16 `json:"machine"`
	NumberOfSections     uint16 `json:"number_of_sections"`
	TimeDateStamp        uint32 `json:"time_date_stamp"`
	PointerToSymbolTable uint32 `json:"pointer_to_symbol_table"`
	NumberOfSymbols      uint32 `json:"number_of_symbols"`
	SizeOfOptionalHeader uint16 `json:"size_of_optional_header"`
	Characteristics      uint16 `json:"characteristics"`

	Optional              PayloadOptionalHeader `json:"optional"`
	LoadedDataDirectories int                   `json:"loaded_data_directory_count"`
	LoadedSections        int                   `json:"loaded_section_count"`
}

// PayloadOptionalHeader mirrors the decoded PE32 or PE32+ optional header.
type PayloadOptionalHeader struct {
	Magic                   uint16 `json:"magic"`
	MajorLinkerVersion      uint8  `json:"major_linker_version"`
	MinorLinkerVersion      uint8  `json:"minor_linker_version"`
	SizeOfCode              uint32 `json:"size_of_code"`
	SizeOfInitializedData   uint32 `json:"size_of_initialized_data"`
	SizeOfUninitializedData uint32 `json:"size_of_uninitialized_data"`
	AddressOfEntryPoint     uint32 `json:"address_of_entry_point"`
	BaseOfCode              uint32 `json:"base_of_code"`
	BaseOfData              uint32 `json:"base_of_data"`
	ImageBase               string `json:"image_base"`
	SectionAlignment        uint32 `json:"section_alignment"`
	FileAlignment           uint32 `json:"file_alignment"`

	MajorOperatingSystemVersion uint16 `json:"major_operating_system_version"`
	MinorOperatingSystemVersion uint16 `json:"minor_operating_system_version"`
	MajorImageVersion           uint16 `json:"major_image_version"`
	MinorImageVersion           uint16 `json:"minor_image_version"`
	MajorSubsystemVersion       uint16 `json:"major_subsystem_version"`
	MinorSubsystemVersion       uint16 `json:"minor_subsystem_version"`
	Win32VersionValue           uint32 `json:"win32_version_value"`
	SizeOfImage                 uint32 `json:"size_of_image"`
	SizeOfHeaders               uint32 `json:"size_of_headers"`
	CheckSum                    uint32 `json:"check_sum"`
	Subsystem                   uint16 `json:"subsystem"`
	DllCharacteristics          uint16 `json:"dll_characteristics"`
	SizeOfStackReserve          string `json:"size_of_stack_reserve"`
	SizeOfStackCommit           string `json:"size_of_stack_commit"`
	SizeOfHeapReserve           string `json:"size_of_heap_reserve"`
	SizeOfHeapCommit            string `json:"size_of_heap_commit"`
	LoaderFlags                 uint32 `json:"loader_flags"`
	NumberOfRvaAndSizes         uint32 `json:"number_of_rva_and_sizes"`
}

// PayloadDataDirectory is one optional header data directory entry.
//
// The values are raw. In the security directory, index 4, VirtualAddress is a
// file offset rather than an RVA.
type PayloadDataDirectory struct {
	Index          int    `json:"index"`
	VirtualAddress uint32 `json:"virtual_address"`
	Size           uint32 `json:"size"`
}

// PayloadSection is one section header observation.
type PayloadSection struct {
	Index         int    `json:"index"`
	Name          string `json:"name"`
	NameAvailable bool   `json:"name_available"`
	// NameHex is the raw eight-byte name field as lowercase hexadecimal.
	NameHex string `json:"name_hex"`

	VirtualSize          uint32 `json:"virtual_size"`
	VirtualAddress       uint32 `json:"virtual_address"`
	SizeOfRawData        uint32 `json:"size_of_raw_data"`
	PointerToRawData     uint32 `json:"pointer_to_raw_data"`
	PointerToRelocations uint32 `json:"pointer_to_relocations"`
	PointerToLinenumbers uint32 `json:"pointer_to_linenumbers"`
	NumberOfRelocations  uint16 `json:"number_of_relocations"`
	NumberOfLinenumbers  uint16 `json:"number_of_linenumbers"`
	Characteristics      uint32 `json:"characteristics"`

	// DataSHA256 is the digest of the declared raw section bytes. It is
	// omitted for empty sections and when the content budget could not hash
	// them.
	DataSHA256 *string `json:"data_sha256,omitempty"`
}

// PayloadOverlay describes bytes after the headers and the last section raw
// data.
type PayloadOverlay struct {
	Offset string `json:"offset"`
	Size   string `json:"size"`
}

// PayloadImports is the decoded import directory. It is null when the artifact
// declares no import directory or the directory could not be used; a record
// limitation then states why.
type PayloadImports struct {
	Modules   []PayloadImportModule `json:"modules"`
	Truncated bool                  `json:"truncated"`
}

// PayloadImportModule is one import descriptor.
type PayloadImportModule struct {
	Index         int    `json:"index"`
	Name          string `json:"name"`
	NameAvailable bool   `json:"name_available"`
	NameRVA       uint32 `json:"name_rva"`

	TimeDateStamp      uint32 `json:"time_date_stamp"`
	ForwarderChain     uint32 `json:"forwarder_chain"`
	OriginalFirstThunk uint32 `json:"original_first_thunk"`
	FirstThunk         uint32 `json:"first_thunk"`

	ThunkSource string               `json:"thunk_source"`
	Thunks      []PayloadImportThunk `json:"thunks"`
	Truncated   bool                 `json:"truncated"`
}

// PayloadImportThunk is one import name or ordinal entry.
type PayloadImportThunk struct {
	Index         int    `json:"index"`
	ByOrdinal     bool   `json:"by_ordinal"`
	Ordinal       uint16 `json:"ordinal"`
	Hint          uint16 `json:"hint"`
	Name          string `json:"name"`
	NameAvailable bool   `json:"name_available"`
	NameRVA       uint32 `json:"name_rva"`
}

// PayloadExports is the decoded export directory. It is null when the artifact
// declares no export directory or the directory could not be used.
type PayloadExports struct {
	Name          string `json:"name"`
	NameAvailable bool   `json:"name_available"`
	NameRVA       uint32 `json:"name_rva"`

	TimeDateStamp uint32 `json:"time_date_stamp"`
	MajorVersion  uint16 `json:"major_version"`
	MinorVersion  uint16 `json:"minor_version"`
	Base          uint32 `json:"base"`

	NumberOfFunctions     uint32 `json:"number_of_functions"`
	NumberOfNames         uint32 `json:"number_of_names"`
	AddressOfFunctions    uint32 `json:"address_of_functions"`
	AddressOfNames        uint32 `json:"address_of_names"`
	AddressOfNameOrdinals uint32 `json:"address_of_name_ordinals"`

	Exports   []PayloadExport `json:"exports"`
	Truncated bool            `json:"truncated"`
}

// PayloadExport is one exported function slot.
type PayloadExport struct {
	Index              int    `json:"index"`
	Ordinal            uint32 `json:"ordinal"`
	RVA                uint32 `json:"rva"`
	Name               string `json:"name"`
	NameAvailable      bool   `json:"name_available"`
	NameRVA            uint32 `json:"name_rva"`
	Forwarder          string `json:"forwarder"`
	ForwarderAvailable bool   `json:"forwarder_available"`
}

// PayloadResources is the decoded resource tree. It is null when the artifact
// declares no resource directory or the directory could not be used.
type PayloadResources struct {
	Resources []PayloadResource `json:"resources"`
	Truncated bool              `json:"truncated"`
}

// PayloadResource is one leaf resource with its path from the root type level.
type PayloadResource struct {
	Path          []PayloadResourceIdentifier `json:"path"`
	DataRVA       uint32                      `json:"data_rva"`
	DataSize      uint32                      `json:"data_size"`
	CodePage      uint32                      `json:"code_page"`
	DataAvailable bool                        `json:"data_available"`
}

// PayloadResourceIdentifier is one resource path level.
type PayloadResourceIdentifier struct {
	IsName        bool   `json:"is_name"`
	Name          string `json:"name"`
	NameAvailable bool   `json:"name_available"`
	ID            uint32 `json:"id"`
}

// PayloadCertificates is the decoded attribute certificate table. It is null
// when the artifact declares no security directory or the directory could not
// be used.
type PayloadCertificates struct {
	Offset       string               `json:"offset"`
	Size         uint32               `json:"size"`
	Certificates []PayloadCertificate `json:"certificates"`
	Truncated    bool                 `json:"truncated"`
}

// PayloadCertificate is one WIN_CERTIFICATE record header.
type PayloadCertificate struct {
	Index      int    `json:"index"`
	Offset     string `json:"offset"`
	Length     uint32 `json:"length"`
	Revision   uint16 `json:"revision"`
	Type       uint16 `json:"type"`
	DataOffset string `json:"data_offset"`
	DataSize   uint32 `json:"data_size"`
}

func uint64String(value uint64) string { return strconv.FormatUint(value, 10) }

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
