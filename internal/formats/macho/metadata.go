package macho

import "fmt"

// Load commands decoded by the metadata layer. The segment commands are in
// macho.go; this file names the rest.
const (
	// CommandSymtab is LC_SYMTAB, the symbol and string table location.
	CommandSymtab uint32 = 0x2
	// CommandDylibID is LC_ID_DYLIB, the install name of a dylib.
	CommandDylibID uint32 = 0xd
	// CommandLoadDylib is LC_LOAD_DYLIB, a required dependency.
	CommandLoadDylib uint32 = 0xc
	// CommandLoadWeakDylib is LC_LOAD_WEAK_DYLIB, an optional dependency.
	CommandLoadWeakDylib uint32 = 0x80000018
	// CommandReexportDylib is LC_REEXPORT_DYLIB, a re-exported dependency.
	CommandReexportDylib uint32 = 0x8000001f
	// CommandLazyLoadDylib is LC_LAZY_LOAD_DYLIB, a lazily loaded dependency.
	CommandLazyLoadDylib uint32 = 0x20
	// CommandLoadUpwardDylib is LC_LOAD_UPWARD_DYLIB, an upward dependency.
	CommandLoadUpwardDylib uint32 = 0x80000023
	// CommandUUID is LC_UUID, the sixteen-byte image identifier.
	CommandUUID uint32 = 0x1b
	// CommandCodeSignature is LC_CODE_SIGNATURE, the embedded signature range.
	CommandCodeSignature uint32 = 0x1d
	// CommandVersionMinMacOSX is the legacy macOS minimum version command.
	CommandVersionMinMacOSX uint32 = 0x24
	// CommandVersionMinIPhoneOS is the legacy iOS minimum version command.
	CommandVersionMinIPhoneOS uint32 = 0x25
	// CommandVersionMinTVOS is the legacy tvOS minimum version command.
	CommandVersionMinTVOS uint32 = 0x2f
	// CommandVersionMinWatchOS is the legacy watchOS minimum version command.
	CommandVersionMinWatchOS uint32 = 0x30
	// CommandBuildVersion is LC_BUILD_VERSION, the platform and SDK record.
	CommandBuildVersion uint32 = 0x32
	// CommandMain is LC_MAIN, the entry point offset.
	CommandMain uint32 = 0x80000028
)

// CodeSignatureMagic is CSMAGIC_EMBEDDED_SIGNATURE, the superblob magic that
// wraps an embedded signature. Signature structures are always big-endian.
const CodeSignatureMagic uint32 = 0xfade0cc0

// Dylib is one decoded dylib load command.
type Dylib struct {
	// Index is the position among the dylib commands, in load command order.
	Index int
	// Command is the raw command, one of the Command*Dylib constants.
	Command uint32
	// Name is the install name or dependency path, decoded from the command.
	// It is empty when NameAvailable is false.
	Name string
	// NameAvailable reports that the name was non-empty, NUL-terminated,
	// inside the command, within the string limit, and valid UTF-8.
	NameAvailable bool
	// NameOffset is the raw offset of the name inside the command.
	NameOffset uint32

	Timestamp            uint32
	CurrentVersion       uint32
	CompatibilityVersion uint32
}

// DylibTable is the dylib load commands of one image, in command order.
type DylibTable struct {
	Dylibs []Dylib
	// Truncated reports that the table stopped at the configured limit or at a
	// command that could not be decoded.
	Truncated bool
	// Limitations states, in deterministic order, why the table is incomplete.
	Limitations []string
}

// Dylibs returns the dylib load commands of the image.
//
// A missing dylib command returns ErrNotFound. Reader failures wrap ErrRead;
// per-command defects become limitations so one malformed command does not hide
// the others.
func (f *File) Dylibs() (DylibTable, error) {
	table, err := f.commandTable()
	if err != nil {
		return DylibTable{}, err
	}
	order := byteOrder(f.Header.Data)
	out := DylibTable{Dylibs: []Dylib{}}
	pos := 0
	index := 0
	invalidNames := 0
	longNames := 0
	unterminated := 0
	for pos+loadCommandSize <= len(table) {
		command := order.Uint32(table[pos:])
		size := int(order.Uint32(table[pos+4:]))
		if size < loadCommandSize || pos+size > len(table) {
			break
		}
		if !isDylibCommand(command) {
			pos += size
			continue
		}
		if size < dylibCommandSize {
			out.Truncated = true
			out.note("dylib command %d is %d bytes", index, size)
			break
		}
		if len(out.Dylibs) >= f.limits.Dylibs {
			out.Truncated = true
			out.note("dylib count %d exceeds limit %d", len(out.Dylibs)+1, f.limits.Dylibs)
			break
		}
		raw := table[pos : pos+size]
		entry, nameStatus := f.decodeDylib(index, command, raw)
		switch nameStatus {
		case nameInvalid:
			invalidNames++
		case nameTooLong:
			longNames++
		case nameUnterminated:
			unterminated++
		}
		out.Dylibs = append(out.Dylibs, entry)
		index++
		pos += size
	}
	if len(out.Dylibs) == 0 {
		return DylibTable{}, fmtNotFound("dylib command")
	}
	if invalidNames > 0 {
		out.note("%d dylib names are not valid UTF-8", invalidNames)
	}
	if longNames > 0 {
		out.note("%d dylib names exceed %d bytes", longNames, f.limits.StringBytes)
	}
	if unterminated > 0 {
		out.note("%d dylib names are not NUL-terminated", unterminated)
	}
	return out, nil
}

func isDylibCommand(command uint32) bool {
	switch command {
	case CommandDylibID, CommandLoadDylib, CommandLoadWeakDylib,
		CommandReexportDylib, CommandLazyLoadDylib, CommandLoadUpwardDylib:
		return true
	default:
		return false
	}
}

// UUID returns the sixteen-byte LC_UUID value.
//
// A missing command returns ErrNotFound. When a malformed image carries several
// UUID commands the first one is returned; duplicates are not reported.
func (f *File) UUID() ([16]byte, error) {
	var uuid [16]byte
	table, err := f.commandTable()
	if err != nil {
		return uuid, err
	}
	order := byteOrder(f.Header.Data)
	for pos := 0; pos+loadCommandSize <= len(table); {
		command := order.Uint32(table[pos:])
		size := int(order.Uint32(table[pos+4:]))
		if size < loadCommandSize || pos+size > len(table) {
			break
		}
		if command == CommandUUID {
			if size < uuidCommandSize {
				return uuid, fmt.Errorf("%w: UUID command is %d bytes", ErrInvalid, size)
			}
			copy(uuid[:], table[pos+loadCommandSize:pos+uuidCommandSize])
			return uuid, nil
		}
		pos += size
	}
	return uuid, fmtNotFound("UUID command")
}

// BuildVersionTool is one tool record of LC_BUILD_VERSION.
type BuildVersionTool struct {
	Tool    uint32
	Version uint32
}

// BuildVersion is the platform and SDK record of an image.
type BuildVersion struct {
	// Command is LC_BUILD_VERSION or one of the legacy version-min commands.
	Command uint32
	// Platform is the LC_BUILD_VERSION platform. PlatformAvailable is false for
	// a legacy version-min command, which does not carry one.
	Platform          uint32
	PlatformAvailable bool
	MinimumOS         uint32
	SDK               uint32
	// Tools holds the LC_BUILD_VERSION tool records. It is empty for a legacy
	// version-min command.
	Tools []BuildVersionTool
	// Truncated reports that the tool list stopped at a configured limit or at
	// the command end.
	Truncated bool
	// Limitations states why the record is incomplete.
	Limitations []string
}

// BuildVersion returns LC_BUILD_VERSION when present, otherwise the first
// legacy version-min command.
//
// A missing command returns ErrNotFound.
func (f *File) BuildVersion() (BuildVersion, error) {
	table, err := f.commandTable()
	if err != nil {
		return BuildVersion{}, err
	}
	order := byteOrder(f.Header.Data)
	var legacy *BuildVersion
	for pos := 0; pos+loadCommandSize <= len(table); {
		command := order.Uint32(table[pos:])
		size := int(order.Uint32(table[pos+4:]))
		if size < loadCommandSize || pos+size > len(table) {
			break
		}
		raw := table[pos : pos+size]
		switch command {
		case CommandBuildVersion:
			return f.decodeBuildVersion(raw), nil
		case CommandVersionMinMacOSX, CommandVersionMinIPhoneOS,
			CommandVersionMinTVOS, CommandVersionMinWatchOS:
			if legacy == nil {
				entry := BuildVersion{Command: command, Tools: []BuildVersionTool{}}
				if size < versionMinSize {
					entry.Limitations = append(entry.Limitations,
						fmt.Sprintf("version-min command is %d bytes", size))
				} else {
					entry.MinimumOS = order.Uint32(raw[8:])
					entry.SDK = order.Uint32(raw[12:])
				}
				legacy = &entry
			}
		}
		pos += size
	}
	if legacy != nil {
		return *legacy, nil
	}
	return BuildVersion{}, fmtNotFound("build version command")
}

// EntryPoint is the LC_MAIN record.
type EntryPoint struct {
	// EntryOffset is the file offset of the entry point, not a virtual address.
	EntryOffset uint64
	StackSize   uint64
}

// EntryPoint returns the LC_MAIN record.
//
// A missing command returns ErrNotFound; `LC_UNIXTHREAD` entry points are not
// decoded.
func (f *File) EntryPoint() (EntryPoint, error) {
	table, err := f.commandTable()
	if err != nil {
		return EntryPoint{}, err
	}
	order := byteOrder(f.Header.Data)
	for pos := 0; pos+loadCommandSize <= len(table); {
		command := order.Uint32(table[pos:])
		size := int(order.Uint32(table[pos+4:]))
		if size < loadCommandSize || pos+size > len(table) {
			break
		}
		if command == CommandMain {
			if size < mainCommandSize {
				return EntryPoint{}, fmt.Errorf("%w: main command is %d bytes", ErrInvalid, size)
			}
			return EntryPoint{
				EntryOffset: order.Uint64(table[pos+8:]),
				StackSize:   order.Uint64(table[pos+16:]),
			}, nil
		}
		pos += size
	}
	return EntryPoint{}, fmtNotFound("main command")
}

// Symbol is one decoded nlist or nlist_64 entry.
type Symbol struct {
	// Index is the position in the symbol table.
	Index int
	// StringIndex is the raw n_strx value.
	StringIndex uint32
	// Name is the decoded symbol name. It is empty when NameAvailable is false.
	Name          string
	NameAvailable bool

	Type        uint8
	Section     uint8
	Description uint16
	// Value is a 64-bit field; a 32-bit image widens its value.
	Value uint64
}

// SymbolTable is the decoded LC_SYMTAB tables of one image.
type SymbolTable struct {
	Symbols []Symbol
	// DeclaredCount is the raw nsyms value, next to the loaded symbols.
	DeclaredCount uint32
	// StringBytes is the number of string table bytes actually loaded.
	StringBytes int64
	// Truncated reports that the symbol or string table is a prefix.
	Truncated bool
	// Limitations states, in deterministic order, why the table is incomplete.
	Limitations []string
}

// Symbols returns the symbol table declared by LC_SYMTAB.
//
// A missing command returns ErrNotFound. The symbol and string tables are read
// under the symbol, string table, and per-name limits: an oversized or
// out-of-range table yields the entries that fit, a limitation, and no error. A
// reader failure wraps ErrRead.
func (f *File) Symbols() (SymbolTable, error) {
	table, err := f.commandTable()
	if err != nil {
		return SymbolTable{}, err
	}
	order := byteOrder(f.Header.Data)
	for pos := 0; pos+loadCommandSize <= len(table); {
		command := order.Uint32(table[pos:])
		size := int(order.Uint32(table[pos+4:]))
		if size < loadCommandSize || pos+size > len(table) {
			break
		}
		if command == CommandSymtab {
			if size < symtabCommandSize {
				return SymbolTable{}, fmt.Errorf("%w: symbol table command is %d bytes", ErrInvalid, size)
			}
			raw := table[pos : pos+size]
			return f.decodeSymbols(
				order.Uint32(raw[8:]),
				order.Uint32(raw[12:]),
				order.Uint32(raw[16:]),
				order.Uint32(raw[20:]),
			)
		}
		pos += size
	}
	return SymbolTable{}, fmtNotFound("symbol table command")
}

// CodeSignatureBlob is one index entry of a code signature superblob.
type CodeSignatureBlob struct {
	Index int
	// Type is the raw blob type, for example zero for a code directory.
	Type uint32
	// Offset is relative to the superblob start.
	Offset uint32
	// Magic and Length are the blob header values, zero when the header could
	// not be read.
	Magic  uint32
	Length uint32
}

// CodeSignature is the LC_CODE_SIGNATURE record and its superblob headers.
//
// Only headers are decoded. Signature bytes are not verified, certificates and
// entitlements are not parsed, and presence proves nothing about trust.
type CodeSignature struct {
	// DataOffset and DataSize are the raw command values, relative to the slice.
	DataOffset uint32
	DataSize   uint32

	// Magic, Length, and Count are the superblob header. They are zero when the
	// header is not present.
	Magic  uint32
	Length uint32
	Count  uint32
	Blobs  []CodeSignatureBlob

	// Truncated reports that the blob list or the signature range was cut short.
	Truncated bool
	// Limitations states why the signature view is incomplete.
	Limitations []string
}

// CodeSignature returns the embedded signature headers declared by
// LC_CODE_SIGNATURE.
//
// A missing or empty command returns ErrNotFound. Only superblob and blob
// headers are read; the package never validates a signature, a certificate
// chain, or an entitlement.
func (f *File) CodeSignature() (CodeSignature, error) {
	table, err := f.commandTable()
	if err != nil {
		return CodeSignature{}, err
	}
	order := byteOrder(f.Header.Data)
	for pos := 0; pos+loadCommandSize <= len(table); {
		command := order.Uint32(table[pos:])
		size := int(order.Uint32(table[pos+4:]))
		if size < loadCommandSize || pos+size > len(table) {
			break
		}
		if command == CommandCodeSignature {
			if size < linkEditCommandSize {
				return CodeSignature{}, fmt.Errorf("%w: code signature command is %d bytes", ErrInvalid, size)
			}
			raw := table[pos : pos+size]
			offset := order.Uint32(raw[8:])
			length := order.Uint32(raw[12:])
			if offset == 0 && length == 0 {
				return CodeSignature{}, fmtNotFound("code signature data")
			}
			return f.decodeCodeSignature(offset, length)
		}
		pos += size
	}
	return CodeSignature{}, fmtNotFound("code signature command")
}

// commandTable re-reads the load command table recorded during Parse.
func (f *File) commandTable() ([]byte, error) {
	if f == nil {
		return nil, fmt.Errorf("%w: nil file", ErrInvalid)
	}
	if f.commandBytes <= 0 {
		return []byte{}, nil
	}
	buf := make([]byte, f.commandBytes)
	if err := readAt(f.reader, int64(f.headerSize()), buf, f.size); err != nil {
		return nil, err
	}
	return buf, nil
}

func (f *File) headerSize() int {
	if f.Header.Is64 {
		return header64Size
	}
	return header32Size
}

func (d *DylibTable) note(format string, args ...any) {
	d.Limitations = append(d.Limitations, fmt.Sprintf(format, args...))
}

func (b *BuildVersion) note(format string, args ...any) {
	b.Limitations = append(b.Limitations, fmt.Sprintf(format, args...))
}

func (s *SymbolTable) note(format string, args ...any) {
	s.Limitations = append(s.Limitations, fmt.Sprintf(format, args...))
}

func (c *CodeSignature) note(format string, args ...any) {
	c.Limitations = append(c.Limitations, fmt.Sprintf(format, args...))
}
