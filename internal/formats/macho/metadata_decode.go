package macho

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf8"
)

const (
	dylibCommandSize    = 24
	uuidCommandSize     = 24
	versionMinSize      = 16
	buildVersionSize    = 24
	buildVersionTool    = 8
	mainCommandSize     = 24
	symtabCommandSize   = 24
	symbol32Size        = 12
	symbol64Size        = 16
	linkEditCommandSize = 16
	codeSignatureHeader = 12
	codeSignatureIndex  = 8
	blobHeaderSize      = 8
)

// nameStatus reports why a variable-length name inside a load command is or is
// not usable.
type nameStatus int

const (
	nameOK nameStatus = iota
	nameUnavailable
	nameInvalid
	nameTooLong
	nameUnterminated
)

func fmtNotFound(what string) error {
	return fmt.Errorf("%w: %s", ErrNotFound, what)
}

// decodeDylib decodes one dylib command. The caller has checked the command
// size against dylibCommandSize.
func (f *File) decodeDylib(index int, command uint32, raw []byte) (Dylib, nameStatus) {
	order := byteOrder(f.Header.Data)
	out := Dylib{
		Index:                index,
		Command:              command,
		NameOffset:           order.Uint32(raw[8:]),
		Timestamp:            order.Uint32(raw[12:]),
		CurrentVersion:       order.Uint32(raw[16:]),
		CompatibilityVersion: order.Uint32(raw[20:]),
	}
	if out.NameOffset < dylibCommandSize || uint64(out.NameOffset) >= uint64(len(raw)) {
		return out, nameUnavailable
	}
	name := raw[out.NameOffset:]
	if nul := bytes.IndexByte(name, 0); nul >= 0 {
		name = name[:nul]
	} else {
		return out, nameUnterminated
	}
	if len(name) == 0 {
		return out, nameUnavailable
	}
	if len(name) > f.limits.StringBytes {
		return out, nameTooLong
	}
	if !utf8.Valid(name) {
		return out, nameInvalid
	}
	out.Name = string(name)
	out.NameAvailable = true
	return out, nameOK
}

// decodeBuildVersion decodes LC_BUILD_VERSION and its tool records.
func (f *File) decodeBuildVersion(raw []byte) BuildVersion {
	order := byteOrder(f.Header.Data)
	out := BuildVersion{
		Command:           CommandBuildVersion,
		PlatformAvailable: true,
		Tools:             []BuildVersionTool{},
	}
	if len(raw) < buildVersionSize {
		out.note("build version command is %d bytes", len(raw))
		return out
	}
	out.Platform = order.Uint32(raw[8:])
	out.MinimumOS = order.Uint32(raw[12:])
	out.SDK = order.Uint32(raw[16:])

	declared := order.Uint32(raw[20:])
	available := uint64(len(raw)-buildVersionSize) / buildVersionTool
	loaded := uint64(declared)
	if loaded > available {
		out.Truncated = true
		out.note("build version declares %d tools but its command holds %d", declared, available)
		loaded = available
	}
	if loaded > uint64(f.limits.BuildTools) {
		out.Truncated = true
		out.note("build version tool count %d exceeds limit %d", declared, f.limits.BuildTools)
		loaded = uint64(f.limits.BuildTools)
	}
	for i := uint64(0); i < loaded; i++ {
		start := buildVersionSize + int(i)*buildVersionTool
		out.Tools = append(out.Tools, BuildVersionTool{
			Tool:    order.Uint32(raw[start:]),
			Version: order.Uint32(raw[start+4:]),
		})
	}
	return out
}

// decodeSymbols loads the symbol and string tables declared by LC_SYMTAB.
func (f *File) decodeSymbols(symoff, nsyms, stroff, strsize uint32) (SymbolTable, error) {
	order := byteOrder(f.Header.Data)
	out := SymbolTable{Symbols: []Symbol{}, DeclaredCount: nsyms}
	entrySize := uint64(symbol32Size)
	if f.Header.Is64 {
		entrySize = symbol64Size
	}

	loaded := uint64(nsyms)
	switch {
	case nsyms == 0:
		loaded = 0
	case uint64(symoff) >= uint64(f.size):
		out.Truncated = true
		out.note("symbol table offset %d is outside the slice", symoff)
		loaded = 0
	case loaded*entrySize > uint64(f.size)-uint64(symoff):
		available := (uint64(f.size) - uint64(symoff)) / entrySize
		out.Truncated = true
		out.note("symbol table truncated at %d of %d entries", available, nsyms)
		loaded = available
	}
	if loaded > uint64(f.limits.Symbols) {
		out.Truncated = true
		out.note("symbol count %d exceeds limit %d", nsyms, f.limits.Symbols)
		loaded = uint64(f.limits.Symbols)
	}

	stringBytes := uint64(strsize)
	switch {
	case stringBytes == 0:
		stringBytes = 0
	case uint64(stroff) >= uint64(f.size):
		out.Truncated = true
		out.note("symbol string table offset %d is outside the slice", stroff)
		stringBytes = 0
	case stringBytes > uint64(f.size)-uint64(stroff):
		available := uint64(f.size) - uint64(stroff)
		out.Truncated = true
		out.note("symbol string table truncated at %d of %d bytes", available, strsize)
		stringBytes = available
	}
	if stringBytes > uint64(f.limits.SymbolStringBytes) {
		out.Truncated = true
		out.note("symbol string table size %d exceeds limit %d", strsize, f.limits.SymbolStringBytes)
		stringBytes = uint64(f.limits.SymbolStringBytes)
	}
	out.StringBytes = int64(stringBytes)

	if loaded == 0 {
		return out, nil
	}

	symbolData := make([]byte, loaded*entrySize)
	if err := readAt(f.reader, int64(symoff), symbolData, f.size); err != nil {
		return SymbolTable{}, err
	}
	stringData := make([]byte, stringBytes)
	if stringBytes > 0 {
		if err := readAt(f.reader, int64(stroff), stringData, f.size); err != nil {
			return SymbolTable{}, err
		}
	}

	invalidUTF8 := 0
	tooLong := 0
	unterminated := 0
	outsideStrings := 0
	for i := uint64(0); i < loaded; i++ {
		start := i * entrySize
		raw := symbolData[start:]
		symbol := Symbol{
			Index:       int(i),
			StringIndex: order.Uint32(raw[0:]),
			Type:        raw[4],
			Section:     raw[5],
			Description: order.Uint16(raw[6:]),
		}
		if f.Header.Is64 {
			symbol.Value = order.Uint64(raw[8:])
		} else {
			symbol.Value = uint64(order.Uint32(raw[8:]))
		}

		if uint64(symbol.StringIndex) >= uint64(len(stringData)) {
			outsideStrings++
			out.Symbols = append(out.Symbols, symbol)
			continue
		}
		name := stringData[symbol.StringIndex:]
		if nul := bytes.IndexByte(name, 0); nul >= 0 {
			name = name[:nul]
		} else {
			unterminated++
			out.Symbols = append(out.Symbols, symbol)
			continue
		}
		if len(name) == 0 {
			out.Symbols = append(out.Symbols, symbol)
			continue
		}
		if len(name) > f.limits.StringBytes {
			tooLong++
			out.Symbols = append(out.Symbols, symbol)
			continue
		}
		if !utf8.Valid(name) {
			invalidUTF8++
			out.Symbols = append(out.Symbols, symbol)
			continue
		}
		symbol.Name = string(name)
		symbol.NameAvailable = true
		out.Symbols = append(out.Symbols, symbol)
	}

	if invalidUTF8 > 0 {
		out.note("%d symbol names are not valid UTF-8", invalidUTF8)
	}
	if tooLong > 0 {
		out.note("%d symbol names exceed %d bytes", tooLong, f.limits.StringBytes)
	}
	if unterminated > 0 {
		out.note("%d symbol names are not NUL-terminated", unterminated)
	}
	if outsideStrings > 0 {
		out.note("%d symbol string indexes are outside the string table", outsideStrings)
	}
	return out, nil
}

// decodeCodeSignature reads the embedded signature superblob and its index.
//
// Signature structures are big-endian even when the image is little-endian.
func (f *File) decodeCodeSignature(offset, length uint32) (CodeSignature, error) {
	out := CodeSignature{DataOffset: offset, DataSize: length, Blobs: []CodeSignatureBlob{}}
	if uint64(offset) > uint64(f.size) || uint64(length) > uint64(f.size)-uint64(offset) {
		out.Limitations = append(out.Limitations, "code signature range is outside the slice")
		return out, nil
	}
	loaded := uint64(length)
	if loaded > uint64(f.limits.CodeSignBytes) {
		out.Truncated = true
		out.note("code signature data size %d exceeds limit %d", length, f.limits.CodeSignBytes)
		loaded = uint64(f.limits.CodeSignBytes)
	}
	if loaded < codeSignatureHeader {
		out.note("code signature data is %d bytes, smaller than the superblob header", length)
		return out, nil
	}
	data := make([]byte, loaded)
	if err := readAt(f.reader, int64(offset), data, f.size); err != nil {
		return CodeSignature{}, err
	}

	out.Magic = binary.BigEndian.Uint32(data[0:])
	out.Length = binary.BigEndian.Uint32(data[4:])
	out.Count = binary.BigEndian.Uint32(data[8:])
	if out.Magic != CodeSignatureMagic {
		out.note("signature superblob magic %#08x is not %#08x", out.Magic, CodeSignatureMagic)
		return out, nil
	}

	limit := uint64(out.Length)
	if limit < codeSignatureHeader || limit > uint64(len(data)) {
		out.Truncated = true
		out.note("signature superblob length %d is not inside the %d bytes read", out.Length, len(data))
		limit = uint64(len(data))
	}

	count := uint64(out.Count)
	if count > uint64(f.limits.CodeSignBlobs) {
		out.Truncated = true
		out.note("signature blob count %d exceeds limit %d", out.Count, f.limits.CodeSignBlobs)
		count = uint64(f.limits.CodeSignBlobs)
	}
	if available := (limit - codeSignatureHeader) / codeSignatureIndex; count > available {
		out.Truncated = true
		out.note("signature superblob declares %d blobs but holds %d index entries", out.Count, available)
		count = available
	}

	outside := 0
	short := 0
	for i := uint64(0); i < count; i++ {
		start := codeSignatureHeader + i*codeSignatureIndex
		blob := CodeSignatureBlob{
			Index:  int(i),
			Type:   binary.BigEndian.Uint32(data[start:]),
			Offset: binary.BigEndian.Uint32(data[start+4:]),
		}
		end := uint64(blob.Offset) + blobHeaderSize
		if end > limit || end > uint64(len(data)) {
			outside++
			out.Blobs = append(out.Blobs, blob)
			continue
		}
		blob.Magic = binary.BigEndian.Uint32(data[blob.Offset:])
		blob.Length = binary.BigEndian.Uint32(data[blob.Offset+4:])
		if uint64(blob.Length) < blobHeaderSize || uint64(blob.Offset)+uint64(blob.Length) > limit {
			short++
		}
		out.Blobs = append(out.Blobs, blob)
	}
	if outside > 0 {
		out.note("%d signature blobs lie outside the superblob", outside)
	}
	if short > 0 {
		out.note("%d signature blobs declare a length outside the superblob", short)
	}
	return out, nil
}
