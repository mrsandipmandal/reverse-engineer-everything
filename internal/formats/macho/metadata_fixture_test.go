package macho

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Crafted metadata fixtures. Each image is generated in code so a test can
// express a malformed command without committing a binary.

type metadataDylib struct {
	command uint32
	name    string
	// nameOffset overrides the recorded offset when set.
	nameOffset *uint32
}

type metadataSymbol struct {
	name  string
	typ   uint8
	sect  uint8
	desc  uint16
	value uint64
	strx  *uint32
	noNUL bool
}

type metadataSignature struct {
	// blobs are the raw blob bodies without the eight-byte header.
	blobs [][]byte
	// magics overrides the per-blob magic, keyed by blob index.
	magics map[int]uint32
	// magic overrides the superblob magic.
	magic *uint32
	// length overrides the declared superblob length.
	length *uint32
	// offsets overrides the recorded blob offset, keyed by blob index.
	offsets map[int]uint32
	// short records the eight-byte header length of a blob as four, keyed by
	// blob index.
	short map[int]bool
}

type metadataFixture struct {
	is64    bool
	data    Data
	dylibs  []metadataDylib
	uuid    bool
	build   bool
	legacy  bool
	main    bool
	symbols []metadataSymbol
	// strings overrides the generated string table.
	strings []byte
	// symtab overrides symoff, nsyms, stroff, and strsize.
	symtab *[4]uint32
	// signature adds an embedded signature; nil omits the command.
	signature *metadataSignature
	// codeSig overrides the LC_CODE_SIGNATURE offset and size.
	codeSig *[2]uint32
	// extra holds raw commands appended last.
	extra [][]byte
}

func align8(n int) int {
	if n%8 == 0 {
		return n
	}
	return n + 8 - n%8
}

// buildMetadata returns a thin Mach-O image with the requested commands and
// payload. Command sizes are computed first so symbol, string, and signature
// offsets land inside the image.
func buildMetadata(t testing.TB, opt metadataFixture) []byte {
	t.Helper()
	if opt.data == DataNone {
		opt.data = DataLittle
	}
	order := byteOrder(opt.data)
	headerSize := header32Size
	if opt.is64 {
		headerSize = header64Size
	}
	entrySize := symbol32Size
	if opt.is64 {
		entrySize = symbol64Size
	}

	dylibSizes := make([]int, len(opt.dylibs))
	for i, dylib := range opt.dylibs {
		dylibSizes[i] = align8(dylibCommandSize + len(dylib.name) + 1)
	}
	commandSize := 0
	for _, size := range dylibSizes {
		commandSize += size
	}
	if opt.uuid {
		commandSize += uuidCommandSize
	}
	if opt.build {
		commandSize += buildVersionSize + 2*buildVersionTool
	}
	if opt.legacy {
		commandSize += versionMinSize
	}
	if opt.main {
		commandSize += mainCommandSize
	}
	hasSymbols := opt.symtab != nil || len(opt.symbols) > 0 || opt.strings != nil
	if hasSymbols {
		commandSize += symtabCommandSize
	}
	signature := opt.signature
	var signatureData []byte
	if signature != nil {
		signatureData = buildSuperBlob(t, signature)
		commandSize += linkEditCommandSize
	}
	for _, raw := range opt.extra {
		commandSize += len(raw)
	}

	stringTable := opt.strings
	offsets := make([]uint32, len(opt.symbols))
	if stringTable == nil {
		stringTable = []byte{0}
		for i, symbol := range opt.symbols {
			offsets[i] = uint32(len(stringTable))
			stringTable = append(stringTable, symbol.name...)
			if !symbol.noNUL {
				stringTable = append(stringTable, 0)
			}
		}
	}
	symbolData := make([]byte, len(opt.symbols)*entrySize)
	for i, symbol := range opt.symbols {
		raw := symbolData[i*entrySize:]
		strx := offsets[i]
		if symbol.strx != nil {
			strx = *symbol.strx
		}
		order.PutUint32(raw[0:], strx)
		raw[4] = symbol.typ
		raw[5] = symbol.sect
		order.PutUint16(raw[6:], symbol.desc)
		if opt.is64 {
			order.PutUint64(raw[8:], symbol.value)
		} else {
			order.PutUint32(raw[8:], uint32(symbol.value))
		}
	}

	payloadStart := headerSize + commandSize
	symoff := uint32(payloadStart)
	nsyms := uint32(len(opt.symbols))
	stroff := uint32(payloadStart + len(symbolData))
	strsize := uint32(len(stringTable))
	if opt.symtab != nil {
		symoff = opt.symtab[0]
		nsyms = opt.symtab[1]
		stroff = opt.symtab[2]
		strsize = opt.symtab[3]
	}
	csOffset := uint32(0)
	csSize := uint32(0)
	signatureStart := payloadStart + len(symbolData) + len(stringTable)
	if signature != nil {
		csOffset = uint32(signatureStart)
		csSize = uint32(len(signatureData))
	}
	if opt.codeSig != nil {
		csOffset = opt.codeSig[0]
		csSize = opt.codeSig[1]
	}

	image := make([]byte, headerSize+commandSize, headerSize+commandSize+len(symbolData)+len(stringTable)+len(signatureData))
	magic := Magic32
	if opt.is64 {
		magic = Magic64
	}
	writeMagic(image[:magicSize], opt.data, magic)
	order.PutUint32(image[4:], fixtureCPUAMD64)
	order.PutUint32(image[8:], 0x80000003)
	order.PutUint32(image[12:], fixtureFileDylib)
	order.PutUint32(image[16:], uint32(len(opt.dylibs)))
	order.PutUint32(image[20:], uint32(commandSize))
	order.PutUint32(image[24:], 0x00200085)
	// The header's command count is corrected below to include every command.

	pos := headerSize
	commandCount := 0
	command := func(size int) []byte {
		pos += size
		commandCount++
		return image[pos-size : pos]
	}

	for i, dylib := range opt.dylibs {
		raw := command(dylibSizes[i])
		order.PutUint32(raw[0:], dylib.command)
		order.PutUint32(raw[4:], uint32(len(raw)))
		nameOffset := uint32(dylibCommandSize)
		if dylib.nameOffset != nil {
			nameOffset = *dylib.nameOffset
		}
		order.PutUint32(raw[8:], nameOffset)
		order.PutUint32(raw[12:], 1)
		order.PutUint32(raw[16:], 0x00010000)
		order.PutUint32(raw[20:], 0x00010000)
		copy(raw[nameOffset:], dylib.name+"\x00")
	}

	if opt.uuid {
		raw := command(uuidCommandSize)
		order.PutUint32(raw[0:], CommandUUID)
		order.PutUint32(raw[4:], uuidCommandSize)
		for i := 0; i < 16; i++ {
			raw[8+i] = byte(i)
		}
	}

	if opt.build {
		raw := command(buildVersionSize + 2*buildVersionTool)
		order.PutUint32(raw[0:], CommandBuildVersion)
		order.PutUint32(raw[4:], uint32(len(raw)))
		order.PutUint32(raw[8:], 1)
		order.PutUint32(raw[12:], 0x000d0000)
		order.PutUint32(raw[16:], 0x000e0000)
		order.PutUint32(raw[20:], 2)
		order.PutUint32(raw[24:], 1)
		order.PutUint32(raw[28:], 0x000e0000)
		order.PutUint32(raw[32:], 3)
		order.PutUint32(raw[36:], 0x000c0000)
	}

	if opt.legacy {
		raw := command(versionMinSize)
		order.PutUint32(raw[0:], CommandVersionMinMacOSX)
		order.PutUint32(raw[4:], versionMinSize)
		order.PutUint32(raw[8:], 0x000a0f00)
		order.PutUint32(raw[12:], 0x000b0000)
	}

	if opt.main {
		raw := command(mainCommandSize)
		order.PutUint32(raw[0:], CommandMain)
		order.PutUint32(raw[4:], mainCommandSize)
		order.PutUint64(raw[8:], 0x1234)
		order.PutUint64(raw[16:], 0x8000)
	}

	if hasSymbols {
		raw := command(symtabCommandSize)
		order.PutUint32(raw[0:], CommandSymtab)
		order.PutUint32(raw[4:], symtabCommandSize)
		order.PutUint32(raw[8:], symoff)
		order.PutUint32(raw[12:], nsyms)
		order.PutUint32(raw[16:], stroff)
		order.PutUint32(raw[20:], strsize)
	}

	if signature != nil {
		raw := command(linkEditCommandSize)
		order.PutUint32(raw[0:], CommandCodeSignature)
		order.PutUint32(raw[4:], linkEditCommandSize)
		order.PutUint32(raw[8:], csOffset)
		order.PutUint32(raw[12:], csSize)
	}

	for _, extra := range opt.extra {
		raw := command(len(extra))
		copy(raw, extra)
	}

	order.PutUint32(image[16:], uint32(commandCount))
	image = append(image, symbolData...)
	image = append(image, stringTable...)
	image = append(image, signatureData...)
	return image
}

// buildSuperBlob returns an embedded signature superblob whose index points at
// the requested blob bodies.
func buildSuperBlob(t testing.TB, signature *metadataSignature) []byte {
	t.Helper()
	indexSize := codeSignatureHeader + len(signature.blobs)*codeSignatureIndex
	offsets := make([]int, len(signature.blobs))
	total := indexSize
	for i, body := range signature.blobs {
		offsets[i] = total
		total += blobHeaderSize + len(body)
	}
	if total%4 != 0 {
		total += 4 - total%4
	}

	blob := make([]byte, total)
	magic := CodeSignatureMagic
	if signature.magic != nil {
		magic = *signature.magic
	}
	binary.BigEndian.PutUint32(blob[0:], magic)
	length := uint32(total)
	if signature.length != nil {
		length = *signature.length
	}
	binary.BigEndian.PutUint32(blob[4:], length)
	binary.BigEndian.PutUint32(blob[8:], uint32(len(signature.blobs)))
	for i, body := range signature.blobs {
		pos := codeSignatureHeader + i*codeSignatureIndex
		magic := testCodeDirectoryMagic
		if override, ok := signature.magics[i]; ok {
			magic = override
		}
		offset := uint32(offsets[i])
		if override, ok := signature.offsets[i]; ok {
			offset = override
		}
		binary.BigEndian.PutUint32(blob[pos:], magic)
		binary.BigEndian.PutUint32(blob[pos+4:], offset)
		binary.BigEndian.PutUint32(blob[offsets[i]:], magic)
		blobLength := uint32(blobHeaderSize + len(body))
		if signature.short[i] {
			blobLength = 4
		}
		binary.BigEndian.PutUint32(blob[offsets[i]+4:], blobLength)
		copy(blob[offsets[i]+blobHeaderSize:], body)
	}
	return blob
}

const testCodeDirectoryMagic uint32 = 0xfade0c02

func parseMetadata(t testing.TB, data []byte) *File {
	t.Helper()
	artifact, err := Parse(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(artifact.Slices) != 1 || artifact.Slices[0].File == nil {
		t.Fatalf("Parse returned %d slices", len(artifact.Slices))
	}
	return artifact.Slices[0].File
}

func defaultMetadataFixture() metadataFixture {
	return metadataFixture{
		is64: true,
		dylibs: []metadataDylib{
			{command: CommandLoadDylib, name: "/usr/lib/libSystem.B.dylib"},
			{command: CommandDylibID, name: "@rpath/libsample.dylib"},
		},
		uuid:  true,
		build: true,
		main:  true,
		symbols: []metadataSymbol{
			{name: "_main", typ: 0x0f, sect: 1, desc: 0, value: 0x100001000},
			{name: "_helper", typ: 0x0e, sect: 1, desc: 0, value: 0x100002000},
			{name: "_data", typ: 0x0f, sect: 2, desc: 0x0010, value: 0x100003000},
		},
		signature: &metadataSignature{blobs: [][]byte{
			[]byte("code-directory-body"),
			[]byte("requirements-body"),
		}},
	}
}
