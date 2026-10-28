package macho

import (
	"encoding/binary"
	"testing"
)

// Metadata fixture for the adapter tests. It builds one thin Mach-O image with
// the commands the adapter projects: dylibs, UUID, build version, entry point,
// symbols, and an embedded signature superblob.

const (
	dylibCommandSize    = 24
	uuidCommandSize     = 24
	buildVersionSize    = 24
	buildToolSize       = 8
	mainCommandSize     = 24
	symtabSize          = 24
	symbolEntry32       = 12
	symbolEntry64       = 16
	linkEditSize        = 16
	superBlobHeaderSize = 12
	blobIndexSize       = 8
	blobHeaderSize      = 8

	commandSymtab      uint32 = 0x2
	commandLoadDylib   uint32 = 0xc
	commandDylibID     uint32 = 0xd
	commandUUID        uint32 = 0x1b
	commandCodeSign    uint32 = 0x1d
	commandBuild       uint32 = 0x32
	commandMain        uint32 = 0x80000028
	embeddedSignatures uint32 = 0xfade0cc0
	codeDirectoryMagic uint32 = 0xfade0c02
)

type fixtureDylib struct {
	command uint32
	name    string
}

type fixtureSymbol struct {
	name  string
	typ   uint8
	sect  uint8
	desc  uint16
	value uint64
}

type metadataFixture struct {
	is64      bool
	dylibs    []fixtureDylib
	uuid      bool
	build     bool
	legacy    bool
	main      bool
	symbols   []fixtureSymbol
	signature bool
}

func metadataImage(t testing.TB, opt metadataFixture) []byte {
	t.Helper()
	order := binary.LittleEndian
	headerSize := header64Bytes
	entrySize := symbolEntry64
	if !opt.is64 {
		headerSize = header32Bytes
		entrySize = symbolEntry32
	}

	commandSize := 0
	dylibSizes := make([]int, len(opt.dylibs))
	for i, dylib := range opt.dylibs {
		dylibSizes[i] = alignCommand(dylibCommandSize + len(dylib.name) + 1)
		commandSize += dylibSizes[i]
	}
	if opt.uuid {
		commandSize += uuidCommandSize
	}
	if opt.build {
		commandSize += buildVersionSize + 2*buildToolSize
	}
	if opt.legacy {
		commandSize += 16
	}
	if opt.main {
		commandSize += mainCommandSize
	}
	if opt.symbols != nil {
		commandSize += symtabSize
	}
	var signature []byte
	if opt.signature {
		signature = fixtureSuperBlob()
		commandSize += linkEditSize
	}

	stringTable := []byte{0}
	offsets := make([]uint32, len(opt.symbols))
	for i, symbol := range opt.symbols {
		offsets[i] = uint32(len(stringTable))
		stringTable = append(stringTable, symbol.name...)
		stringTable = append(stringTable, 0)
	}
	symbolData := make([]byte, len(opt.symbols)*entrySize)
	for i, symbol := range opt.symbols {
		raw := symbolData[i*entrySize:]
		order.PutUint32(raw[0:], offsets[i])
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
	stroff := uint32(payloadStart + len(symbolData))
	signatureOffset := uint32(payloadStart + len(symbolData) + len(stringTable))

	image := make([]byte, payloadStart+len(symbolData)+len(stringTable)+len(signature))
	order.PutUint32(image[0:], fixtureMagic64)
	if !opt.is64 {
		order.PutUint32(image[0:], fixtureMagic32)
	}
	order.PutUint32(image[4:], 0x01000007)
	order.PutUint32(image[8:], 3)
	order.PutUint32(image[12:], 6)
	order.PutUint32(image[16:], uint32(len(opt.dylibs)+count(opt.uuid)+count(opt.build)+count(opt.legacy)+count(opt.main)+count(opt.symbols != nil)+count(opt.signature)))
	order.PutUint32(image[20:], uint32(commandSize))
	order.PutUint32(image[24:], 0x00200085)

	pos := headerSize
	for i, dylib := range opt.dylibs {
		size := dylibSizes[i]
		order.PutUint32(image[pos:], dylib.command)
		order.PutUint32(image[pos+4:], uint32(size))
		order.PutUint32(image[pos+8:], dylibCommandSize)
		order.PutUint32(image[pos+12:], 1)
		order.PutUint32(image[pos+16:], 0x00010000)
		order.PutUint32(image[pos+20:], 0x00010000)
		copy(image[pos+dylibCommandSize:], dylib.name+"\x00")
		pos += size
	}
	if opt.uuid {
		order.PutUint32(image[pos:], commandUUID)
		order.PutUint32(image[pos+4:], uuidCommandSize)
		for i := 0; i < 16; i++ {
			image[pos+8+i] = byte(i + 1)
		}
		pos += uuidCommandSize
	}
	if opt.build {
		order.PutUint32(image[pos:], commandBuild)
		order.PutUint32(image[pos+4:], buildVersionSize+2*buildToolSize)
		order.PutUint32(image[pos+8:], 1)
		order.PutUint32(image[pos+12:], 0x000d0000)
		order.PutUint32(image[pos+16:], 0x000e0000)
		order.PutUint32(image[pos+20:], 2)
		order.PutUint32(image[pos+24:], 1)
		order.PutUint32(image[pos+28:], 0x000e0000)
		order.PutUint32(image[pos+32:], 3)
		order.PutUint32(image[pos+36:], 0x000c0000)
		pos += buildVersionSize + 2*buildToolSize
	}
	if opt.legacy {
		order.PutUint32(image[pos:], 0x24) // LC_VERSION_MIN_MACOSX
		order.PutUint32(image[pos+4:], 16)
		order.PutUint32(image[pos+8:], 0x000a0f00)
		order.PutUint32(image[pos+12:], 0x000b0000)
		pos += 16
	}
	if opt.main {
		order.PutUint32(image[pos:], commandMain)
		order.PutUint32(image[pos+4:], mainCommandSize)
		order.PutUint64(image[pos+8:], 0x1234)
		order.PutUint64(image[pos+16:], 0x8000)
		pos += mainCommandSize
	}
	if opt.symbols != nil {
		order.PutUint32(image[pos:], commandSymtab)
		order.PutUint32(image[pos+4:], symtabSize)
		order.PutUint32(image[pos+8:], symoff)
		order.PutUint32(image[pos+12:], uint32(len(opt.symbols)))
		order.PutUint32(image[pos+16:], stroff)
		order.PutUint32(image[pos+20:], uint32(len(stringTable)))
		pos += symtabSize
	}
	if opt.signature {
		order.PutUint32(image[pos:], commandCodeSign)
		order.PutUint32(image[pos+4:], linkEditSize)
		order.PutUint32(image[pos+8:], signatureOffset)
		order.PutUint32(image[pos+12:], uint32(len(signature)))
		pos += linkEditSize
	}
	_ = pos
	copy(image[payloadStart:], symbolData)
	copy(image[payloadStart+len(symbolData):], stringTable)
	copy(image[signatureOffset:], signature)
	return image
}

func count(enabled bool) int {
	if enabled {
		return 1
	}
	return 0
}

// fixtureSuperBlob returns an embedded signature with two blob headers.
func fixtureSuperBlob() []byte {
	bodies := [][]byte{[]byte("code-directory"), []byte("requirements")}
	indexSize := superBlobHeaderSize + len(bodies)*blobIndexSize
	offsets := make([]int, len(bodies))
	total := indexSize
	for i, body := range bodies {
		offsets[i] = total
		total += blobHeaderSize + len(body)
	}
	blob := make([]byte, total)
	binary.BigEndian.PutUint32(blob[0:], embeddedSignatures)
	binary.BigEndian.PutUint32(blob[4:], uint32(total))
	binary.BigEndian.PutUint32(blob[8:], uint32(len(bodies)))
	for i, body := range bodies {
		pos := superBlobHeaderSize + i*blobIndexSize
		binary.BigEndian.PutUint32(blob[pos:], codeDirectoryMagic)
		binary.BigEndian.PutUint32(blob[pos+4:], uint32(offsets[i]))
		binary.BigEndian.PutUint32(blob[offsets[i]:], codeDirectoryMagic)
		binary.BigEndian.PutUint32(blob[offsets[i]+4:], uint32(blobHeaderSize+len(body)))
		copy(blob[offsets[i]+blobHeaderSize:], body)
	}
	return blob
}

// defaultMetadataFixture carries every command the adapter projects.
func defaultMetadataFixture() metadataFixture {
	return metadataFixture{
		is64: true,
		dylibs: []fixtureDylib{
			{command: commandLoadDylib, name: "/usr/lib/libSystem.B.dylib"},
			{command: commandDylibID, name: "@rpath/libsample.dylib"},
		},
		uuid:      true,
		build:     true,
		main:      true,
		signature: true,
		symbols: []fixtureSymbol{
			{name: "_main", typ: 0x0f, sect: 1, value: 0x100001000},
			{name: "_helper", typ: 0x0e, sect: 1, value: 0x100002000},
		},
	}
}
