package macho

import (
	"encoding/binary"
	"testing"
)

// Crafted Mach-O images for the reader tests. Every fixture is generated in
// code: no real binary is committed, and the builders make malformed headers
// easy to express by mutation.

type fixtureSection struct {
	name  string
	addr  uint64
	flags uint32
	data  []byte
}

type fixtureSegment struct {
	name     string
	vmaddr   uint64
	maxprot  uint32
	initprot uint32
	flags    uint32
	sections []fixtureSection
}

type fixtureImage struct {
	is64     bool
	data     Data
	cpuType  uint32
	fileType uint32
	flags    uint32
	segments []fixtureSegment
	// extra holds raw load commands appended after the segments.
	extra [][]byte
	// commands and sizeOfCommands override the computed header values when set.
	commands         *uint32
	sizeOfCommands   *uint32
	trailingCommands int
}

type fixtureFatSlice struct {
	cpuType    uint32
	cpuSubtype uint32
	data       []byte
	align      uint32
}

const (
	fixtureCPUAMD64  uint32 = 0x01000007
	fixtureCPUARM64  uint32 = 0x0100000c
	fixtureCPUI386   uint32 = 0x00000007
	fixtureFileDylib uint32 = 0x6
	fixtureFileExec  uint32 = 0x2
)

func fixtureOrder(data Data) binary.ByteOrder {
	if data == DataBig {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

// buildImage returns a thin Mach-O image. Section data is placed directly after
// the load command table, and each segment records the range of its sections.
func buildImage(t testing.TB, opt fixtureImage) []byte {
	t.Helper()
	if opt.data == DataNone {
		opt.data = DataLittle
	}
	order := fixtureOrder(opt.data)

	headerSize := header32Size
	segmentHeader := segment32Size
	sectionHeader := section32Size
	if opt.is64 {
		headerSize = header64Size
		segmentHeader = segment64Size
		sectionHeader = section64Size
	}

	commandsSize := 0
	for _, segment := range opt.segments {
		commandsSize += segmentHeader + len(segment.sections)*sectionHeader
	}
	for _, extra := range opt.extra {
		commandsSize += len(extra)
	}
	commands := uint32(len(opt.segments) + len(opt.extra))
	if opt.commands != nil {
		commands = *opt.commands
	}
	declaredBytes := uint32(commandsSize)
	if opt.sizeOfCommands != nil {
		declaredBytes = *opt.sizeOfCommands
	}

	payloadOffset := headerSize + commandsSize
	var payload []byte
	sectionOffsets := make([][]uint32, len(opt.segments))
	sectionSizes := make([][]uint64, len(opt.segments))
	for i, segment := range opt.segments {
		sectionOffsets[i] = make([]uint32, len(segment.sections))
		sectionSizes[i] = make([]uint64, len(segment.sections))
		for j, section := range segment.sections {
			if len(section.data) == 0 {
				continue
			}
			sectionOffsets[i][j] = uint32(payloadOffset + len(payload))
			sectionSizes[i][j] = uint64(len(section.data))
			payload = append(payload, section.data...)
		}
	}

	image := make([]byte, payloadOffset+len(payload)+opt.trailingCommands)
	magic := Magic32
	if opt.is64 {
		magic = Magic64
	}
	writeMagic(image, opt.data, magic)
	order.PutUint32(image[4:], opt.cpuType)
	order.PutUint32(image[8:], 3)
	order.PutUint32(image[12:], opt.fileType)
	order.PutUint32(image[16:], commands)
	order.PutUint32(image[20:], declaredBytes)
	order.PutUint32(image[24:], opt.flags)
	if opt.is64 {
		order.PutUint32(image[28:], 0)
	}

	pos := headerSize
	for i, segment := range opt.segments {
		command := CommandSegment
		if opt.is64 {
			command = CommandSegment64
		}
		size := segmentHeader + len(segment.sections)*sectionHeader
		order.PutUint32(image[pos:], command)
		order.PutUint32(image[pos+4:], uint32(size))
		writeFixedName(image[pos+8:], segment.name)

		fileOffset := uint32(0)
		fileSize := uint64(0)
		for _, offset := range sectionOffsets[i] {
			if offset != 0 {
				fileOffset = offset
				break
			}
		}
		for _, size := range sectionSizes[i] {
			fileSize += size
		}

		if opt.is64 {
			order.PutUint64(image[pos+24:], segment.vmaddr)
			order.PutUint64(image[pos+32:], 0x4000)
			order.PutUint64(image[pos+40:], uint64(fileOffset))
			order.PutUint64(image[pos+48:], fileSize)
			order.PutUint32(image[pos+56:], segment.maxprot)
			order.PutUint32(image[pos+60:], segment.initprot)
			order.PutUint32(image[pos+64:], uint32(len(segment.sections)))
			order.PutUint32(image[pos+68:], segment.flags)
		} else {
			order.PutUint32(image[pos+24:], uint32(segment.vmaddr))
			order.PutUint32(image[pos+28:], 0x4000)
			order.PutUint32(image[pos+32:], fileOffset)
			order.PutUint32(image[pos+36:], uint32(fileSize))
			order.PutUint32(image[pos+40:], segment.maxprot)
			order.PutUint32(image[pos+44:], segment.initprot)
			order.PutUint32(image[pos+48:], uint32(len(segment.sections)))
			order.PutUint32(image[pos+52:], segment.flags)
		}
		pos += segmentHeader

		for j, section := range segment.sections {
			sectionStart := pos
			writeFixedName(image[sectionStart:], section.name)
			writeFixedName(image[sectionStart+16:], segment.name)
			if opt.is64 {
				order.PutUint64(image[sectionStart+32:], section.addr)
				order.PutUint64(image[sectionStart+40:], sectionSizes[i][j])
				order.PutUint32(image[sectionStart+48:], sectionOffsets[i][j])
				order.PutUint32(image[sectionStart+64:], section.flags)
			} else {
				order.PutUint32(image[sectionStart+32:], uint32(section.addr))
				order.PutUint32(image[sectionStart+36:], uint32(sectionSizes[i][j]))
				order.PutUint32(image[sectionStart+40:], sectionOffsets[i][j])
				order.PutUint32(image[sectionStart+56:], section.flags)
			}
			pos += sectionHeader
		}
	}
	for _, extra := range opt.extra {
		copy(image[pos:], extra)
		pos += len(extra)
	}
	copy(image[payloadOffset:], payload)
	return image
}

// buildFat returns a universal binary wrapping the given images, each aligned
// as the fat header declares.
func buildFat(t testing.TB, fat64, swapped bool, slices []fixtureFatSlice) []byte {
	t.Helper()
	data := DataBig
	magic := FatMagic
	if fat64 {
		magic = FatMagic64
	}
	if swapped {
		data = DataLittle
	}
	order := fixtureOrder(data)

	entrySize := fatEntry32Size
	if fat64 {
		entrySize = fatEntry64Size
	}
	tableEnd := fatHeaderSize + len(slices)*entrySize
	offsets := make([]int, len(slices))
	total := tableEnd
	for i, slice := range slices {
		align := slice.align
		if align == 0 {
			align = 12
		}
		boundary := 1 << align
		if total%boundary != 0 {
			total += boundary - total%boundary
		}
		offsets[i] = total
		total += len(slice.data)
	}

	artifact := make([]byte, total)
	writeMagic(artifact, data, magic)
	order.PutUint32(artifact[4:], uint32(len(slices)))
	for i, slice := range slices {
		pos := fatHeaderSize + i*entrySize
		order.PutUint32(artifact[pos:], slice.cpuType)
		order.PutUint32(artifact[pos+4:], slice.cpuSubtype)
		align := slice.align
		if align == 0 {
			align = 12
		}
		if fat64 {
			order.PutUint64(artifact[pos+8:], uint64(offsets[i]))
			order.PutUint64(artifact[pos+16:], uint64(len(slice.data)))
			order.PutUint32(artifact[pos+24:], align)
		} else {
			order.PutUint32(artifact[pos+8:], uint32(offsets[i]))
			order.PutUint32(artifact[pos+12:], uint32(len(slice.data)))
			order.PutUint32(artifact[pos+16:], align)
		}
		copy(artifact[offsets[i]:], slice.data)
	}
	return artifact
}

// writeMagic writes a canonical magic in the requested byte order.
func writeMagic(buf []byte, data Data, magic uint32) {
	fixtureOrder(data).PutUint32(buf[:4], magic)
}

// writeFixedName writes a sixteen-byte fixed name field, NUL padded.
func writeFixedName(buf []byte, name string) {
	for i := 0; i < fixedNameSize; i++ {
		buf[i] = 0
	}
	copy(buf[:fixedNameSize], name)
}

func putUint32(t testing.TB, data Data, buf []byte, offset int, value uint32) {
	t.Helper()
	fixtureOrder(data).PutUint32(buf[offset:], value)
}

func putUint64(t testing.TB, data Data, buf []byte, offset int, value uint64) {
	t.Helper()
	fixtureOrder(data).PutUint64(buf[offset:], value)
}

// defaultImage is a 64-bit little-endian image with one text segment holding
// two sections, plus one raw non-segment load command.
func defaultImage() fixtureImage {
	return fixtureImage{
		is64:     true,
		cpuType:  fixtureCPUAMD64,
		fileType: fixtureFileDylib,
		flags:    0x00200085,
		segments: []fixtureSegment{
			{
				name:     "__TEXT",
				vmaddr:   0x100000000,
				maxprot:  0x5,
				initprot: 0x5,
				sections: []fixtureSection{
					{name: "__text", addr: 0x100001000, flags: 0x80000400, data: []byte("text-bytes")},
					{name: "__const", addr: 0x100002000, flags: 0, data: []byte("const-bytes")},
				},
			},
		},
		extra: [][]byte{
			// A load command the reader does not decode: cmd 0x1b, 24 bytes.
			{0x1b, 0x00, 0x00, 0x00, 24, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
	}
}
