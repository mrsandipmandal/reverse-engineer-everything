package macho

import (
	"encoding/binary"
	"testing"
)

// Crafted Mach-O images for the adapter tests. The reader has its own fixtures,
// but they are package-internal, so the adapter builds the small images it
// needs here. Every image is generated in code: no binary is committed.

type fixtureSection struct {
	name  string
	data  []byte
	flags uint32
}

type fixtureExtra struct {
	command uint32
	body    []byte
}

type fixtureImage struct {
	data     remachoData
	is64     bool
	cpuType  uint32
	subtype  uint32
	fileType uint32
	flags    uint32
	segments [][]fixtureSection
	segment  []string
	extras   []fixtureExtra
}

// remachoData mirrors the reader byte-order enum without importing it into the
// fixture signatures, which keeps the builders readable.
type remachoData uint8

const (
	fixtureLittle remachoData = 1
	fixtureBig    remachoData = 2
)

const (
	fixtureMagic32    uint32 = 0xfeedface
	fixtureMagic64    uint32 = 0xfeedfacf
	fixtureCommandSeg uint32 = 0x1
	fixtureCommandS64 uint32 = 0x19
)

const (
	header32Bytes  = 28
	header64Bytes  = 32
	segment32Bytes = 56
	segment64Bytes = 72
	section32Bytes = 68
	section64Bytes = 80
	nameBytes      = 16
	commandHeader  = 8
	commandAlign   = 4
)

func fixtureOrder(data remachoData) binary.ByteOrder {
	if data == fixtureBig {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

func alignCommand(size int) int {
	if size%commandAlign == 0 {
		return size
	}
	return size + commandAlign - size%commandAlign
}

// buildFixture returns one thin image. Section data is appended after the load
// command table, and each segment records the range of its sections.
func buildFixture(t testing.TB, opt fixtureImage) []byte {
	t.Helper()
	if opt.data == 0 {
		opt.data = fixtureLittle
	}
	order := fixtureOrder(opt.data)
	headerSize := header32Bytes
	segmentSize := segment32Bytes
	sectionSize := section32Bytes
	if opt.is64 {
		headerSize = header64Bytes
		segmentSize = segment64Bytes
		sectionSize = section64Bytes
	}

	commandsSize := 0
	for i := range opt.segments {
		commandsSize += segmentSize + len(opt.segments[i])*sectionSize
	}
	for _, extra := range opt.extras {
		commandsSize += alignCommand(commandHeader + len(extra.body))
	}

	payloadStart := headerSize + commandsSize
	type offset struct{ offset, size int }
	sectionLayout := make([][]offset, len(opt.segments))
	payloadLen := 0
	for i := range opt.segments {
		sectionLayout[i] = make([]offset, len(opt.segments[i]))
		for j, section := range opt.segments[i] {
			if len(section.data) == 0 {
				continue
			}
			sectionLayout[i][j] = offset{offset: payloadStart + payloadLen, size: len(section.data)}
			payloadLen += len(section.data)
		}
	}

	image := make([]byte, payloadStart+payloadLen)
	magic := fixtureMagic32
	if opt.is64 {
		magic = fixtureMagic64
	}
	order.PutUint32(image[0:], magic)
	order.PutUint32(image[4:], opt.cpuType)
	order.PutUint32(image[8:], opt.subtype)
	order.PutUint32(image[12:], opt.fileType)
	order.PutUint32(image[16:], uint32(len(opt.segments)+len(opt.extras)))
	order.PutUint32(image[20:], uint32(commandsSize))
	order.PutUint32(image[24:], opt.flags)
	if opt.is64 {
		order.PutUint32(image[28:], 0)
	}

	pos := headerSize
	for i := range opt.segments {
		command := fixtureCommandSeg
		if opt.is64 {
			command = fixtureCommandS64
		}
		size := segmentSize + len(opt.segments[i])*sectionSize
		order.PutUint32(image[pos:], command)
		order.PutUint32(image[pos+4:], uint32(size))
		writeName(image[pos+8:], segmentName(opt, i))

		fileOffset := uint32(0)
		fileSize := uint64(0)
		for _, layout := range sectionLayout[i] {
			if layout.size == 0 {
				continue
			}
			if fileSize == 0 {
				fileOffset = uint32(layout.offset)
			}
			fileSize += uint64(layout.size)
		}
		if opt.is64 {
			order.PutUint64(image[pos+24:], uint64(0x100000000)+uint64(i)*0x4000)
			order.PutUint64(image[pos+32:], 0x4000)
			order.PutUint64(image[pos+40:], uint64(fileOffset))
			order.PutUint64(image[pos+48:], fileSize)
			order.PutUint32(image[pos+56:], 0x7)
			order.PutUint32(image[pos+60:], 0x5)
			order.PutUint32(image[pos+64:], uint32(len(opt.segments[i])))
			order.PutUint32(image[pos+68:], 0)
		} else {
			order.PutUint32(image[pos+24:], uint32(0x1000+i*0x1000))
			order.PutUint32(image[pos+28:], 0x1000)
			order.PutUint32(image[pos+32:], fileOffset)
			order.PutUint32(image[pos+36:], uint32(fileSize))
			order.PutUint32(image[pos+40:], 0x7)
			order.PutUint32(image[pos+44:], 0x5)
			order.PutUint32(image[pos+48:], uint32(len(opt.segments[i])))
			order.PutUint32(image[pos+52:], 0)
		}
		pos += segmentSize

		for j, section := range opt.segments[i] {
			writeName(image[pos:], section.name)
			writeName(image[pos+16:], segmentName(opt, i))
			layout := sectionLayout[i][j]
			if opt.is64 {
				order.PutUint64(image[pos+32:], 0x100000000+uint64(j)*0x100)
				order.PutUint64(image[pos+40:], uint64(layout.size))
				order.PutUint32(image[pos+48:], uint32(layout.offset))
				order.PutUint32(image[pos+52:], 0)
				order.PutUint32(image[pos+64:], section.flags)
			} else {
				order.PutUint32(image[pos+32:], uint32(0x1000+j*0x100))
				order.PutUint32(image[pos+36:], uint32(layout.size))
				order.PutUint32(image[pos+40:], uint32(layout.offset))
				order.PutUint32(image[pos+44:], 0)
				order.PutUint32(image[pos+56:], section.flags)
			}
			pos += sectionSize
		}
	}

	for _, extra := range opt.extras {
		size := alignCommand(commandHeader + len(extra.body))
		order.PutUint32(image[pos:], extra.command)
		order.PutUint32(image[pos+4:], uint32(size))
		copy(image[pos+commandHeader:], extra.body)
		pos += size
	}

	payloadAt := payloadStart
	for i := range opt.segments {
		for j, section := range opt.segments[i] {
			layout := sectionLayout[i][j]
			if layout.size == 0 {
				continue
			}
			copy(image[payloadAt:], section.data)
			payloadAt += len(section.data)
		}
	}
	return image
}

func segmentName(opt fixtureImage, index int) string {
	if index < len(opt.segment) {
		return opt.segment[index]
	}
	return "__TEXT"
}

func writeName(buf []byte, name string) {
	for i := 0; i < nameBytes; i++ {
		buf[i] = 0
	}
	copy(buf[:nameBytes], name)
}

// buildFatFixture wraps images in a 32-bit fat header.
func buildFatFixture(t testing.TB, images [][]byte) []byte {
	t.Helper()
	const entrySize = 20
	tableEnd := 8 + len(images)*entrySize
	offsets := make([]int, len(images))
	total := tableEnd
	for i, image := range images {
		if total%0x1000 != 0 {
			total += 0x1000 - total%0x1000
		}
		offsets[i] = total
		total += len(image)
	}
	fat := make([]byte, total)
	binary.BigEndian.PutUint32(fat[0:], 0xcafebabe)
	binary.BigEndian.PutUint32(fat[4:], uint32(len(images)))
	for i, image := range images {
		pos := 8 + i*entrySize
		binary.BigEndian.PutUint32(fat[pos:], 0x01000007)
		binary.BigEndian.PutUint32(fat[pos+4:], 3)
		binary.BigEndian.PutUint32(fat[pos+8:], uint32(offsets[i]))
		binary.BigEndian.PutUint32(fat[pos+12:], uint32(len(image)))
		binary.BigEndian.PutUint32(fat[pos+16:], 12)
		copy(fat[offsets[i]:], image)
	}
	return fat
}

// defaultFixture is a 64-bit dylib with one segment, two sections with content,
// and no metadata commands.
func defaultFixture() fixtureImage {
	return fixtureImage{
		is64:     true,
		cpuType:  0x01000007,
		subtype:  3,
		fileType: 6,
		flags:    0x00200085,
		segment:  []string{"__TEXT"},
		segments: [][]fixtureSection{{
			{name: "__text", data: []byte("text-bytes"), flags: 0x80000400},
			{name: "__const", data: []byte("const-bytes")},
		}},
	}
}
