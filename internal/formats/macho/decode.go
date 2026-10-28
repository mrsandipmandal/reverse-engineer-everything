package macho

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf8"
)

const (
	magicSize       = 4
	header32Size    = 28
	header64Size    = 32
	fatHeaderSize   = 8
	fatEntry32Size  = 20
	fatEntry64Size  = 32
	loadCommandSize = 8
	segment32Size   = 56
	segment64Size   = 72
	section32Size   = 68
	section64Size   = 80
	fixedNameSize   = 16
	commandAlign    = 4
)

// Magics as they appear when the first four bytes are read big-endian. The
// canonical values are in macho.go; these name the opposite byte order.
const (
	swappedMagic32    uint32 = 0xcefaedfe
	swappedMagic64    uint32 = 0xcffaedfe
	swappedFatMagic   uint32 = 0xbebafeca
	swappedFatMagic64 uint32 = 0xbfbafeca
)

func byteOrder(data Data) binary.ByteOrder {
	if data == DataBig {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

func readUint32(raw []byte, data Data) uint32 {
	return byteOrder(data).Uint32(raw[:4])
}

// parseFat loads a universal binary header and every slice it lists.
func parseFat(r io.ReaderAt, size int64, limits Limits, magic uint32) (*Artifact, error) {
	fat64 := magic == FatMagic64 || magic == swappedFatMagic64
	data := DataBig
	if magic == swappedFatMagic || magic == swappedFatMagic64 {
		data = DataLittle
	}
	order := byteOrder(data)

	var header [fatHeaderSize]byte
	if err := readAt(r, 0, header[:], size); err != nil {
		return nil, err
	}
	declared := order.Uint32(header[4:])
	if declared == 0 {
		return nil, fmt.Errorf("%w: fat header declares no slices", ErrInvalid)
	}
	if declared > uint32(limits.FatSlices) {
		return nil, fmt.Errorf("%w: fat slice count %d exceeds limit %d",
			ErrLimit, declared, limits.FatSlices)
	}

	entrySize := uint64(fatEntry32Size)
	if fat64 {
		entrySize = fatEntry64Size
	}
	tableSize := uint64(declared) * entrySize
	if tableSize > uint64(size)-fatHeaderSize {
		return nil, fmt.Errorf("%w: fat architecture table of %d entries extends beyond the artifact",
			ErrTruncated, declared)
	}
	table := make([]byte, tableSize)
	if err := readAt(r, fatHeaderSize, table, size); err != nil {
		return nil, err
	}

	canonical := FatMagic
	if fat64 {
		canonical = FatMagic64
	}
	artifact := &Artifact{
		Magic:  canonical,
		Fat:    true,
		Data:   data,
		Slices: make([]Slice, 0, declared),
		reader: r,
		size:   size,
		limits: limits,
	}

	parsed := 0
	for i := 0; i < int(declared); i++ {
		raw := table[i*int(entrySize):]
		slice := Slice{
			Index:      i,
			CPUType:    order.Uint32(raw[0:]),
			CPUSubtype: order.Uint32(raw[4:]),
		}
		var offset, length uint64
		if fat64 {
			offset = order.Uint64(raw[8:])
			length = order.Uint64(raw[16:])
			slice.Alignment = order.Uint32(raw[24:])
		} else {
			offset = uint64(order.Uint32(raw[8:]))
			length = uint64(order.Uint32(raw[12:]))
			slice.Alignment = order.Uint32(raw[16:])
		}

		if err := validateSliceRange(i, offset, length, size); err != nil {
			slice.Err = err
			artifact.note("slice %d could not be parsed: %v", i, err)
			artifact.Slices = append(artifact.Slices, slice)
			continue
		}
		slice.Offset = int64(offset)
		slice.Size = int64(length)

		file, err := parseImage(r, slice.Offset, slice.Size, limits)
		if err != nil {
			slice.Err = err
			artifact.note("slice %d could not be parsed: %v", i, err)
			artifact.Slices = append(artifact.Slices, slice)
			continue
		}
		slice.File = file
		parsed++
		artifact.Slices = append(artifact.Slices, slice)
	}
	if parsed == 0 {
		return nil, fmt.Errorf("%w: no fat slice could be parsed", ErrInvalid)
	}
	return artifact, nil
}

func (a *Artifact) note(format string, args ...any) {
	a.Limitations = append(a.Limitations, fmt.Sprintf(format, args...))
}

// validateSliceRange checks that a fat entry describes a non-empty range inside
// the artifact without overflowing.
func validateSliceRange(index int, offset, length uint64, size int64) error {
	if length == 0 {
		return fmt.Errorf("%w: slice %d is empty", ErrInvalid, index)
	}
	if offset > uint64(size) || length > uint64(size)-offset {
		return fmt.Errorf("%w: slice %d range %d bytes at offset %d is outside artifact size %d",
			ErrTruncated, index, length, offset, size)
	}
	return nil
}

// parseImage loads one thin Mach-O image at offset inside an artifact of size
// bytes. It is called only for ranges already known to fit.
func parseImage(r io.ReaderAt, offset, size int64, limits Limits) (*File, error) {
	// Every range inside an image is relative to the slice, so reads go through
	// a section reader and cannot escape it.
	image := io.NewSectionReader(r, offset, size)
	if size < magicSize {
		return nil, fmt.Errorf("%w: image size %d is smaller than the Mach-O magic", ErrTruncated, size)
	}
	var magicRaw [magicSize]byte
	if err := readAt(image, 0, magicRaw[:], size); err != nil {
		return nil, err
	}

	var (
		is64 bool
		data Data
	)
	switch magic := binary.BigEndian.Uint32(magicRaw[:]); magic {
	case Magic32:
		data = DataBig
	case swappedMagic32:
		data = DataLittle
	case Magic64:
		is64 = true
		data = DataBig
	case swappedMagic64:
		is64 = true
		data = DataLittle
	default:
		return nil, fmt.Errorf("%w: bad Mach-O magic %#08x", ErrInvalid, magic)
	}
	order := byteOrder(data)

	headerSize := header32Size
	if is64 {
		headerSize = header64Size
	}
	if size < int64(headerSize) {
		return nil, fmt.Errorf("%w: image size %d is smaller than the %d-byte header",
			ErrTruncated, size, headerSize)
	}
	raw := make([]byte, headerSize)
	if err := readAt(image, 0, raw, size); err != nil {
		return nil, err
	}

	file := &File{
		Header: Header{
			Magic:            Magic32,
			Is64:             is64,
			Data:             data,
			CPUType:          order.Uint32(raw[4:]),
			CPUSubtype:       order.Uint32(raw[8:]),
			FileType:         order.Uint32(raw[12:]),
			NumberOfCommands: order.Uint32(raw[16:]),
			SizeOfCommands:   order.Uint32(raw[20:]),
			Flags:            order.Uint32(raw[24:]),
		},
		reader: image,
		size:   size,
		limits: limits,
	}
	if is64 {
		file.Header.Magic = Magic64
		file.Header.Reserved = order.Uint32(raw[28:])
	}

	declaredCommands := uint64(file.Header.NumberOfCommands)
	declaredBytes := uint64(file.Header.SizeOfCommands)
	if declaredCommands*loadCommandSize > declaredBytes {
		return nil, fmt.Errorf("%w: %d load commands need at least %d bytes but SizeOfCommands is %d",
			ErrInvalid, declaredCommands, declaredCommands*loadCommandSize, declaredBytes)
	}

	tableSize := int64(declaredBytes)
	if tableSize > limits.LoadCommandBytes {
		file.truncate("load command table size %d exceeds limit %d", tableSize, limits.LoadCommandBytes)
		tableSize = limits.LoadCommandBytes
	}
	if available := size - int64(headerSize); tableSize > available {
		file.truncate("load command table truncated at %d of %d bytes", available, declaredBytes)
		tableSize = available
	}

	limit := declaredCommands
	if limit > uint64(limits.LoadCommands) {
		file.truncate("load command count %d exceeds limit %d", declaredCommands, limits.LoadCommands)
		limit = uint64(limits.LoadCommands)
	}

	table := make([]byte, tableSize)
	if err := readAt(image, int64(headerSize), table, size); err != nil {
		return nil, err
	}
	file.parseCommands(table, int(limit), int(declaredCommands))

	if file.invalidNames > 0 {
		file.limit("%d segment or section names are not valid UTF-8", file.invalidNames)
	}
	if file.outsideSegments > 0 {
		file.limit("%d segment file ranges extend beyond the slice", file.outsideSegments)
	}
	if file.outsideSections > 0 {
		file.limit("%d section ranges extend beyond the slice", file.outsideSections)
	}
	return file, nil
}

// parseCommands walks the load command table and decodes the segment commands.
//
// A size that contradicts the chain stops the walk with a truncation
// limitation: the commands already loaded remain available.
func (f *File) parseCommands(table []byte, limit, declared int) {
	order := byteOrder(f.Header.Data)
	pos := 0
	for index := 0; index < limit; index++ {
		if pos+loadCommandSize > len(table) {
			f.truncate("load command %d begins beyond the load command table", index)
			return
		}
		command := order.Uint32(table[pos:])
		commandSize := order.Uint32(table[pos+4:])
		switch {
		case commandSize < loadCommandSize:
			f.truncate("load command %d has invalid size %d", index, commandSize)
			return
		case commandSize%commandAlign != 0:
			f.truncate("load command %d size %d is not %d-byte aligned",
				index, commandSize, commandAlign)
			return
		case uint64(pos)+uint64(commandSize) > uint64(len(table)):
			f.truncate("load command %d extends beyond the load command table", index)
			return
		}

		f.Commands = append(f.Commands, LoadCommand{Index: index, Command: command, Size: commandSize})
		f.Header.LoadedCommandCount = len(f.Commands)
		if command == CommandSegment || command == CommandSegment64 {
			f.parseSegment(index, command, table[pos:pos+int(commandSize)])
		}
		pos += int(commandSize)
	}
	if limit == declared && pos != len(table) {
		f.truncate("load command table has %d trailing bytes", len(table)-pos)
	}
}

// parseSegment decodes one segment command and the sections it declares.
func (f *File) parseSegment(commandIndex int, command uint32, raw []byte) {
	order := byteOrder(f.Header.Data)
	segment64 := command == CommandSegment64
	fixed := segment32Size
	sectionSize := section32Size
	if segment64 {
		fixed = segment64Size
		sectionSize = section64Size
	}
	if len(raw) < fixed {
		f.limit("segment command %d is shorter than its fixed header", commandIndex)
		return
	}
	if len(f.Segments) >= f.limits.Segments {
		if !f.segmentStop {
			f.truncate("segment count %d exceeds limit %d", len(f.Segments)+1, f.limits.Segments)
			f.segmentStop = true
		}
		return
	}

	segment := Segment{Index: len(f.Segments), Command: command}
	copy(segment.NameBytes[:], raw[8:8+fixedNameSize])
	segment.Name, segment.NameAvailable = f.decodeName(segment.NameBytes)
	if segment64 {
		segment.VMAddress = order.Uint64(raw[24:])
		segment.VMSize = order.Uint64(raw[32:])
		segment.FileOffset = order.Uint64(raw[40:])
		segment.FileSize = order.Uint64(raw[48:])
		segment.MaxProtection = order.Uint32(raw[56:])
		segment.InitProtection = order.Uint32(raw[60:])
		segment.DeclaredSectionCount = order.Uint32(raw[64:])
		segment.Flags = order.Uint32(raw[68:])
	} else {
		segment.VMAddress = uint64(order.Uint32(raw[24:]))
		segment.VMSize = uint64(order.Uint32(raw[28:]))
		segment.FileOffset = uint64(order.Uint32(raw[32:]))
		segment.FileSize = uint64(order.Uint32(raw[36:]))
		segment.MaxProtection = order.Uint32(raw[40:])
		segment.InitProtection = order.Uint32(raw[44:])
		segment.DeclaredSectionCount = order.Uint32(raw[48:])
		segment.Flags = order.Uint32(raw[52:])
	}

	if segment.FileSize > 0 {
		if segment.FileOffset > uint64(f.size) || segment.FileSize > uint64(f.size)-segment.FileOffset {
			f.outsideSegments++
		}
	}

	segment.FirstSection = len(f.Sections)
	f.Segments = append(f.Segments, segment)
	f.Header.LoadedSegmentCount = len(f.Segments)

	if f.sectionStop {
		return
	}

	declared := segment.DeclaredSectionCount
	if available := uint32((len(raw) - fixed) / sectionSize); declared > available {
		f.truncate("segment %d declares %d sections but its command holds %d",
			segment.Index, declared, available)
		declared = available
	}
	if remaining := f.limits.Sections - len(f.Sections); uint64(declared) > uint64(remaining) {
		f.truncate("section count %d exceeds limit %d",
			len(f.Sections)+int(declared), f.limits.Sections)
		declared = uint32(remaining)
		f.sectionStop = true
	}
	if declared < segment.DeclaredSectionCount {
		f.sectionStop = true
	}

	for i := uint32(0); i < declared; i++ {
		start := fixed + int(i)*sectionSize
		f.Sections = append(f.Sections, f.decodeSection(segment.Index, raw[start:start+sectionSize]))
	}
	f.Segments[segment.Index].SectionCount = int(declared)
	f.Header.LoadedSectionCount = len(f.Sections)
}

func (f *File) decodeSection(segmentIndex int, raw []byte) Section {
	order := byteOrder(f.Header.Data)
	section := Section{
		Index:        len(f.Sections),
		SegmentIndex: segmentIndex,
	}
	copy(section.NameBytes[:], raw[:fixedNameSize])
	section.Name, section.NameAvailable = f.decodeName(section.NameBytes)

	if f.Header.Is64 {
		section.Address = order.Uint64(raw[32:])
		section.Size = order.Uint64(raw[40:])
		section.Offset = order.Uint32(raw[48:])
		section.Alignment = order.Uint32(raw[52:])
		section.RelocationOffset = order.Uint32(raw[56:])
		section.NumberOfRelocations = order.Uint32(raw[60:])
		section.Flags = order.Uint32(raw[64:])
		section.Reserved1 = order.Uint32(raw[68:])
		section.Reserved2 = order.Uint32(raw[72:])
		section.Reserved3 = order.Uint32(raw[76:])
	} else {
		section.Address = uint64(order.Uint32(raw[32:]))
		section.Size = uint64(order.Uint32(raw[36:]))
		section.Offset = order.Uint32(raw[40:])
		section.Alignment = order.Uint32(raw[44:])
		section.RelocationOffset = order.Uint32(raw[48:])
		section.NumberOfRelocations = order.Uint32(raw[52:])
		section.Flags = order.Uint32(raw[56:])
		section.Reserved1 = order.Uint32(raw[60:])
		section.Reserved2 = order.Uint32(raw[64:])
	}

	if section.Size > 0 {
		if uint64(section.Offset) > uint64(f.size) || section.Size > uint64(f.size)-uint64(section.Offset) {
			f.outsideSections++
		}
	}
	return section
}

// decodeName decodes a fixed sixteen-byte name field, truncated at the first
// NUL. A field that is empty or not valid UTF-8 is reported as unavailable
// rather than as an empty name.
func (f *File) decodeName(raw [fixedNameSize]byte) (string, bool) {
	name := raw[:]
	if nul := bytes.IndexByte(name, 0); nul >= 0 {
		name = name[:nul]
	}
	if len(name) == 0 {
		return "", false
	}
	if !utf8.Valid(name) {
		f.invalidNames++
		return "", false
	}
	return string(name), true
}

func (f *File) limit(format string, args ...any) {
	f.Limitations = append(f.Limitations, fmt.Sprintf(format, args...))
}

func (f *File) truncate(format string, args ...any) {
	f.Truncated = true
	f.limit(format, args...)
}
