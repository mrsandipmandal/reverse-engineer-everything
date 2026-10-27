package pe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const (
	dosHeaderSize            = 64
	peSignatureSize          = 4
	coffHeaderSize           = 20
	peSignatureOffset        = 0x3c
	pe32FixedSize            = 96
	pe32PlusFixedSize        = 112
	dataDirectorySize        = 8
	sectionHeaderSize        = 40
	sectionNameSize          = 8
	dosMagic          uint16 = 0x5a4d
	peSignature              = "PE\x00\x00"
)

// Parse reads PE headers, data directories, and the section table using the
// default limits.
func Parse(r io.ReaderAt, size int64) (*File, error) {
	return ParseWithLimits(r, size, DefaultLimits())
}

// ParseWithLimits reads PE headers, data directories, and the section table
// using the given limits.
//
// A physical section table truncation or a section count limit produces a
// non-nil File with Truncated set and a nil error. A header that cannot be
// interpreted returns a nil File and an error wrapping ErrInvalid,
// ErrTruncated, or ErrLimit. Reader failures wrap ErrRead.
func ParseWithLimits(r io.ReaderAt, size int64, limits Limits) (*File, error) {
	limits = limits.withDefaults()
	if r == nil {
		return nil, fmt.Errorf("%w: nil reader", ErrInvalid)
	}
	if size < 0 {
		return nil, fmt.Errorf("%w: negative artifact size", ErrInvalid)
	}
	if size > limits.ArtifactBytes {
		return nil, fmt.Errorf("%w: artifact size %d exceeds limit %d", ErrLimit, size, limits.ArtifactBytes)
	}
	if size < dosHeaderSize {
		return nil, fmt.Errorf("%w: artifact size %d is smaller than the DOS header", ErrTruncated, size)
	}

	p := &parser{
		r:      r,
		size:   size,
		limits: limits,
		file:   &File{size: size, reader: r, limits: limits},
	}

	dos := make([]byte, dosHeaderSize)
	if err := p.readAt(0, dos); err != nil {
		return nil, err
	}
	if binary.LittleEndian.Uint16(dos) != dosMagic {
		return nil, fmt.Errorf("%w: DOS signature is not MZ", ErrInvalid)
	}
	header := Header{
		DOSMagic:       dosMagic,
		PEHeaderOffset: binary.LittleEndian.Uint32(dos[peSignatureOffset:]),
	}
	if header.PEHeaderOffset < dosHeaderSize {
		return nil, fmt.Errorf("%w: PE header offset %d overlaps the DOS header",
			ErrInvalid, header.PEHeaderOffset)
	}
	peOffset := uint64(header.PEHeaderOffset)
	if peOffset+peSignatureSize > uint64(size) {
		return nil, fmt.Errorf("%w: PE signature at offset %d extends beyond artifact size %d",
			ErrTruncated, peOffset, size)
	}
	signature := make([]byte, peSignatureSize)
	if err := p.readAt(peOffset, signature); err != nil {
		return nil, err
	}
	if string(signature) != peSignature {
		return nil, fmt.Errorf("%w: PE signature is missing", ErrInvalid)
	}

	coff := make([]byte, coffHeaderSize)
	if err := p.readAt(peOffset+peSignatureSize, coff); err != nil {
		return nil, err
	}
	header.Machine = binary.LittleEndian.Uint16(coff[0:])
	header.NumberOfSections = binary.LittleEndian.Uint16(coff[2:])
	header.TimeDateStamp = binary.LittleEndian.Uint32(coff[4:])
	header.PointerToSymbolTable = binary.LittleEndian.Uint32(coff[8:])
	header.NumberOfSymbols = binary.LittleEndian.Uint32(coff[12:])
	header.SizeOfOptionalHeader = binary.LittleEndian.Uint16(coff[16:])
	header.Characteristics = binary.LittleEndian.Uint16(coff[18:])

	optionalStart := peOffset + peSignatureSize + coffHeaderSize
	optionalSize := uint64(header.SizeOfOptionalHeader)
	if optionalSize < 2 {
		return nil, fmt.Errorf("%w: optional header size %d is too small", ErrInvalid, optionalSize)
	}
	if optionalStart+optionalSize > uint64(size) {
		return nil, fmt.Errorf("%w: optional header at offset %d extends beyond artifact size %d",
			ErrTruncated, optionalStart, size)
	}
	optional := make([]byte, optionalSize)
	if err := p.readAt(optionalStart, optional); err != nil {
		return nil, err
	}

	magic := binary.LittleEndian.Uint16(optional)
	var fixedSize int
	switch magic {
	case MagicPE32:
		fixedSize = pe32FixedSize
	case MagicPE32P:
		fixedSize = pe32PlusFixedSize
	default:
		return nil, fmt.Errorf("%w: unsupported optional header magic %#x", ErrInvalid, magic)
	}
	if optionalSize < uint64(fixedSize) {
		return nil, fmt.Errorf("%w: %s optional header size %d is smaller than %d",
			ErrInvalid, optionalMagicName(magic), optionalSize, fixedSize)
	}
	header.Optional.Magic = magic
	decodeOptional(magic, optional[:fixedSize], &header.Optional)

	p.file.Header = header
	p.loadDataDirectories(optional, fixedSize)
	if err := p.loadSections(optionalStart + optionalSize); err != nil {
		return nil, err
	}
	p.computeOverlay()
	if p.invalidNames > 0 {
		p.limit("%d section names are not valid UTF-8", p.invalidNames)
	}
	return p.file, nil
}

func optionalMagicName(magic uint16) string {
	if magic == MagicPE32 {
		return "PE32"
	}
	return "PE32+"
}

// decodeOptional decodes the fixed part of a PE32 or PE32+ optional header.
// raw is exactly the fixed size for the magic.
func decodeOptional(magic uint16, raw []byte, out *OptionalHeader) {
	order := binary.LittleEndian
	out.Magic = magic
	out.MajorLinkerVersion = raw[2]
	out.MinorLinkerVersion = raw[3]
	out.SizeOfCode = order.Uint32(raw[4:])
	out.SizeOfInitializedData = order.Uint32(raw[8:])
	out.SizeOfUninitializedData = order.Uint32(raw[12:])
	out.AddressOfEntryPoint = order.Uint32(raw[16:])
	out.BaseOfCode = order.Uint32(raw[20:])
	out.SectionAlignment = order.Uint32(raw[32:])
	out.FileAlignment = order.Uint32(raw[36:])
	out.MajorOperatingSystemVersion = order.Uint16(raw[40:])
	out.MinorOperatingSystemVersion = order.Uint16(raw[42:])
	out.MajorImageVersion = order.Uint16(raw[44:])
	out.MinorImageVersion = order.Uint16(raw[46:])
	out.MajorSubsystemVersion = order.Uint16(raw[48:])
	out.MinorSubsystemVersion = order.Uint16(raw[50:])
	out.Win32VersionValue = order.Uint32(raw[52:])
	out.SizeOfImage = order.Uint32(raw[56:])
	out.SizeOfHeaders = order.Uint32(raw[60:])
	out.CheckSum = order.Uint32(raw[64:])
	out.Subsystem = order.Uint16(raw[68:])
	out.DllCharacteristics = order.Uint16(raw[70:])

	if magic == MagicPE32 {
		out.BaseOfData = order.Uint32(raw[24:])
		out.ImageBase = uint64(order.Uint32(raw[28:]))
		out.SizeOfStackReserve = uint64(order.Uint32(raw[72:]))
		out.SizeOfStackCommit = uint64(order.Uint32(raw[76:]))
		out.SizeOfHeapReserve = uint64(order.Uint32(raw[80:]))
		out.SizeOfHeapCommit = uint64(order.Uint32(raw[84:]))
		out.LoaderFlags = order.Uint32(raw[88:])
		out.NumberOfRvaAndSizes = order.Uint32(raw[92:])
		return
	}

	out.ImageBase = order.Uint64(raw[24:])
	out.SizeOfStackReserve = order.Uint64(raw[72:])
	out.SizeOfStackCommit = order.Uint64(raw[80:])
	out.SizeOfHeapReserve = order.Uint64(raw[88:])
	out.SizeOfHeapCommit = order.Uint64(raw[96:])
	out.LoaderFlags = order.Uint32(raw[104:])
	out.NumberOfRvaAndSizes = order.Uint32(raw[108:])
}

func (p *parser) loadDataDirectories(optional []byte, fixedSize int) {
	declared := uint64(p.file.Header.Optional.NumberOfRvaAndSizes)
	available := (len(optional) - fixedSize) / dataDirectorySize

	// Compute the loaded count from the small bounds first so that a declared
	// count near 2^32 cannot overflow int on a 32-bit platform.
	count := MaxDataDirectories
	if p.limits.DataDirectories < count {
		count = p.limits.DataDirectories
	}
	if available < count {
		count = available
	}
	if declared < uint64(count) {
		count = int(declared)
	}

	if declared > MaxDataDirectories {
		p.limit("data directory count %d exceeds the %d supported entries",
			declared, MaxDataDirectories)
	}
	if declared > uint64(available) {
		p.limit("data directory count %d exceeds the %d entries present in the optional header",
			declared, available)
	}
	if declared > uint64(p.limits.DataDirectories) {
		p.limit("data directory count %d exceeds limit %d", declared, p.limits.DataDirectories)
	}

	directories := make([]DataDirectory, 0, count)
	for i := 0; i < count; i++ {
		offset := fixedSize + i*dataDirectorySize
		directories = append(directories, DataDirectory{
			Index:          i,
			VirtualAddress: binary.LittleEndian.Uint32(optional[offset:]),
			Size:           binary.LittleEndian.Uint32(optional[offset+4:]),
		})
	}
	p.file.DataDirectories = directories
}

func (p *parser) loadSections(tableStart uint64) error {
	count := int(p.file.Header.NumberOfSections)
	loaded := count
	if loaded > p.limits.Sections {
		p.truncate("section count %d exceeds limit %d", count, p.limits.Sections)
		loaded = p.limits.Sections
	}

	available := 0
	if tableStart <= uint64(p.size) {
		available = int((uint64(p.size) - tableStart) / sectionHeaderSize)
	}
	if loaded > available {
		p.truncate("section table truncated at %d of %d entries", available, count)
		loaded = available
	}

	sections := make([]SectionHeader, 0, loaded)
	for i := 0; i < loaded; i++ {
		raw := make([]byte, sectionHeaderSize)
		if err := p.readAt(tableStart+uint64(i*sectionHeaderSize), raw); err != nil {
			// The range was bounded above, so a failure here is a reader error.
			p.file.Sections = sections
			return err
		}
		sections = append(sections, p.decodeSection(i, raw))
	}
	p.file.Sections = sections
	return nil
}

func (p *parser) decodeSection(index int, raw []byte) SectionHeader {
	order := binary.LittleEndian
	section := SectionHeader{
		Index:                index,
		VirtualSize:          order.Uint32(raw[8:]),
		VirtualAddress:       order.Uint32(raw[12:]),
		SizeOfRawData:        order.Uint32(raw[16:]),
		PointerToRawData:     order.Uint32(raw[20:]),
		PointerToRelocations: order.Uint32(raw[24:]),
		PointerToLinenumbers: order.Uint32(raw[28:]),
		NumberOfRelocations:  order.Uint16(raw[32:]),
		NumberOfLinenumbers:  order.Uint16(raw[34:]),
		Characteristics:      order.Uint32(raw[36:]),
	}
	copy(section.NameBytes[:], raw[:sectionNameSize])

	name := section.NameBytes[:]
	if nul := bytes.IndexByte(name, 0); nul >= 0 {
		name = name[:nul]
	}
	if len(name) == 0 {
		return section
	}
	if !utf8.Valid(name) {
		p.invalidNames++
		return section
	}
	section.Name = string(name)
	section.NameAvailable = true
	return section
}

func (p *parser) computeOverlay() {
	header := p.file.Header.Optional
	if uint64(header.SizeOfHeaders) > uint64(p.size) {
		p.limit("SizeOfHeaders %d exceeds artifact size %d", header.SizeOfHeaders, p.size)
	}

	end := uint64(header.SizeOfHeaders)
	for _, section := range p.file.Sections {
		if section.SizeOfRawData == 0 {
			continue
		}
		sectionEnd := uint64(section.PointerToRawData) + uint64(section.SizeOfRawData)
		if sectionEnd > uint64(p.size) {
			p.limit("overlay is not reported because section %d raw data extends beyond the artifact",
				section.Index)
			return
		}
		if sectionEnd > end {
			end = sectionEnd
		}
	}
	if end < uint64(p.size) {
		p.file.OverlayOffset = end
		p.file.OverlaySize = uint64(p.size) - end
	}
}

func (p *parser) limit(format string, args ...any) {
	p.file.Limitations = append(p.file.Limitations, fmt.Sprintf(format, args...))
}

func (p *parser) truncate(format string, args ...any) {
	p.file.Truncated = true
	p.limit(format, args...)
}

func (p *parser) readAt(offset uint64, buf []byte) error {
	if offset > uint64(p.size) {
		return fmt.Errorf("%w: %d bytes at offset %d extend beyond artifact size %d",
			ErrTruncated, len(buf), offset, p.size)
	}
	return readAt(p.r, int64(offset), buf, p.size)
}

func readAt(r io.ReaderAt, offset int64, buf []byte, size int64) error {
	if offset < 0 || offset > size || int64(len(buf)) > size-offset {
		return fmt.Errorf("%w: %d bytes at offset %d extend beyond artifact size %d",
			ErrTruncated, len(buf), offset, size)
	}
	n, err := r.ReadAt(buf, offset)
	if n == len(buf) {
		return nil
	}
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: %w", ErrRead, err)
	}
	return fmt.Errorf("%w: short read of %d bytes at offset %d", ErrRead, len(buf)-n, offset)
}

type parser struct {
	r      io.ReaderAt
	size   int64
	limits Limits
	file   *File

	invalidNames int
}
