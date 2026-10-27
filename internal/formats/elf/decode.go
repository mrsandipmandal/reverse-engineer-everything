package elf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	identSize                 = 16
	elf32HeaderSize           = 52
	elf64HeaderSize           = 64
	elf32SectionHeaderSize    = 40
	elf64SectionHeaderSize    = 64
	elf32ProgramHeaderSize    = 32
	elf64ProgramHeaderSize    = 56
	versionCurrent            = 1
	sectionNameIndexXIndex    = 0xffff
	programHeaderCountXNumber = 0xffff
)

var elfMagic = [4]byte{0x7f, 'E', 'L', 'F'}

type parser struct {
	r      io.ReaderAt
	size   int64
	limits Limits
	class  Class
	data   Data
	order  binary.ByteOrder
	file   *File
	header Header

	rawProgramCount uint16
	rawSectionCount uint16
	rawSectionName  uint16
}

func decodeIdent(ident []byte) (Class, Data, error) {
	if !bytes.Equal(ident[:4], elfMagic[:]) {
		return ClassNone, DataNone, fmt.Errorf("%w: bad ELF magic", ErrInvalid)
	}
	class := Class(ident[4])
	if class != Class32 && class != Class64 {
		return ClassNone, DataNone, fmt.Errorf("%w: unsupported ELF class %d", ErrInvalid, ident[4])
	}
	data := Data(ident[5])
	if data != DataLittle && data != DataBig {
		return ClassNone, DataNone, fmt.Errorf("%w: unsupported ELF data encoding %d", ErrInvalid, ident[5])
	}
	if ident[6] != versionCurrent {
		return ClassNone, DataNone, fmt.Errorf("%w: unsupported ELF identifier version %d", ErrInvalid, ident[6])
	}
	return class, data, nil
}

func byteOrder(data Data) binary.ByteOrder {
	if data == DataBig {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

func (p *parser) decodeHeader(raw []byte) {
	order := p.order
	hdr := Header{
		Class:        p.class,
		Data:         p.data,
		IdentVersion: raw[6],
		OSABI:        raw[7],
		ABIVersion:   raw[8],
	}
	if p.class == Class64 {
		hdr.Type = order.Uint16(raw[16:18])
		hdr.Machine = order.Uint16(raw[18:20])
		hdr.Version = order.Uint32(raw[20:24])
		hdr.Entry = order.Uint64(raw[24:32])
		hdr.ProgramHeaderOffset = order.Uint64(raw[32:40])
		hdr.SectionHeaderOffset = order.Uint64(raw[40:48])
		hdr.Flags = order.Uint32(raw[48:52])
		hdr.HeaderSize = order.Uint16(raw[52:54])
		hdr.ProgramHeaderEntrySize = order.Uint16(raw[54:56])
		hdr.SectionHeaderEntrySize = order.Uint16(raw[58:60])
		p.rawProgramCount = order.Uint16(raw[56:58])
		p.rawSectionCount = order.Uint16(raw[60:62])
		p.rawSectionName = order.Uint16(raw[62:64])
	} else {
		hdr.Type = order.Uint16(raw[16:18])
		hdr.Machine = order.Uint16(raw[18:20])
		hdr.Version = order.Uint32(raw[20:24])
		hdr.Entry = uint64(order.Uint32(raw[24:28]))
		hdr.ProgramHeaderOffset = uint64(order.Uint32(raw[28:32]))
		hdr.SectionHeaderOffset = uint64(order.Uint32(raw[32:36]))
		hdr.Flags = order.Uint32(raw[36:40])
		hdr.HeaderSize = order.Uint16(raw[40:42])
		hdr.ProgramHeaderEntrySize = order.Uint16(raw[42:44])
		p.rawProgramCount = order.Uint16(raw[44:46])
		hdr.SectionHeaderEntrySize = order.Uint16(raw[46:48])
		p.rawSectionCount = order.Uint16(raw[48:50])
		p.rawSectionName = order.Uint16(raw[50:52])
	}
	p.header = hdr
}

func (p *parser) resolve() error {
	hdr := &p.header
	expectedHeaderSize := uint16(elf32HeaderSize)
	expectedSectionSize := uint16(elf32SectionHeaderSize)
	expectedProgramSize := uint16(elf32ProgramHeaderSize)
	if p.class == Class64 {
		expectedHeaderSize = elf64HeaderSize
		expectedSectionSize = elf64SectionHeaderSize
		expectedProgramSize = elf64ProgramHeaderSize
	}
	if hdr.Version != versionCurrent {
		return fmt.Errorf("%w: unsupported ELF version %d", ErrInvalid, hdr.Version)
	}
	if hdr.HeaderSize != expectedHeaderSize {
		return fmt.Errorf("%w: header size %d does not match %s header size %d", ErrInvalid, hdr.HeaderSize, p.class, expectedHeaderSize)
	}
	if p.rawProgramCount != 0 && hdr.ProgramHeaderEntrySize != expectedProgramSize {
		return fmt.Errorf("%w: program header entry size %d does not match %d", ErrInvalid, hdr.ProgramHeaderEntrySize, expectedProgramSize)
	}

	hasSections := hdr.SectionHeaderOffset != 0
	if !hasSections {
		if p.rawSectionCount != 0 || p.rawSectionName != 0 {
			return fmt.Errorf("%w: section metadata is present without a section header table", ErrInvalid)
		}
		if p.rawProgramCount == programHeaderCountXNumber {
			return fmt.Errorf("%w: extended program header count requires a section header table", ErrInvalid)
		}
		hdr.SectionHeaderCount = 0
		hdr.ProgramHeaderCount = uint64(p.rawProgramCount)
		hdr.SectionNameIndex = 0
		if hdr.ProgramHeaderCount > 0 && hdr.ProgramHeaderOffset == 0 {
			return fmt.Errorf("%w: program header count is nonzero without a program header table", ErrInvalid)
		}
		p.file.Header = *hdr
		return nil
	}

	if hdr.SectionHeaderEntrySize != expectedSectionSize {
		return fmt.Errorf("%w: section header entry size %d does not match %d", ErrInvalid, hdr.SectionHeaderEntrySize, expectedSectionSize)
	}

	needsSectionZero := p.rawSectionCount == 0 ||
		p.rawProgramCount == programHeaderCountXNumber ||
		p.rawSectionName == sectionNameIndexXIndex
	var sectionZero SectionHeader
	if needsSectionZero {
		var err error
		sectionZero, err = p.readSectionHeader(0, hdr.SectionHeaderOffset)
		if err != nil {
			return err
		}
	}

	sectionCount := uint64(p.rawSectionCount)
	if p.rawSectionCount == 0 {
		hdr.ExtendedSectionHeaderCount = true
		sectionCount = sectionZero.Size
		if sectionCount == 0 {
			return fmt.Errorf("%w: extended section header count is zero", ErrInvalid)
		}
	}
	hdr.SectionHeaderCount = sectionCount

	if p.rawProgramCount == programHeaderCountXNumber {
		hdr.ExtendedProgramHeaderCount = true
		hdr.ProgramHeaderCount = uint64(sectionZero.Info)
	} else {
		hdr.ProgramHeaderCount = uint64(p.rawProgramCount)
	}
	if hdr.ProgramHeaderCount > 0 {
		if hdr.ProgramHeaderOffset == 0 {
			return fmt.Errorf("%w: program header count is nonzero without a program header table", ErrInvalid)
		}
		if hdr.ProgramHeaderEntrySize != expectedProgramSize {
			return fmt.Errorf("%w: program header entry size %d does not match %d", ErrInvalid, hdr.ProgramHeaderEntrySize, expectedProgramSize)
		}
	}

	if p.rawSectionName == sectionNameIndexXIndex {
		hdr.ExtendedSectionNameIndex = true
		hdr.SectionNameIndex = sectionZero.Link
	} else {
		hdr.SectionNameIndex = uint32(p.rawSectionName)
	}
	if hdr.SectionNameIndex != 0 && uint64(hdr.SectionNameIndex) >= sectionCount {
		return fmt.Errorf("%w: section name table index %d is outside %d section headers", ErrInvalid, hdr.SectionNameIndex, sectionCount)
	}

	p.file.Header = *hdr
	return nil
}

func (p *parser) readSectionHeader(index int, offset uint64) (SectionHeader, error) {
	var buf [elf64SectionHeaderSize]byte
	entrySize := p.sectionHeaderSize()
	if err := p.readAt(offset, buf[:entrySize]); err != nil {
		return SectionHeader{}, err
	}
	return decodeSectionHeader(buf[:entrySize], index, p.class, p.order), nil
}

func (p *parser) loadSectionHeaders() ([]SectionHeader, error) {
	count := p.header.SectionHeaderCount
	if count == 0 {
		return nil, nil
	}
	entrySize := p.sectionHeaderSize()
	effective := count
	limit := uint64(p.limits.SectionHeaders)
	capped := effective > limit
	if capped {
		effective = limit
	}
	available := p.available(p.header.SectionHeaderOffset) / uint64(entrySize)
	short := effective > available
	if short {
		effective = available
	}
	if capped {
		p.noteTruncated(fmt.Sprintf(
			"section header count %d exceeds limit %d; %d entries loaded",
			count, limit, effective,
		))
	}
	if short {
		p.noteTruncated(fmt.Sprintf(
			"section header table at offset %d exceeds artifact size %d; %d of %d entries available",
			p.header.SectionHeaderOffset, p.size, effective, count,
		))
	}
	if effective == 0 {
		return nil, nil
	}
	buf := make([]byte, int(effective)*entrySize)
	if err := p.readAt(p.header.SectionHeaderOffset, buf); err != nil {
		return nil, err
	}
	sections := make([]SectionHeader, 0, int(effective))
	for i := range int(effective) {
		start := i * entrySize
		sections = append(sections, decodeSectionHeader(buf[start:start+entrySize], i, p.class, p.order))
	}
	return sections, nil
}

func (p *parser) loadProgramHeaders() ([]ProgramHeader, error) {
	count := p.header.ProgramHeaderCount
	if count == 0 {
		return nil, nil
	}
	entrySize := p.programHeaderSize()
	effective := count
	limit := uint64(p.limits.ProgramHeaders)
	capped := effective > limit
	if capped {
		effective = limit
	}
	available := p.available(p.header.ProgramHeaderOffset) / uint64(entrySize)
	short := effective > available
	if short {
		effective = available
	}
	if capped {
		p.noteTruncated(fmt.Sprintf(
			"program header count %d exceeds limit %d; %d entries loaded",
			count, limit, effective,
		))
	}
	if short {
		p.noteTruncated(fmt.Sprintf(
			"program header table at offset %d exceeds artifact size %d; %d of %d entries available",
			p.header.ProgramHeaderOffset, p.size, effective, count,
		))
	}
	if effective == 0 {
		return nil, nil
	}
	buf := make([]byte, int(effective)*entrySize)
	if err := p.readAt(p.header.ProgramHeaderOffset, buf); err != nil {
		return nil, err
	}
	programs := make([]ProgramHeader, 0, int(effective))
	for i := range int(effective) {
		start := i * entrySize
		programs = append(programs, decodeProgramHeader(buf[start:start+entrySize], i, p.class, p.order))
	}
	return programs, nil
}

func decodeSectionHeader(raw []byte, index int, class Class, order binary.ByteOrder) SectionHeader {
	sh := SectionHeader{
		Index:      index,
		NameOffset: order.Uint32(raw[0:4]),
		Type:       order.Uint32(raw[4:8]),
	}
	if class == Class64 {
		sh.Flags = order.Uint64(raw[8:16])
		sh.Address = order.Uint64(raw[16:24])
		sh.Offset = order.Uint64(raw[24:32])
		sh.Size = order.Uint64(raw[32:40])
		sh.Link = order.Uint32(raw[40:44])
		sh.Info = order.Uint32(raw[44:48])
		sh.AddressAlign = order.Uint64(raw[48:56])
		sh.EntrySize = order.Uint64(raw[56:64])
	} else {
		sh.Flags = uint64(order.Uint32(raw[8:12]))
		sh.Address = uint64(order.Uint32(raw[12:16]))
		sh.Offset = uint64(order.Uint32(raw[16:20]))
		sh.Size = uint64(order.Uint32(raw[20:24]))
		sh.Link = order.Uint32(raw[24:28])
		sh.Info = order.Uint32(raw[28:32])
		sh.AddressAlign = uint64(order.Uint32(raw[32:36]))
		sh.EntrySize = uint64(order.Uint32(raw[36:40]))
	}
	return sh
}

func decodeProgramHeader(raw []byte, index int, class Class, order binary.ByteOrder) ProgramHeader {
	ph := ProgramHeader{Index: index, Type: order.Uint32(raw[0:4])}
	if class == Class64 {
		ph.Flags = order.Uint32(raw[4:8])
		ph.Offset = order.Uint64(raw[8:16])
		ph.VirtualAddress = order.Uint64(raw[16:24])
		ph.PhysicalAddress = order.Uint64(raw[24:32])
		ph.FileSize = order.Uint64(raw[32:40])
		ph.MemorySize = order.Uint64(raw[40:48])
		ph.Align = order.Uint64(raw[48:56])
	} else {
		ph.Offset = uint64(order.Uint32(raw[4:8]))
		ph.VirtualAddress = uint64(order.Uint32(raw[8:12]))
		ph.PhysicalAddress = uint64(order.Uint32(raw[12:16]))
		ph.FileSize = uint64(order.Uint32(raw[16:20]))
		ph.MemorySize = uint64(order.Uint32(raw[20:24]))
		ph.Flags = order.Uint32(raw[24:28])
		ph.Align = uint64(order.Uint32(raw[28:32]))
	}
	return ph
}

func (p *parser) sectionHeaderSize() int {
	if p.class == Class64 {
		return elf64SectionHeaderSize
	}
	return elf32SectionHeaderSize
}

func (p *parser) programHeaderSize() int {
	if p.class == Class64 {
		return elf64ProgramHeaderSize
	}
	return elf32ProgramHeaderSize
}

func (p *parser) available(offset uint64) uint64 {
	if offset > uint64(p.size) {
		return 0
	}
	return uint64(p.size) - offset
}

func (p *parser) noteTruncated(reason string) {
	p.file.Truncated = true
	p.file.Limitations = append(p.file.Limitations, reason)
}

func (p *parser) readAt(offset uint64, buf []byte) error {
	if offset > uint64(p.size) {
		return fmt.Errorf("%w: %d bytes at offset %d extend beyond artifact size %d", ErrTruncated, len(buf), offset, p.size)
	}
	return readAt(p.r, int64(offset), buf, p.size)
}

func readAt(r io.ReaderAt, offset int64, buf []byte, size int64) error {
	if offset < 0 || offset > size || int64(len(buf)) > size-offset {
		return fmt.Errorf("%w: %d bytes at offset %d extend beyond artifact size %d", ErrTruncated, len(buf), offset, size)
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
