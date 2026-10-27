package elf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

const (
	sectionTypeSymtab      = 2
	sectionTypeRela        = 4
	sectionTypeRel         = 9
	sectionTypeDynsym      = 11
	sectionTypeSymtabShndx = 18

	symbolSectionIndexXIndex = 0xffff

	elf32SymbolSize = 16
	elf64SymbolSize = 24
	elf32RelSize    = 8
	elf64RelSize    = 16
	elf32RelaSize   = 12
	elf64RelaSize   = 24
	symbolShndxSize = 4
)

// Symbol is one entry from a SHT_SYMTAB or SHT_DYNSYM section.
type Symbol struct {
	// TableIndex is the section header index of the symbol table.
	TableIndex int
	// Index is the position within that symbol table. Index 0 is the null
	// symbol.
	Index int
	// Name is the resolved symbol name. It is empty when the string table is
	// unavailable or the name is not valid UTF-8, unterminated, or above the
	// name limit; NameOffset still records the raw offset.
	Name string
	// NameOffset is the raw st_name offset into the linked string table.
	NameOffset uint32
	// Info is the raw st_info byte.
	Info uint8
	// Other is the raw st_other byte.
	Other uint8
	// SectionIndex is st_shndx, resolved through a SHT_SYMTAB_SHNDX section
	// when st_shndx is SHN_XINDEX and resolution succeeded.
	SectionIndex uint32
	// ExtendedSectionIndex reports that SectionIndex came from a
	// SHT_SYMTAB_SHNDX section.
	ExtendedSectionIndex bool
	// Value is the raw st_value.
	Value uint64
	// Size is the raw st_size.
	Size uint64
}

// Bind returns the symbol binding from Info.
func (s Symbol) Bind() uint8 { return s.Info >> 4 }

// Type returns the symbol type from Info.
func (s Symbol) Type() uint8 { return s.Info & 0x0f }

// Visibility returns the symbol visibility from Other.
func (s Symbol) Visibility() uint8 { return s.Other & 0x03 }

// SymbolSet is the result of scanning symbol table sections.
//
// Truncated reports that at least one symbol was omitted or was emitted with
// an unavailable name because of a configured limit, malformed or unavailable
// data, or an incomplete section header table. Limitations records the reasons
// in section order.
//
// An empty set with no limitations means the artifact has no SHT_SYMTAB or
// SHT_DYNSYM sections. The null symbol at index 0 of each table is included so
// indexes match the raw tables.
type SymbolSet struct {
	Symbols     []Symbol
	Truncated   bool
	Limitations []string
}

// Symbols scans every loaded SHT_SYMTAB and SHT_DYNSYM section.
//
// Entries are decoded using the artifact byte order and word size. Names are
// resolved through the section's sh_link string table. A table whose entry size
// is wrong, whose range is unavailable, or whose name table cannot be used is
// skipped or emitted with empty names and a limitation rather than failing the
// whole scan. Reader failures stop the scan and return ErrRead together with
// the symbols collected so far.
func (f *File) Symbols() (SymbolSet, error) {
	var set SymbolSet
	if uint64(len(f.SectionHeaders)) < f.Header.SectionHeaderCount {
		set.addLimitation("section header table is incomplete; symbol coverage is partial")
	}

	tables := 0
	stringBudget := f.limits.SymbolStringBytes
	for _, sh := range f.SectionHeaders {
		if sh.Type != sectionTypeSymtab && sh.Type != sectionTypeDynsym {
			continue
		}
		if tables >= f.limits.SymbolTables {
			set.addLimitation(fmt.Sprintf("symbol table count exceeds limit %d", f.limits.SymbolTables))
			break
		}
		tables++
		stop, err := f.scanSymbolTable(sh, &set, &stringBudget)
		if err != nil {
			return set, err
		}
		if stop {
			break
		}
	}
	return set, nil
}

// Relocation is one entry from a relocation section, with or without an
// explicit addend.
type Relocation struct {
	// SectionIndex is the section header index of the relocation section.
	SectionIndex int
	// TargetSectionIndex is the raw sh_info value of the relocation section,
	// which normally names the section the relocations apply to. It is zero
	// for some dynamic relocation sections.
	TargetSectionIndex uint32
	// Index is the position within the relocation section.
	Index int
	// Offset is the raw r_offset. Its meaning depends on the object type.
	Offset uint64
	// Info is the raw r_info value.
	Info uint64
	// SymIndex is the symbol table index encoded in Info.
	SymIndex uint32
	// Type is the relocation type encoded in Info.
	Type uint32
	// Addend is the explicit r_addend when the section stores one, and zero
	// for sections that store the addend at the relocated location.
	Addend int64
	// HasAddend reports that Addend came from the entry. Sections without an
	// explicit addend store it at the relocated location, which this layer
	// does not read.
	HasAddend bool
}

// RelocationSet is the result of scanning relocation sections.
//
// Truncated reports that at least one relocation was omitted because of a
// configured limit, malformed or unavailable data, or an incomplete section
// header table. Limitations records the reasons in section order.
type RelocationSet struct {
	Relocations []Relocation
	Truncated   bool
	Limitations []string
}

// Relocations scans every loaded relocation section, including those with
// and without an explicit addend.
//
// Entries are decoded using the artifact byte order and word size. SHT_REL
// entries have no explicit addend; the stored value at the relocated location
// is not read by this layer. A section whose entry size is wrong or whose
// declared range is unavailable is skipped with a limitation. Reader failures
// stop the scan and return ErrRead together with the relocations collected so
// far.
func (f *File) Relocations() (RelocationSet, error) {
	var set RelocationSet
	if uint64(len(f.SectionHeaders)) < f.Header.SectionHeaderCount {
		set.addLimitation("section header table is incomplete; relocation coverage is partial")
	}

	sections := 0
	for _, sh := range f.SectionHeaders {
		if sh.Type != sectionTypeRel && sh.Type != sectionTypeRela {
			continue
		}
		if sections >= f.limits.RelocationSections {
			set.addLimitation(fmt.Sprintf("relocation section count exceeds limit %d", f.limits.RelocationSections))
			break
		}
		sections++
		stop, err := f.scanRelocationSection(sh, &set)
		if err != nil {
			return set, err
		}
		if stop {
			break
		}
	}
	return set, nil
}

func (f *File) scanSymbolTable(sh SectionHeader, set *SymbolSet, stringBudget *int64) (bool, error) {
	entrySize := f.symbolEntrySize()
	if int(sh.EntrySize) != entrySize {
		set.addLimitation(fmt.Sprintf(
			"symbol table %d entry size %d does not match %d; table skipped",
			sh.Index, sh.EntrySize, entrySize,
		))
		return false, nil
	}

	declared := sh.Size / uint64(entrySize)
	if remainder := sh.Size % uint64(entrySize); remainder != 0 {
		set.addLimitation(fmt.Sprintf(
			"symbol table %d has %d trailing bytes; complete entries only",
			sh.Index, remainder,
		))
	}
	if declared == 0 {
		return false, nil
	}

	effective := declared
	limit := uint64(f.limits.Symbols - len(set.Symbols))
	stop := false
	if effective > limit {
		effective = limit
		stop = true
	}
	available := f.availableBytes(sh.Offset) / uint64(entrySize)
	if effective > available {
		effective = available
		set.addLimitation(fmt.Sprintf(
			"symbol table %d at offset %d exceeds artifact size %d; %d of %d entries available",
			sh.Index, sh.Offset, f.size, effective, declared,
		))
	}
	if stop {
		set.addLimitation(fmt.Sprintf(
			"symbol count exceeds limit %d; %d of %d entries loaded for table %d",
			f.limits.Symbols, effective, declared, sh.Index,
		))
	}

	data, err := f.readPrefix(sh.Offset, effective*uint64(entrySize))
	if err != nil {
		return stop, err
	}
	if uint64(len(data)) < effective*uint64(entrySize) {
		// The reader returned fewer bytes than the declared artifact size
		// allowed; treat it as an unavailable table rather than a short parse.
		set.addLimitation(fmt.Sprintf("symbol table %d data is unavailable", sh.Index))
		effective = uint64(len(data)) / uint64(entrySize)
	}

	names, shndx, nameIssue, err := f.symbolTableContext(sh, effective, stringBudget, set)
	if err != nil {
		return stop, err
	}

	nameFailures := 0
	indexFailures := 0
	for i := range int(effective) {
		sym := decodeSymbol(data[i*entrySize:(i+1)*entrySize], f.Header.Class, byteOrder(f.Header.Data))
		sym.TableIndex = sh.Index
		sym.Index = i

		if names != nil {
			name, ok := symbolNameAt(names, sym.NameOffset, f.limits.NameBytes)
			if ok {
				sym.Name = name
			} else {
				nameFailures++
			}
		} else if nameIssue {
			nameFailures++
		}

		if sym.SectionIndex == symbolSectionIndexXIndex {
			if idx, ok := shndxSectionIndex(shndx, i); ok {
				sym.SectionIndex = idx
				sym.ExtendedSectionIndex = true
			} else {
				indexFailures++
			}
		}
		set.Symbols = append(set.Symbols, sym)
	}
	if nameFailures > 0 {
		set.addLimitation(fmt.Sprintf(
			"symbol table %d: %d symbol names unavailable", sh.Index, nameFailures,
		))
	}
	if indexFailures > 0 {
		set.addLimitation(fmt.Sprintf(
			"symbol table %d: %d extended section indexes unavailable", sh.Index, indexFailures,
		))
	}
	return stop, nil
}

func (f *File) symbolTableContext(sh SectionHeader, entries uint64, stringBudget *int64, set *SymbolSet) ([]byte, []uint32, bool, error) {
	names, ok, err := f.symbolStringTable(sh, stringBudget, set)
	if err != nil {
		return nil, nil, false, err
	}
	var shndx []uint32
	for _, candidate := range f.SectionHeaders {
		if candidate.Type != sectionTypeSymtabShndx || candidate.Link != uint32(sh.Index) {
			continue
		}
		if candidate.EntrySize != symbolShndxSize {
			set.addLimitation(fmt.Sprintf(
				"section index table %d entry size %d does not match %d",
				candidate.Index, candidate.EntrySize, symbolShndxSize,
			))
			break
		}
		want := entries * symbolShndxSize
		if want > candidate.Size {
			want = candidate.Size
		}
		available := f.availableBytes(candidate.Offset)
		if want > available {
			want = available
			set.addLimitation(fmt.Sprintf(
				"section index table %d is incomplete", candidate.Index,
			))
		}
		data, err := f.readPrefix(candidate.Offset, want)
		if err != nil {
			return nil, nil, false, err
		}
		shndx = make([]uint32, len(data)/symbolShndxSize)
		for i := range shndx {
			shndx[i] = byteOrder(f.Header.Data).Uint32(data[i*symbolShndxSize:])
		}
		break
	}
	return names, shndx, !ok, nil
}

func (f *File) symbolStringTable(sh SectionHeader, budget *int64, set *SymbolSet) ([]byte, bool, error) {
	if sh.Link == 0 {
		set.addLimitation(fmt.Sprintf("symbol table %d has no linked string table", sh.Index))
		return nil, false, nil
	}
	if uint64(sh.Link) >= uint64(len(f.SectionHeaders)) {
		set.addLimitation(fmt.Sprintf(
			"symbol table %d string table %d is not loaded", sh.Index, sh.Link,
		))
		return nil, false, nil
	}
	table := f.SectionHeaders[sh.Link]
	if table.Type != sectionTypeStrtab {
		set.addLimitation(fmt.Sprintf(
			"symbol table %d string table %d has type %d", sh.Index, sh.Link, table.Type,
		))
		return nil, false, nil
	}
	if table.Size > uint64(f.limits.StringTableBytes) {
		set.addLimitation(fmt.Sprintf(
			"symbol table %d string table size %d exceeds %d",
			sh.Index, table.Size, f.limits.StringTableBytes,
		))
		return nil, false, nil
	}
	if int64(table.Size) > *budget {
		set.addLimitation(fmt.Sprintf(
			"symbol string table budget %d exhausted at section %d",
			f.limits.SymbolStringBytes, sh.Link,
		))
		return nil, false, nil
	}
	data, err := f.readExactRange(table.Offset, table.Size, uint64(f.limits.StringTableBytes),
		fmt.Sprintf("symbol table %d string table", sh.Index))
	if err != nil {
		if errors.Is(err, ErrRead) {
			return nil, false, err
		}
		set.addLimitation(fmt.Sprintf(
			"symbol table %d string table %d is unavailable", sh.Index, sh.Link,
		))
		return nil, false, nil
	}
	*budget -= int64(table.Size)
	return data, true, nil
}

func (f *File) scanRelocationSection(sh SectionHeader, set *RelocationSet) (bool, error) {
	entrySize := f.relocationEntrySize(sh.Type)
	if int(sh.EntrySize) != entrySize {
		set.addLimitation(fmt.Sprintf(
			"relocation section %d entry size %d does not match %d; section skipped",
			sh.Index, sh.EntrySize, entrySize,
		))
		return false, nil
	}

	declared := sh.Size / uint64(entrySize)
	if remainder := sh.Size % uint64(entrySize); remainder != 0 {
		set.addLimitation(fmt.Sprintf(
			"relocation section %d has %d trailing bytes; complete entries only",
			sh.Index, remainder,
		))
	}
	if declared == 0 {
		return false, nil
	}

	effective := declared
	limit := uint64(f.limits.Relocations - len(set.Relocations))
	stop := false
	if effective > limit {
		effective = limit
		stop = true
	}
	available := f.availableBytes(sh.Offset) / uint64(entrySize)
	if effective > available {
		effective = available
		set.addLimitation(fmt.Sprintf(
			"relocation section %d at offset %d exceeds artifact size %d; %d of %d entries available",
			sh.Index, sh.Offset, f.size, effective, declared,
		))
	}
	if stop {
		set.addLimitation(fmt.Sprintf(
			"relocation count exceeds limit %d; %d of %d entries loaded for section %d",
			f.limits.Relocations, effective, declared, sh.Index,
		))
	}

	data, err := f.readPrefix(sh.Offset, effective*uint64(entrySize))
	if err != nil {
		return stop, err
	}
	if uint64(len(data)) < effective*uint64(entrySize) {
		set.addLimitation(fmt.Sprintf("relocation section %d data is unavailable", sh.Index))
		effective = uint64(len(data)) / uint64(entrySize)
	}

	explicitAddend := sh.Type == sectionTypeRela
	for i := range int(effective) {
		rel := decodeRelocation(data[i*entrySize:(i+1)*entrySize], f.Header.Class, byteOrder(f.Header.Data), explicitAddend)
		rel.SectionIndex = sh.Index
		rel.TargetSectionIndex = sh.Info
		rel.Index = i
		set.Relocations = append(set.Relocations, rel)
	}
	return stop, nil
}

func decodeSymbol(raw []byte, class Class, order binary.ByteOrder) Symbol {
	sym := Symbol{NameOffset: order.Uint32(raw[0:4])}
	if class == Class64 {
		sym.Info = raw[4]
		sym.Other = raw[5]
		sym.SectionIndex = uint32(order.Uint16(raw[6:8]))
		sym.Value = order.Uint64(raw[8:16])
		sym.Size = order.Uint64(raw[16:24])
		return sym
	}
	sym.Value = uint64(order.Uint32(raw[4:8]))
	sym.Size = uint64(order.Uint32(raw[8:12]))
	sym.Info = raw[12]
	sym.Other = raw[13]
	sym.SectionIndex = uint32(order.Uint16(raw[14:16]))
	return sym
}

func decodeRelocation(raw []byte, class Class, order binary.ByteOrder, explicitAddend bool) Relocation {
	var rel Relocation
	if class == Class64 {
		rel.Offset = order.Uint64(raw[0:8])
		rel.Info = order.Uint64(raw[8:16])
		rel.SymIndex = uint32(rel.Info >> 32)
		rel.Type = uint32(rel.Info)
		if explicitAddend {
			rel.Addend = int64(order.Uint64(raw[16:24]))
			rel.HasAddend = true
		}
		return rel
	}
	rel.Offset = uint64(order.Uint32(raw[0:4]))
	rel.Info = uint64(order.Uint32(raw[4:8]))
	rel.SymIndex = uint32(rel.Info >> 8)
	rel.Type = uint32(rel.Info & 0xff)
	if explicitAddend {
		rel.Addend = int64(int32(order.Uint32(raw[8:12])))
		rel.HasAddend = true
	}
	return rel
}

func (f *File) symbolEntrySize() int {
	if f.Header.Class == Class64 {
		return elf64SymbolSize
	}
	return elf32SymbolSize
}

func (f *File) relocationEntrySize(sectionType uint32) int {
	if f.Header.Class == Class64 {
		if sectionType == sectionTypeRela {
			return elf64RelaSize
		}
		return elf64RelSize
	}
	if sectionType == sectionTypeRela {
		return elf32RelaSize
	}
	return elf32RelSize
}

func (f *File) availableBytes(offset uint64) uint64 {
	if offset > uint64(f.size) {
		return 0
	}
	return uint64(f.size) - offset
}

func (f *File) readPrefix(offset, want uint64) ([]byte, error) {
	length := want
	if available := f.availableBytes(offset); length > available {
		length = available
	}
	if length == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, int(length))
	if err := readAt(f.reader, int64(offset), buf, f.size); err != nil {
		return nil, err
	}
	return buf, nil
}

func symbolNameAt(table []byte, offset uint32, maxBytes int) (string, bool) {
	if uint64(offset) >= uint64(len(table)) {
		return "", false
	}
	start := int(offset)
	limit := start + maxBytes + 1
	if limit > len(table) {
		limit = len(table)
	}
	for end := start; end < limit; end++ {
		if table[end] != 0 {
			continue
		}
		name := table[start:end]
		if !utf8.Valid(name) {
			return "", false
		}
		return string(name), true
	}
	return "", false
}

func shndxSectionIndex(table []uint32, index int) (uint32, bool) {
	if index < 0 || index >= len(table) {
		return 0, false
	}
	return table[index], true
}

func (s *SymbolSet) addLimitation(reason string) {
	s.Truncated = true
	appendLimitation(&s.Limitations, reason)
}

func (r *RelocationSet) addLimitation(reason string) {
	r.Truncated = true
	appendLimitation(&r.Limitations, reason)
}
