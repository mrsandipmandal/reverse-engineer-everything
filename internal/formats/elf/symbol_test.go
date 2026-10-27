package elf_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	reeelf "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/elf"
)

const (
	textSectionIndex        = 2
	dataSectionIndex        = 3
	strtabSectionIndex      = 4
	symtabSectionIndex      = 5
	dynsymSectionIndex      = 6
	relaSectionIndex        = 7
	relSectionIndex         = 8
	symtabShndxSectionIndex = 9
)

var (
	symbolSectionNames = []byte("\x00.shstrtab\x00.text\x00.data\x00.strtab\x00.symtab\x00.dynsym\x00.rela.text\x00.rel.data\x00.symtab_shndx\x00")
	symbolNames        = []byte("\x00local_fn\x00global_data\x00weak_ref\x00xindex_fn\x00dyn_import\x00dyn_export\x00")
)

type symbolFixture struct {
	fixture

	strtabOffset int
	textOffset   int
	dataOffset   int
	symtabOffset int
	dynsymOffset int
	relaOffset   int
	relOffset    int
	shndxOffset  int
	symbolSize   int
	relaSize     int
	relSize      int
}

func buildSymbolFixture(class reeelf.Class, data reeelf.Data) symbolFixture {
	f := symbolFixture{fixture: fixture{class: class, order: binary.LittleEndian}}
	if data == reeelf.DataBig {
		f.order = binary.BigEndian
	}
	switch class {
	case reeelf.Class64:
		f.headerSize = 64
		f.sectionSize = 64
		f.symbolSize = 24
		f.relaSize = 24
		f.relSize = 16
	case reeelf.Class32:
		f.headerSize = 52
		f.sectionSize = 40
		f.symbolSize = 16
		f.relaSize = 12
		f.relSize = 8
	default:
		panic("unsupported fixture class")
	}
	f.programSize = 0
	f.programStart = f.headerSize
	f.sectionStart = f.headerSize

	const sectionCount = 10
	tableEnd := f.sectionStart + sectionCount*f.sectionSize
	cursor := alignUp(tableEnd, 8)
	f.nameTableOffset = cursor
	cursor = alignUp(cursor+len(symbolSectionNames), 8)
	f.strtabOffset = cursor
	cursor = alignUp(cursor+len(symbolNames), 8)
	f.textOffset = cursor
	cursor += 8
	f.dataOffset = cursor
	cursor += 8
	f.symtabOffset = cursor
	cursor += 5 * f.symbolSize
	cursor = alignUp(cursor, 8)
	f.dynsymOffset = cursor
	cursor += 3 * f.symbolSize
	cursor = alignUp(cursor, 8)
	f.relaOffset = cursor
	cursor += 2 * f.relaSize
	f.relOffset = cursor
	cursor += f.relSize
	cursor = alignUp(cursor, 8)
	f.shndxOffset = cursor
	cursor += 5 * 4
	f.data = make([]byte, alignUp(cursor, 8))

	buf := f.data
	copy(buf[0:4], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = byte(class)
	buf[5] = byte(data)
	buf[6] = 1

	machine := uint16(62)
	base := uint64(0x400000)
	if class == reeelf.Class32 {
		machine = 3
		base = 0x8048000
	}
	f.put16(16, 1) // ET_REL
	f.put16(18, machine)
	f.put32(20, 1)
	if class == reeelf.Class64 {
		f.put64(40, uint64(f.sectionStart))
	} else {
		f.put32(32, uint32(f.sectionStart))
	}
	f.put16(f.headerSizeOffset(), uint16(f.headerSize))
	f.put16(f.programEntrySizeOffset(), 0)
	f.put16(f.programCountOffset(), 0)
	f.put16(f.sectionEntrySizeOffset(), uint16(f.sectionSize))
	f.put16(f.sectionCountOffset(), sectionCount)
	f.put16(f.sectionNameIndexOffset(), 1)

	f.writeSection(1, symbolSectionName(".shstrtab"), 3, 0, 0, uint64(f.nameTableOffset), uint64(len(symbolSectionNames)), 0, 0, 1, 0)
	f.writeSection(textSectionIndex, symbolSectionName(".text"), 1, 6, base+0x1000, uint64(f.textOffset), 8, 0, 0, 8, 0)
	f.writeSection(dataSectionIndex, symbolSectionName(".data"), 1, 3, base+0x2000, uint64(f.dataOffset), 8, 0, 0, 8, 0)
	f.writeSection(strtabSectionIndex, symbolSectionName(".strtab"), 3, 0, 0, uint64(f.strtabOffset), uint64(len(symbolNames)), 0, 0, 1, 0)
	f.writeSection(symtabSectionIndex, symbolSectionName(".symtab"), 2, 0, 0, uint64(f.symtabOffset), uint64(5*f.symbolSize), strtabSectionIndex, 2, 8, uint64(f.symbolSize))
	f.writeSection(dynsymSectionIndex, symbolSectionName(".dynsym"), 11, 0, 0, uint64(f.dynsymOffset), uint64(3*f.symbolSize), strtabSectionIndex, 1, 8, uint64(f.symbolSize))
	f.writeSection(relaSectionIndex, symbolSectionName(".rela.text"), 4, 0, 0, uint64(f.relaOffset), uint64(2*f.relaSize), symtabSectionIndex, textSectionIndex, 8, uint64(f.relaSize))
	f.writeSection(relSectionIndex, symbolSectionName(".rel.data"), 9, 0, 0, uint64(f.relOffset), uint64(f.relSize), symtabSectionIndex, dataSectionIndex, 8, uint64(f.relSize))
	f.writeSection(symtabShndxSectionIndex, symbolSectionName(".symtab_shndx"), 18, 0, 0, uint64(f.shndxOffset), 5*4, symtabSectionIndex, 0, 4, 4)

	copy(buf[f.nameTableOffset:], symbolSectionNames)
	copy(buf[f.strtabOffset:], symbolNames)
	copy(buf[f.textOffset:], []byte{0x90, 0x90, 0x90, 0x90, 0xc3, 0xcc, 0xcc, 0xcc})
	copy(buf[f.dataOffset:], []byte{1, 2, 3, 4, 5, 6, 7, 8})

	f.writeSymbol(f.symtabOffset+0*f.symbolSize, 0, 0, 0, 0, 0, 0)
	f.writeSymbol(f.symtabOffset+1*f.symbolSize, symbolNameOffset("local_fn"), base+0x1000, 4, 0x02, 0, textSectionIndex)
	f.writeSymbol(f.symtabOffset+2*f.symbolSize, symbolNameOffset("global_data"), base+0x2000, 8, 0x11, 2, dataSectionIndex)
	f.writeSymbol(f.symtabOffset+3*f.symbolSize, symbolNameOffset("weak_ref"), 0, 0, 0x20, 0, 0)
	f.writeSymbol(f.symtabOffset+4*f.symbolSize, symbolNameOffset("xindex_fn"), base+0x1004, 4, 0x12, 0, 0xffff)

	f.writeSymbol(f.dynsymOffset+0*f.symbolSize, 0, 0, 0, 0, 0, 0)
	f.writeSymbol(f.dynsymOffset+1*f.symbolSize, symbolNameOffset("dyn_import"), 0, 0, 0x12, 0, 0)
	f.writeSymbol(f.dynsymOffset+2*f.symbolSize, symbolNameOffset("dyn_export"), base+0x1000, 4, 0x11, 0, textSectionIndex)

	f.writeRela(f.relaOffset+0*f.relaSize, base+0x1000, 2, 1, 42)
	f.writeRela(f.relaOffset+1*f.relaSize, base+0x1004, 3, 2, -8)
	f.writeRel(f.relOffset, base+0x2000, 2, 1)

	shndx := []uint32{0, 0, 0, 0, textSectionIndex}
	for i, value := range shndx {
		f.order.PutUint32(buf[f.shndxOffset+i*4:], value)
	}
	return f
}

func (f *symbolFixture) writeSymbol(offset int, name uint32, value, size uint64, info, other uint8, shndx uint16) {
	buf := f.data
	f.order.PutUint32(buf[offset:offset+4], name)
	if f.class == reeelf.Class64 {
		buf[offset+4] = info
		buf[offset+5] = other
		f.order.PutUint16(buf[offset+6:offset+8], shndx)
		f.order.PutUint64(buf[offset+8:offset+16], value)
		f.order.PutUint64(buf[offset+16:offset+24], size)
		return
	}
	f.order.PutUint32(buf[offset+4:offset+8], uint32(value))
	f.order.PutUint32(buf[offset+8:offset+12], uint32(size))
	buf[offset+12] = info
	buf[offset+13] = other
	f.order.PutUint16(buf[offset+14:offset+16], shndx)
}

func (f *symbolFixture) writeRela(offset int, rOffset uint64, sym uint32, typ uint32, addend int64) {
	buf := f.data
	if f.class == reeelf.Class64 {
		f.order.PutUint64(buf[offset:offset+8], rOffset)
		f.order.PutUint64(buf[offset+8:offset+16], uint64(sym)<<32|uint64(typ))
		f.order.PutUint64(buf[offset+16:offset+24], uint64(addend))
		return
	}
	f.order.PutUint32(buf[offset:offset+4], uint32(rOffset))
	f.order.PutUint32(buf[offset+4:offset+8], sym<<8|typ)
	f.order.PutUint32(buf[offset+8:offset+12], uint32(int32(addend)))
}

func (f *symbolFixture) writeRel(offset int, rOffset uint64, sym uint32, typ uint32) {
	buf := f.data
	if f.class == reeelf.Class64 {
		f.order.PutUint64(buf[offset:offset+8], rOffset)
		f.order.PutUint64(buf[offset+8:offset+16], uint64(sym)<<32|uint64(typ))
		return
	}
	f.order.PutUint32(buf[offset:offset+4], uint32(rOffset))
	f.order.PutUint32(buf[offset+4:offset+8], sym<<8|typ)
}

func symbolSectionName(name string) uint32 {
	return uint32(bytes.Index(symbolSectionNames, []byte(name)))
}

func symbolNameOffset(name string) uint32 {
	return uint32(bytes.Index(symbolNames, []byte(name)))
}

func parseSymbolFixture(t *testing.T, f symbolFixture, limits reeelf.Limits) *reeelf.File {
	t.Helper()
	got, err := reeelf.ParseWithLimits(bytes.NewReader(f.data), int64(len(f.data)), limits)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return got
}

func TestSymbols(t *testing.T) {
	t.Parallel()

	for _, class := range []reeelf.Class{reeelf.Class32, reeelf.Class64} {
		for _, data := range []reeelf.Data{reeelf.DataLittle, reeelf.DataBig} {
			t.Run(class.String()+"/"+data.String(), func(t *testing.T) {
				t.Parallel()

				f := buildSymbolFixture(class, data)
				got := parseSymbolFixture(t, f, reeelf.DefaultLimits())
				set, err := got.Symbols()
				if err != nil {
					t.Fatalf("Symbols() error = %v", err)
				}
				if set.Truncated || len(set.Limitations) != 0 {
					t.Fatalf("Symbols() truncation = %t, limitations = %v", set.Truncated, set.Limitations)
				}
				if len(set.Symbols) != 8 {
					t.Fatalf("Symbols() count = %d, want 8", len(set.Symbols))
				}

				base := uint64(0x400000)
				if class == reeelf.Class32 {
					base = 0x8048000
				}
				tests := []struct {
					index      int
					table      int
					name       string
					nameOffset uint32
					value      uint64
					size       uint64
					info       uint8
					other      uint8
					section    uint32
					extended   bool
				}{
					{index: 0, table: symtabSectionIndex, name: ""},
					{index: 1, table: symtabSectionIndex, name: "local_fn", nameOffset: symbolNameOffset("local_fn"), value: base + 0x1000, size: 4, info: 0x02, section: textSectionIndex},
					{index: 2, table: symtabSectionIndex, name: "global_data", nameOffset: symbolNameOffset("global_data"), value: base + 0x2000, size: 8, info: 0x11, other: 2, section: dataSectionIndex},
					{index: 3, table: symtabSectionIndex, name: "weak_ref", nameOffset: symbolNameOffset("weak_ref"), info: 0x20},
					{index: 4, table: symtabSectionIndex, name: "xindex_fn", nameOffset: symbolNameOffset("xindex_fn"), value: base + 0x1004, size: 4, info: 0x12, section: textSectionIndex, extended: true},
					{index: 5, table: dynsymSectionIndex, name: ""},
					{index: 6, table: dynsymSectionIndex, name: "dyn_import", nameOffset: symbolNameOffset("dyn_import"), info: 0x12},
					{index: 7, table: dynsymSectionIndex, name: "dyn_export", nameOffset: symbolNameOffset("dyn_export"), value: base + 0x1000, size: 4, info: 0x11, section: textSectionIndex},
				}
				for _, tt := range tests {
					sym := set.Symbols[tt.index]
					if sym.TableIndex != tt.table {
						t.Fatalf("symbol %d table = %d, want %d", tt.index, sym.TableIndex, tt.table)
					}
					if sym.Index != tt.index && tt.table == symtabSectionIndex {
						t.Fatalf("symbol %d index = %d", tt.index, sym.Index)
					}
					if sym.Name != tt.name {
						t.Fatalf("symbol %d name = %q, want %q", tt.index, sym.Name, tt.name)
					}
					if sym.NameOffset != tt.nameOffset {
						t.Fatalf("symbol %d name offset = %d, want %d", tt.index, sym.NameOffset, tt.nameOffset)
					}
					if sym.Value != tt.value || sym.Size != tt.size {
						t.Fatalf("symbol %d value/size = %#x/%d, want %#x/%d", tt.index, sym.Value, sym.Size, tt.value, tt.size)
					}
					if sym.Info != tt.info || sym.Other != tt.other {
						t.Fatalf("symbol %d info/other = %#x/%#x, want %#x/%#x", tt.index, sym.Info, sym.Other, tt.info, tt.other)
					}
					if sym.SectionIndex != tt.section {
						t.Fatalf("symbol %d section = %d, want %d", tt.index, sym.SectionIndex, tt.section)
					}
					if sym.ExtendedSectionIndex != tt.extended {
						t.Fatalf("symbol %d extended section = %t, want %t", tt.index, sym.ExtendedSectionIndex, tt.extended)
					}
				}

				if got := set.Symbols[1]; got.Bind() != 0 || got.Type() != 2 || got.Visibility() != 0 {
					t.Fatalf("local_fn bind/type/visibility = %d/%d/%d", got.Bind(), got.Type(), got.Visibility())
				}
				if got := set.Symbols[2]; got.Bind() != 1 || got.Type() != 1 || got.Visibility() != 2 {
					t.Fatalf("global_data bind/type/visibility = %d/%d/%d", got.Bind(), got.Type(), got.Visibility())
				}
				if got := set.Symbols[3]; got.Bind() != 2 || got.Type() != 0 {
					t.Fatalf("weak_ref bind/type = %d/%d", got.Bind(), got.Type())
				}
				if got := set.Symbols[7]; got.Index != 2 || got.TableIndex != dynsymSectionIndex {
					t.Fatalf("dyn_export table/index = %d/%d", got.TableIndex, got.Index)
				}
			})
		}
	}
}

func TestSymbolsNameErrors(t *testing.T) {
	t.Parallel()

	t.Run("no string table", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		f.put32(f.sectionFieldOffset(symtabSectionIndex, 40), 0)
		got := parseSymbolFixture(t, f, reeelf.DefaultLimits())
		set, err := got.Symbols()
		if err != nil {
			t.Fatalf("Symbols() error = %v", err)
		}
		if !set.Truncated || len(set.Symbols) != 8 {
			t.Fatalf("truncation = %t, symbols = %d", set.Truncated, len(set.Symbols))
		}
		for _, sym := range set.Symbols {
			if sym.TableIndex == symtabSectionIndex && sym.Name != "" {
				t.Fatalf("symbol %d name = %q, want empty", sym.Index, sym.Name)
			}
		}
		if len(set.Limitations) == 0 || !strings.Contains(set.Limitations[0], "no linked string table") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})

	t.Run("wrong string table type", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		f.put32(f.sectionFieldOffset(strtabSectionIndex, 4), 1)
		got := parseSymbolFixture(t, f, reeelf.DefaultLimits())
		set, err := got.Symbols()
		if err != nil {
			t.Fatalf("Symbols() error = %v", err)
		}
		if !set.Truncated || len(set.Limitations) == 0 || !strings.Contains(set.Limitations[0], "has type") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})

	t.Run("string table not loaded", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		f.put32(f.sectionFieldOffset(symtabSectionIndex, 40), 500)
		got := parseSymbolFixture(t, f, reeelf.DefaultLimits())
		set, err := got.Symbols()
		if err != nil {
			t.Fatalf("Symbols() error = %v", err)
		}
		if !set.Truncated || len(set.Limitations) == 0 || !strings.Contains(set.Limitations[0], "not loaded") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})

	t.Run("name above limit", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		limits := reeelf.DefaultLimits()
		limits.NameBytes = 4
		got := parseSymbolFixture(t, f, limits)
		set, err := got.Symbols()
		if err != nil {
			t.Fatalf("Symbols() error = %v", err)
		}
		if !set.Truncated || len(set.Symbols) != 8 {
			t.Fatalf("truncation = %t, symbols = %d", set.Truncated, len(set.Symbols))
		}
		if set.Symbols[1].Name != "" {
			t.Fatalf("symbol 1 name = %q, want empty", set.Symbols[1].Name)
		}
		if set.Symbols[3].Name != "" {
			t.Fatalf("symbol 3 name = %q, want empty", set.Symbols[3].Name)
		}
		if !hasLimitation(set.Limitations, "symbol names unavailable") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})

	t.Run("invalid UTF-8", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		f.data[f.strtabOffset+int(symbolNameOffset("local_fn"))] = 0xff
		got := parseSymbolFixture(t, f, reeelf.DefaultLimits())
		set, err := got.Symbols()
		if err != nil {
			t.Fatalf("Symbols() error = %v", err)
		}
		if !set.Truncated || set.Symbols[1].Name != "" {
			t.Fatalf("truncation = %t, symbol 1 name = %q", set.Truncated, set.Symbols[1].Name)
		}
	})

	t.Run("unterminated name", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		f.data[f.strtabOffset+len(symbolNames)-1] = 'x'
		got := parseSymbolFixture(t, f, reeelf.DefaultLimits())
		set, err := got.Symbols()
		if err != nil {
			t.Fatalf("Symbols() error = %v", err)
		}
		if !set.Truncated || set.Symbols[7].Name != "" {
			t.Fatalf("truncation = %t, symbol 7 name = %q", set.Truncated, set.Symbols[7].Name)
		}
	})

	t.Run("string budget", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		limits := reeelf.DefaultLimits()
		limits.SymbolStringBytes = 4
		got := parseSymbolFixture(t, f, limits)
		set, err := got.Symbols()
		if err != nil {
			t.Fatalf("Symbols() error = %v", err)
		}
		if !set.Truncated || len(set.Symbols) != 8 {
			t.Fatalf("truncation = %t, symbols = %d", set.Truncated, len(set.Symbols))
		}
		if !hasLimitation(set.Limitations, "budget") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})
}

func TestSymbolsLimits(t *testing.T) {
	t.Parallel()

	t.Run("symbol count", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		limits := reeelf.DefaultLimits()
		limits.Symbols = 2
		got := parseSymbolFixture(t, f, limits)
		set, err := got.Symbols()
		if err != nil {
			t.Fatalf("Symbols() error = %v", err)
		}
		if !set.Truncated || len(set.Symbols) != 2 {
			t.Fatalf("truncation = %t, symbols = %d", set.Truncated, len(set.Symbols))
		}
		if !hasLimitation(set.Limitations, "symbol count exceeds limit 2") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})

	t.Run("table count", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		limits := reeelf.DefaultLimits()
		limits.SymbolTables = 1
		got := parseSymbolFixture(t, f, limits)
		set, err := got.Symbols()
		if err != nil {
			t.Fatalf("Symbols() error = %v", err)
		}
		if !set.Truncated || len(set.Symbols) != 5 {
			t.Fatalf("truncation = %t, symbols = %d", set.Truncated, len(set.Symbols))
		}
		if !hasLimitation(set.Limitations, "symbol table count exceeds limit 1") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})

	t.Run("entry size mismatch", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		f.put64(f.sectionFieldOffset(symtabSectionIndex, 56), 1)
		got := parseSymbolFixture(t, f, reeelf.DefaultLimits())
		set, err := got.Symbols()
		if err != nil {
			t.Fatalf("Symbols() error = %v", err)
		}
		if !set.Truncated || len(set.Symbols) != 3 {
			t.Fatalf("truncation = %t, symbols = %d", set.Truncated, len(set.Symbols))
		}
		if !hasLimitation(set.Limitations, "entry size") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})

	t.Run("trailing bytes", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		f.put64(f.sectionFieldOffset(symtabSectionIndex, 32), uint64(5*f.symbolSize-1))
		got := parseSymbolFixture(t, f, reeelf.DefaultLimits())
		set, err := got.Symbols()
		if err != nil {
			t.Fatalf("Symbols() error = %v", err)
		}
		if !set.Truncated || len(set.Symbols) != 7 {
			t.Fatalf("truncation = %t, symbols = %d", set.Truncated, len(set.Symbols))
		}
		if !hasLimitation(set.Limitations, "trailing bytes") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})

	t.Run("artifact truncation", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		cut := f.symtabOffset + 2*f.symbolSize + 5
		got, err := reeelf.Parse(bytes.NewReader(f.data[:cut]), int64(cut))
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		set, err := got.Symbols()
		if err != nil {
			t.Fatalf("Symbols() error = %v", err)
		}
		if !set.Truncated || len(set.Symbols) != 2 {
			t.Fatalf("truncation = %t, symbols = %d", set.Truncated, len(set.Symbols))
		}
		if !hasLimitation(set.Limitations, "exceeds artifact size") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})

	t.Run("reader failure", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		reader := &limitedReader{data: f.data, failAt: int64(f.symtabOffset)}
		got, err := reeelf.Parse(reader, int64(len(f.data)))
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if _, err := got.Symbols(); !errors.Is(err, reeelf.ErrRead) {
			t.Fatalf("Symbols() error = %v, want ErrRead", err)
		}
	})

	t.Run("incomplete section table", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		limits := reeelf.DefaultLimits()
		limits.SectionHeaders = 2
		got := parseSymbolFixture(t, f, limits)
		set, err := got.Symbols()
		if err != nil {
			t.Fatalf("Symbols() error = %v", err)
		}
		if !set.Truncated || len(set.Symbols) != 0 {
			t.Fatalf("truncation = %t, symbols = %d", set.Truncated, len(set.Symbols))
		}
		if !hasLimitation(set.Limitations, "incomplete") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})
}

func TestSymbolsExtendedIndexMissing(t *testing.T) {
	t.Parallel()

	f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
	f.put32(f.sectionFieldOffset(symtabShndxSectionIndex, 4), 1)
	got := parseSymbolFixture(t, f, reeelf.DefaultLimits())
	set, err := got.Symbols()
	if err != nil {
		t.Fatalf("Symbols() error = %v", err)
	}
	if !set.Truncated || set.Symbols[4].SectionIndex != 0xffff || set.Symbols[4].ExtendedSectionIndex {
		t.Fatalf("symbol 4 = %+v, truncated %t", set.Symbols[4], set.Truncated)
	}
	if !hasLimitation(set.Limitations, "extended section indexes unavailable") {
		t.Fatalf("limitations = %v", set.Limitations)
	}
}

func TestRelocations(t *testing.T) {
	t.Parallel()

	for _, class := range []reeelf.Class{reeelf.Class32, reeelf.Class64} {
		for _, data := range []reeelf.Data{reeelf.DataLittle, reeelf.DataBig} {
			t.Run(class.String()+"/"+data.String(), func(t *testing.T) {
				t.Parallel()

				f := buildSymbolFixture(class, data)
				got := parseSymbolFixture(t, f, reeelf.DefaultLimits())
				set, err := got.Relocations()
				if err != nil {
					t.Fatalf("Relocations() error = %v", err)
				}
				if set.Truncated || len(set.Limitations) != 0 {
					t.Fatalf("Relocations() truncation = %t, limitations = %v", set.Truncated, set.Limitations)
				}
				if len(set.Relocations) != 3 {
					t.Fatalf("Relocations() count = %d, want 3", len(set.Relocations))
				}

				base := uint64(0x400000)
				if class == reeelf.Class32 {
					base = 0x8048000
				}
				rela0 := set.Relocations[0]
				if rela0.SectionIndex != relaSectionIndex || rela0.TargetSectionIndex != textSectionIndex || rela0.Index != 0 {
					t.Fatalf("explicit-addend entry 0 identity = %+v", rela0)
				}
				if rela0.Offset != base+0x1000 || rela0.SymIndex != 2 || rela0.Type != 1 {
					t.Fatalf("explicit-addend entry 0 payload = %+v", rela0)
				}
				if !rela0.HasAddend || rela0.Addend != 42 {
					t.Fatalf("explicit-addend entry 0 value = %d, has %t", rela0.Addend, rela0.HasAddend)
				}

				rela1 := set.Relocations[1]
				if rela1.Offset != base+0x1004 || rela1.SymIndex != 3 || rela1.Type != 2 || rela1.Addend != -8 || !rela1.HasAddend {
					t.Fatalf("explicit-addend entry 1 = %+v", rela1)
				}

				rel0 := set.Relocations[2]
				if rel0.SectionIndex != relSectionIndex || rel0.TargetSectionIndex != dataSectionIndex || rel0.Index != 0 {
					t.Fatalf("rel 0 identity = %+v", rel0)
				}
				if rel0.Offset != base+0x2000 || rel0.SymIndex != 2 || rel0.Type != 1 {
					t.Fatalf("rel 0 payload = %+v", rel0)
				}
				if rel0.HasAddend || rel0.Addend != 0 {
					t.Fatalf("rel 0 addend = %d, has %t", rel0.Addend, rel0.HasAddend)
				}
			})
		}
	}
}

func TestRelocationsLimits(t *testing.T) {
	t.Parallel()

	t.Run("relocation count", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		limits := reeelf.DefaultLimits()
		limits.Relocations = 1
		got := parseSymbolFixture(t, f, limits)
		set, err := got.Relocations()
		if err != nil {
			t.Fatalf("Relocations() error = %v", err)
		}
		if !set.Truncated || len(set.Relocations) != 1 {
			t.Fatalf("truncation = %t, relocations = %d", set.Truncated, len(set.Relocations))
		}
		if !hasLimitation(set.Limitations, "relocation count exceeds limit 1") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})

	t.Run("section count", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		limits := reeelf.DefaultLimits()
		limits.RelocationSections = 1
		got := parseSymbolFixture(t, f, limits)
		set, err := got.Relocations()
		if err != nil {
			t.Fatalf("Relocations() error = %v", err)
		}
		if !set.Truncated || len(set.Relocations) != 2 {
			t.Fatalf("truncation = %t, relocations = %d", set.Truncated, len(set.Relocations))
		}
		if !hasLimitation(set.Limitations, "relocation section count exceeds limit 1") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})

	t.Run("entry size mismatch", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		f.put64(f.sectionFieldOffset(relaSectionIndex, 56), 1)
		got := parseSymbolFixture(t, f, reeelf.DefaultLimits())
		set, err := got.Relocations()
		if err != nil {
			t.Fatalf("Relocations() error = %v", err)
		}
		if !set.Truncated || len(set.Relocations) != 1 || set.Relocations[0].SectionIndex != relSectionIndex {
			t.Fatalf("truncation = %t, relocations = %+v", set.Truncated, set.Relocations)
		}
		if !hasLimitation(set.Limitations, "entry size") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})

	t.Run("trailing bytes", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		f.put64(f.sectionFieldOffset(relaSectionIndex, 32), uint64(2*f.relaSize-1))
		got := parseSymbolFixture(t, f, reeelf.DefaultLimits())
		set, err := got.Relocations()
		if err != nil {
			t.Fatalf("Relocations() error = %v", err)
		}
		if !set.Truncated || len(set.Relocations) != 2 {
			t.Fatalf("truncation = %t, relocations = %d", set.Truncated, len(set.Relocations))
		}
		if !hasLimitation(set.Limitations, "trailing bytes") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})

	t.Run("artifact truncation", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		cut := f.relaOffset + f.relaSize + 3
		got, err := reeelf.Parse(bytes.NewReader(f.data[:cut]), int64(cut))
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		set, err := got.Relocations()
		if err != nil {
			t.Fatalf("Relocations() error = %v", err)
		}
		if !set.Truncated || len(set.Relocations) != 1 {
			t.Fatalf("truncation = %t, relocations = %d", set.Truncated, len(set.Relocations))
		}
	})

	t.Run("reader failure", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		reader := &limitedReader{data: f.data, failAt: int64(f.relaOffset)}
		got, err := reeelf.Parse(reader, int64(len(f.data)))
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if _, err := got.Relocations(); !errors.Is(err, reeelf.ErrRead) {
			t.Fatalf("Relocations() error = %v, want ErrRead", err)
		}
	})

	t.Run("incomplete section table", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		limits := reeelf.DefaultLimits()
		limits.SectionHeaders = 2
		got := parseSymbolFixture(t, f, limits)
		set, err := got.Relocations()
		if err != nil {
			t.Fatalf("Relocations() error = %v", err)
		}
		if !set.Truncated || len(set.Relocations) != 0 {
			t.Fatalf("truncation = %t, relocations = %d", set.Truncated, len(set.Relocations))
		}
		if !hasLimitation(set.Limitations, "incomplete") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})
}

func TestSymbolsAdditionalEdges(t *testing.T) {
	t.Parallel()

	t.Run("empty symbol tables", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		f.put64(f.sectionFieldOffset(symtabSectionIndex, 32), 0)
		f.put64(f.sectionFieldOffset(dynsymSectionIndex, 32), 0)
		got := parseSymbolFixture(t, f, reeelf.DefaultLimits())
		set, err := got.Symbols()
		if err != nil {
			t.Fatalf("Symbols() error = %v", err)
		}
		if set.Truncated || len(set.Symbols) != 0 || len(set.Limitations) != 0 {
			t.Fatalf("Symbols() = %+v", set)
		}
	})

	t.Run("name offset outside string table", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		f.put32(f.symtabOffset+1*f.symbolSize, 10_000)
		got := parseSymbolFixture(t, f, reeelf.DefaultLimits())
		set, err := got.Symbols()
		if err != nil {
			t.Fatalf("Symbols() error = %v", err)
		}
		if !set.Truncated || set.Symbols[1].Name != "" || set.Symbols[1].NameOffset != 10_000 {
			t.Fatalf("symbol 1 = %+v, truncated %t", set.Symbols[1], set.Truncated)
		}
		if !hasLimitation(set.Limitations, "symbol names unavailable") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})

	t.Run("string table above limit", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		limits := reeelf.DefaultLimits()
		limits.StringTableBytes = 4
		got := parseSymbolFixture(t, f, limits)
		set, err := got.Symbols()
		if err != nil {
			t.Fatalf("Symbols() error = %v", err)
		}
		if !set.Truncated || len(set.Symbols) != 8 {
			t.Fatalf("Symbols() = %d symbols, truncated %t", len(set.Symbols), set.Truncated)
		}
		if !hasLimitation(set.Limitations, "string table size") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})

	t.Run("string table outside artifact", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		f.put64(f.sectionFieldOffset(strtabSectionIndex, 24), uint64(len(f.data)+64))
		got := parseSymbolFixture(t, f, reeelf.DefaultLimits())
		set, err := got.Symbols()
		if err != nil {
			t.Fatalf("Symbols() error = %v", err)
		}
		if !set.Truncated || len(set.Symbols) != 8 {
			t.Fatalf("Symbols() = %d symbols, truncated %t", len(set.Symbols), set.Truncated)
		}
		if !hasLimitation(set.Limitations, "is unavailable") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})

	t.Run("symbol table outside artifact", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		f.put64(f.sectionFieldOffset(symtabSectionIndex, 24), uint64(len(f.data)+64))
		got := parseSymbolFixture(t, f, reeelf.DefaultLimits())
		set, err := got.Symbols()
		if err != nil {
			t.Fatalf("Symbols() error = %v", err)
		}
		if !set.Truncated || len(set.Symbols) != 3 {
			t.Fatalf("Symbols() = %d symbols, truncated %t", len(set.Symbols), set.Truncated)
		}
		if !hasLimitation(set.Limitations, "exceeds artifact size") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})

	t.Run("section index table entry size mismatch", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		f.put64(f.sectionFieldOffset(symtabShndxSectionIndex, 56), 1)
		got := parseSymbolFixture(t, f, reeelf.DefaultLimits())
		set, err := got.Symbols()
		if err != nil {
			t.Fatalf("Symbols() error = %v", err)
		}
		if !set.Truncated || set.Symbols[4].SectionIndex != 0xffff || set.Symbols[4].ExtendedSectionIndex {
			t.Fatalf("symbol 4 = %+v, truncated %t", set.Symbols[4], set.Truncated)
		}
		if !hasLimitation(set.Limitations, "section index table") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})
}

func TestRelocationsAdditionalEdges(t *testing.T) {
	t.Parallel()

	t.Run("empty relocation sections", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		f.put64(f.sectionFieldOffset(relaSectionIndex, 32), 0)
		f.put64(f.sectionFieldOffset(relSectionIndex, 32), 0)
		got := parseSymbolFixture(t, f, reeelf.DefaultLimits())
		set, err := got.Relocations()
		if err != nil {
			t.Fatalf("Relocations() error = %v", err)
		}
		if set.Truncated || len(set.Relocations) != 0 || len(set.Limitations) != 0 {
			t.Fatalf("Relocations() = %+v", set)
		}
	})

	t.Run("relocation section outside artifact", func(t *testing.T) {
		t.Parallel()

		f := buildSymbolFixture(reeelf.Class64, reeelf.DataLittle)
		f.put64(f.sectionFieldOffset(relaSectionIndex, 24), uint64(len(f.data)+64))
		got := parseSymbolFixture(t, f, reeelf.DefaultLimits())
		set, err := got.Relocations()
		if err != nil {
			t.Fatalf("Relocations() error = %v", err)
		}
		if !set.Truncated || len(set.Relocations) != 1 || set.Relocations[0].SectionIndex != relSectionIndex {
			t.Fatalf("Relocations() = %+v, truncated %t", set.Relocations, set.Truncated)
		}
		if !hasLimitation(set.Limitations, "exceeds artifact size") {
			t.Fatalf("limitations = %v", set.Limitations)
		}
	})
}

func hasLimitation(limitations []string, fragment string) bool {
	for _, limitation := range limitations {
		if strings.Contains(limitation, fragment) {
			return true
		}
	}
	return false
}
