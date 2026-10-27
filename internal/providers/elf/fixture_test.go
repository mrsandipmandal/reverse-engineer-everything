package elf

import (
	"encoding/binary"
	"testing"
)

const (
	fixtureSectionCount = 8
	fixtureShstrtab     = 7
)

// fixtureOptions configure the crafted ELF64 little-endian artifact.
type fixtureOptions struct {
	// relType selects the relocation section type: the explicit-addend layout
	// (4) by default, or the stored-addend layout (9).
	relType uint32
	// descSize is the GNU build-id descriptor size. Zero selects 8.
	descSize int
	// extraSymbols adds SHT_SYMTAB entries after the null and main entries.
	extraSymbols int
}

// elfFixture is a crafted ELF64 little-endian artifact with a loadable text
// segment, a build-id note, .comment entries, a symbol table, and one
// relocation section.
type elfFixture struct {
	data        []byte
	opts        fixtureOptions
	textOff     int
	noteOff     int
	noteSize    int
	commentOff  int
	strtabOff   int
	relOff      int
	relSize     int
	symtabOff   int
	symtabSize  int
	shstrOff    int
	shOff       int
	symbolCount int
	comment     []string
}

func alignTo(n, align int) int {
	return (n + align - 1) &^ (align - 1)
}

func newELFFixture(t testing.TB, opts fixtureOptions) *elfFixture {
	t.Helper()

	if opts.relType == 0 {
		opts.relType = 4
	}
	if opts.relType != 4 && opts.relType != 9 {
		t.Fatalf("unsupported relocation section type %d", opts.relType)
	}
	if opts.descSize <= 0 {
		opts.descSize = 8
	}

	data := make([]byte, 64)
	alloc := func(size, align int) int {
		offset := alignTo(len(data), align)
		data = append(data, make([]byte, offset+size-len(data))...)
		return offset
	}

	f := &elfFixture{opts: opts}
	phOff := alloc(56, 8)

	f.textOff = alloc(8, 16)
	copy(data[f.textOff:], []byte{0x90, 0x90, 0x90, 0x90, 0xc3, 0x00, 0x00, 0x00})

	f.noteSize = 12 + alignTo(4, 4) + alignTo(opts.descSize, 4)
	f.noteOff = alloc(f.noteSize, 4)
	binary.LittleEndian.PutUint32(data[f.noteOff:], 4)
	binary.LittleEndian.PutUint32(data[f.noteOff+4:], uint32(opts.descSize))
	binary.LittleEndian.PutUint32(data[f.noteOff+8:], 3)
	copy(data[f.noteOff+12:], "GNU\x00")
	desc := data[f.noteOff+16 : f.noteOff+16+opts.descSize]
	for i := range desc {
		desc[i] = byte(i)
	}

	f.comment = []string{"ree-test 1.0", "second entry"}
	f.commentOff = alloc(commentSize(f.comment), 1)
	copy(data[f.commentOff:], joinComment(f.comment))

	strtab := buildStrtab(opts.extraSymbols)
	f.strtabOff = alloc(len(strtab), 1)
	copy(data[f.strtabOff:], strtab)

	f.relSize = 24
	if opts.relType == 9 {
		f.relSize = 16
	}
	f.relOff = alloc(2*f.relSize, 8)

	f.symbolCount = 2 + opts.extraSymbols
	f.symtabSize = f.symbolCount * 24
	f.symtabOff = alloc(f.symtabSize, 8)

	shstr := []byte{0}
	names := make(map[string]uint32)
	addName := func(name string) uint32 {
		offset := uint32(len(shstr))
		shstr = append(shstr, name...)
		shstr = append(shstr, 0)
		return offset
	}
	names[".text"] = addName(".text")
	names[".comment"] = addName(".comment")
	names[".note.gnu.build-id"] = addName(".note.gnu.build-id")
	names[".strtab"] = addName(".strtab")
	names[".symtab"] = addName(".symtab")
	relName := ".rela.text"
	if opts.relType == 9 {
		relName = ".rel.text"
	}
	names[relName] = addName(relName)
	names[".shstrtab"] = addName(".shstrtab")

	f.shstrOff = alloc(len(shstr), 1)
	copy(data[f.shstrOff:], shstr)

	f.shOff = alloc(fixtureSectionCount*64, 8)
	f.data = data

	// ELF header.
	copy(f.data[0:], "\x7fELF\x02\x01\x01")
	binary.LittleEndian.PutUint16(f.data[16:], 3)
	binary.LittleEndian.PutUint16(f.data[18:], 62)
	binary.LittleEndian.PutUint32(f.data[20:], 1)
	binary.LittleEndian.PutUint64(f.data[24:], 0x78)
	binary.LittleEndian.PutUint64(f.data[32:], uint64(phOff))
	binary.LittleEndian.PutUint64(f.data[40:], uint64(f.shOff))
	binary.LittleEndian.PutUint16(f.data[52:], 64)
	binary.LittleEndian.PutUint16(f.data[54:], 56)
	binary.LittleEndian.PutUint16(f.data[56:], 1)
	binary.LittleEndian.PutUint16(f.data[58:], 64)
	binary.LittleEndian.PutUint16(f.data[60:], fixtureSectionCount)
	binary.LittleEndian.PutUint16(f.data[62:], fixtureShstrtab)

	// Program header: one loadable segment covering .text.
	binary.LittleEndian.PutUint32(f.data[phOff:], 1)
	binary.LittleEndian.PutUint32(f.data[phOff+4:], 5)
	binary.LittleEndian.PutUint64(f.data[phOff+8:], uint64(f.textOff))
	binary.LittleEndian.PutUint64(f.data[phOff+16:], 0x78)
	binary.LittleEndian.PutUint64(f.data[phOff+24:], 0x78)
	binary.LittleEndian.PutUint64(f.data[phOff+32:], 8)
	binary.LittleEndian.PutUint64(f.data[phOff+40:], 8)
	binary.LittleEndian.PutUint64(f.data[phOff+48:], 0x1000)

	// Symbols: null, main, then extra objects.
	main := f.symtabOff + 24
	binary.LittleEndian.PutUint32(f.data[main:], 1)
	f.data[main+4] = 0x12
	binary.LittleEndian.PutUint16(f.data[main+6:], 1)
	binary.LittleEndian.PutUint64(f.data[main+8:], 0x78)
	binary.LittleEndian.PutUint64(f.data[main+16:], 8)
	nameOffset := uint32(6) // "\x00main\x00"
	for i := 0; i < opts.extraSymbols; i++ {
		entry := f.symtabOff + (2+i)*24
		binary.LittleEndian.PutUint32(f.data[entry:], nameOffset)
		f.data[entry+4] = 0x11
		binary.LittleEndian.PutUint16(f.data[entry+6:], 1)
		binary.LittleEndian.PutUint64(f.data[entry+8:], uint64(i))
		binary.LittleEndian.PutUint64(f.data[entry+16:], 4)
		nameOffset += uint32(len("sym"+itoa(i)) + 1)
	}

	// Relocations: two entries referencing symbols 1 and 2.
	for i, addend := range []int64{-4, 8} {
		entry := f.relOff + i*f.relSize
		binary.LittleEndian.PutUint64(f.data[entry:], uint64(8+i*8))
		binary.LittleEndian.PutUint64(f.data[entry+8:], uint64(i+1)<<32|uint64(i+1))
		if opts.relType == 4 {
			binary.LittleEndian.PutUint64(f.data[entry+16:], uint64(addend))
		}
	}

	// Section headers.
	f.writeSection(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	f.writeSection(1, names[".text"], 1, 0x6, 0x78, uint64(f.textOff), 8, 0, 0, 16, 0)
	f.writeSection(2, names[".comment"], 1, 0x30, 0, uint64(f.commentOff), uint64(commentSize(f.comment)), 0, 0, 1, 0)
	f.writeSection(3, names[".note.gnu.build-id"], 7, 0x2, 0x80, uint64(f.noteOff), uint64(f.noteSize), 0, 0, 4, 0)
	f.writeSection(4, names[".strtab"], 3, 0, 0, uint64(f.strtabOff), uint64(len(strtab)), 0, 0, 1, 0)
	f.writeSection(5, names[".symtab"], 2, 0, 0, uint64(f.symtabOff), uint64(f.symtabSize), 4, 1, 8, 24)
	f.writeSection(6, names[relName], opts.relType, 0, 0, uint64(f.relOff), uint64(2*f.relSize), 5, 1, 8, uint64(f.relSize))
	f.writeSection(7, names[".shstrtab"], 3, 0, 0, uint64(f.shstrOff), uint64(len(shstr)), 0, 0, 1, 0)

	return f
}

func (f *elfFixture) writeSection(index int, name, typ uint32, flags, addr uint64, offset, size uint64, link, info uint32, align, entsize uint64) {
	base := f.shOff + index*64
	binary.LittleEndian.PutUint32(f.data[base:], name)
	binary.LittleEndian.PutUint32(f.data[base+4:], typ)
	binary.LittleEndian.PutUint64(f.data[base+8:], flags)
	binary.LittleEndian.PutUint64(f.data[base+16:], addr)
	binary.LittleEndian.PutUint64(f.data[base+24:], offset)
	binary.LittleEndian.PutUint64(f.data[base+32:], size)
	binary.LittleEndian.PutUint32(f.data[base+40:], link)
	binary.LittleEndian.PutUint32(f.data[base+44:], info)
	binary.LittleEndian.PutUint64(f.data[base+48:], align)
	binary.LittleEndian.PutUint64(f.data[base+56:], entsize)
}

func (f *elfFixture) buildID() []byte {
	return f.data[f.noteOff+16 : f.noteOff+16+f.opts.descSize]
}

func (f *elfFixture) text() []byte {
	return f.data[f.textOff : f.textOff+8]
}

func buildStrtab(extraSymbols int) []byte {
	out := []byte{0}
	out = append(out, "main"...)
	out = append(out, 0)
	for i := 0; i < extraSymbols; i++ {
		out = append(out, "sym"...)
		out = append(out, itoa(i)...)
		out = append(out, 0)
	}
	return out
}

func commentSize(entries []string) int {
	size := 0
	for _, entry := range entries {
		size += len(entry) + 1
	}
	return size
}

func joinComment(entries []string) []byte {
	var out []byte
	for _, entry := range entries {
		out = append(out, entry...)
		out = append(out, 0)
	}
	return out
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
