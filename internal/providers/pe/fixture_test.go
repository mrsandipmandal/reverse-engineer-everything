package pe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	repe "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/pe"
)

const (
	fixtureRVA        = 0x1000
	fixtureRawOffset  = 0x200
	fixtureHeaderSize = 0x200
)

// thunkSpec describes one import thunk for the fixture.
type thunkSpec struct {
	name      string
	hint      uint16
	ordinal   uint16
	byOrdinal bool
}

// importSpec describes one import descriptor for the fixture.
type importSpec struct {
	name    string
	iatOnly bool
	thunks  []thunkSpec
}

// exportSpec describes one export address table slot for the fixture.
type exportSpec struct {
	name      string
	rva       uint32
	forwarder string
}

// fixtureOptions configure the crafted PE32 or PE32+ artifact.
type fixtureOptions struct {
	magic         uint16
	omitImports   bool
	omitExports   bool
	omitResources bool
	certificates  int
	overlayBytes  int
	extraExports  int
}

// peFixture is a crafted one-section PE image. The .rdata section starts at RVA
// 0x1000 and raw offset 0x200 and holds imports, exports, and resources.
type peFixture struct {
	data  []byte
	magic uint16

	importDirectoryRVA    uint32
	importDirectorySize   uint32
	exportDirectoryRVA    uint32
	exportDirectorySize   uint32
	resourceDirectoryRVA  uint32
	resourceDirectorySize uint32
	sectionTableOffset    int
	certificateOffset     uint64
	certificateSize       uint32
	exportCount           int
	contentSize           int
}

func newPEFixture(t testing.TB, opts fixtureOptions) *peFixture {
	t.Helper()

	if opts.magic == 0 {
		opts.magic = repe.MagicPE32
	}
	if opts.magic != repe.MagicPE32 && opts.magic != repe.MagicPE32P {
		t.Fatalf("unsupported magic %#x", opts.magic)
	}

	f := &peFixture{magic: opts.magic}
	var content []byte

	align := func() {
		for len(content)%4 != 0 {
			content = append(content, 0)
		}
	}
	put := func(raw []byte) uint32 {
		align()
		rva := uint32(fixtureRVA + len(content))
		content = append(content, raw...)
		return rva
	}
	str := func(value string) uint32 {
		rva := uint32(fixtureRVA + len(content))
		content = append(content, value...)
		content = append(content, 0)
		return rva
	}

	if !opts.omitImports {
		entrySize := 4
		if f.magic == repe.MagicPE32P {
			entrySize = 8
		}
		modules := []importSpec{
			{name: "KERNEL32.dll", thunks: []thunkSpec{
				{name: "Sleep", hint: 0},
				{byOrdinal: true, ordinal: 12},
			}},
			{name: "USER32.dll", iatOnly: true, thunks: []thunkSpec{
				{name: "MessageBoxA", hint: 7},
			}},
		}
		start := len(content)
		nameRVAs := make([]uint32, len(modules))
		thunkRVAs := make([]uint32, len(modules))
		for i, module := range modules {
			nameRVAs[i] = str(module.name)
			values := make([]uint64, 0, len(module.thunks))
			for _, thunk := range module.thunks {
				if thunk.byOrdinal {
					if entrySize == 8 {
						values = append(values, 0x8000000000000000|uint64(thunk.ordinal))
					} else {
						values = append(values, 0x80000000|uint64(thunk.ordinal))
					}
					continue
				}
				record := make([]byte, 2+len(thunk.name)+1)
				binary.LittleEndian.PutUint16(record, thunk.hint)
				copy(record[2:], thunk.name)
				values = append(values, uint64(put(record)))
			}
			raw := make([]byte, (len(values)+1)*entrySize)
			for j, value := range values {
				if entrySize == 8 {
					binary.LittleEndian.PutUint64(raw[j*8:], value)
				} else {
					binary.LittleEndian.PutUint32(raw[j*4:], uint32(value))
				}
			}
			thunkRVAs[i] = put(raw)
		}
		descriptors := make([]byte, (len(modules)+1)*20)
		for i := range modules {
			raw := descriptors[i*20:]
			if !modules[i].iatOnly {
				binary.LittleEndian.PutUint32(raw[0:], thunkRVAs[i])
			}
			binary.LittleEndian.PutUint32(raw[12:], nameRVAs[i])
			binary.LittleEndian.PutUint32(raw[16:], thunkRVAs[i])
		}
		f.importDirectoryRVA = put(descriptors)
		f.importDirectorySize = uint32(len(content) - start)
	}

	if !opts.omitExports {
		entries := []exportSpec{
			{name: "Alpha", rva: 0x2000},
			{name: "Forwarded", forwarder: "KERNEL32.Sleep"},
			{rva: 0x2004},
		}
		for i := 0; i < opts.extraExports; i++ {
			entries = append(entries, exportSpec{
				name: fmt.Sprintf("Extra%d", i),
				rva:  uint32(0x3000 + i*4),
			})
		}
		f.exportCount = len(entries)
		start := len(content)
		directoryRVA := put(make([]byte, 40))
		nameRVA := str("sample.dll")
		functions := make([]uint32, len(entries))
		type nameRecord struct {
			rva   uint32
			index uint16
		}
		names := make([]nameRecord, 0, len(entries))
		for i, entry := range entries {
			if entry.forwarder != "" {
				target := str(entry.forwarder)
				raw := make([]byte, 4)
				binary.LittleEndian.PutUint32(raw, target)
				functions[i] = put(raw)
			} else {
				functions[i] = entry.rva
			}
			if entry.name != "" {
				names = append(names, nameRecord{rva: str(entry.name), index: uint16(i)})
			}
		}
		functionsRaw := make([]byte, len(functions)*4)
		for i, rva := range functions {
			binary.LittleEndian.PutUint32(functionsRaw[i*4:], rva)
		}
		functionsRVA := put(functionsRaw)
		namesRaw := make([]byte, len(names)*4)
		ordinalsRaw := make([]byte, len(names)*2)
		for i, name := range names {
			binary.LittleEndian.PutUint32(namesRaw[i*4:], name.rva)
			binary.LittleEndian.PutUint16(ordinalsRaw[i*2:], name.index)
		}
		namesRVA := put(namesRaw)
		ordinalsRVA := put(ordinalsRaw)

		raw := content[directoryRVA-fixtureRVA:]
		binary.LittleEndian.PutUint32(raw[4:], 0x5f5e1000)
		binary.LittleEndian.PutUint16(raw[8:], 1)
		binary.LittleEndian.PutUint16(raw[10:], 2)
		binary.LittleEndian.PutUint32(raw[12:], nameRVA)
		binary.LittleEndian.PutUint32(raw[16:], 1)
		binary.LittleEndian.PutUint32(raw[20:], uint32(len(entries)))
		binary.LittleEndian.PutUint32(raw[24:], uint32(len(names)))
		binary.LittleEndian.PutUint32(raw[28:], functionsRVA)
		binary.LittleEndian.PutUint32(raw[32:], namesRVA)
		binary.LittleEndian.PutUint32(raw[36:], ordinalsRVA)
		f.exportDirectoryRVA = directoryRVA
		f.exportDirectorySize = uint32(len(content) - start)
	}

	if !opts.omitResources {
		align()
		base := uint32(fixtureRVA + len(content))
		block := make([]byte, 104, 104+len("resource-body"))
		// Root directory: one integer type 10 -> subdirectory at 24.
		binary.LittleEndian.PutUint16(block[12:], 0)
		binary.LittleEndian.PutUint16(block[14:], 1)
		binary.LittleEndian.PutUint32(block[16:], 10)
		binary.LittleEndian.PutUint32(block[20:], 0x80000018)
		// Type directory: one named entry at 72 -> subdirectory at 48.
		binary.LittleEndian.PutUint16(block[24+12:], 1)
		binary.LittleEndian.PutUint16(block[24+14:], 0)
		binary.LittleEndian.PutUint32(block[40:], 0x80000048)
		binary.LittleEndian.PutUint32(block[44:], 0x80000030)
		// Name directory: one language 1033 -> data entry at 88.
		binary.LittleEndian.PutUint16(block[48+12:], 0)
		binary.LittleEndian.PutUint16(block[48+14:], 1)
		binary.LittleEndian.PutUint32(block[64:], 1033)
		binary.LittleEndian.PutUint32(block[68:], 88)
		// Name string "RCDATA" at 72.
		binary.LittleEndian.PutUint16(block[72:], 6)
		for i, unit := range []uint16{'R', 'C', 'D', 'A', 'T', 'A'} {
			binary.LittleEndian.PutUint16(block[74+i*2:], unit)
		}
		// Data entry at 88.
		body := []byte("resource-body")
		binary.LittleEndian.PutUint32(block[88:], base+104)
		binary.LittleEndian.PutUint32(block[92:], uint32(len(body)))
		binary.LittleEndian.PutUint32(block[96:], 1252)
		block = append(block, body...)
		content = append(content, block...)
		f.resourceDirectoryRVA = base
		f.resourceDirectorySize = uint32(len(block))
	}

	optionalSize := 224
	machine := uint16(0x14c)
	characteristics := uint16(0x0102)
	if f.magic == repe.MagicPE32P {
		optionalSize = 240
		machine = 0x8664
		characteristics = 0x0022
	}

	data := make([]byte, fixtureHeaderSize, fixtureHeaderSize+len(content))
	copy(data[0:], "MZ")
	binary.LittleEndian.PutUint32(data[0x3c:], 0x80)
	copy(data[0x80:], "PE\x00\x00")

	coff := 0x84
	binary.LittleEndian.PutUint16(data[coff:], machine)
	binary.LittleEndian.PutUint16(data[coff+2:], 1)
	binary.LittleEndian.PutUint32(data[coff+4:], 0x5f5e1000)
	binary.LittleEndian.PutUint16(data[coff+16:], uint16(optionalSize))
	binary.LittleEndian.PutUint16(data[coff+18:], characteristics)

	optional := coff + 20
	binary.LittleEndian.PutUint16(data[optional:], f.magic)
	binary.LittleEndian.PutUint32(data[optional+32:], 0x1000)
	binary.LittleEndian.PutUint32(data[optional+36:], 0x200)
	binary.LittleEndian.PutUint16(data[optional+40:], 6)
	binary.LittleEndian.PutUint16(data[optional+48:], 6)
	binary.LittleEndian.PutUint32(data[optional+56:], 0x2000)
	binary.LittleEndian.PutUint32(data[optional+60:], fixtureHeaderSize)
	binary.LittleEndian.PutUint16(data[optional+68:], 3)

	fixedSize := 96
	if f.magic == repe.MagicPE32 {
		binary.LittleEndian.PutUint32(data[optional+28:], 0x400000)
		binary.LittleEndian.PutUint32(data[optional+72:], 0x100000)
		binary.LittleEndian.PutUint32(data[optional+76:], 0x1000)
		binary.LittleEndian.PutUint32(data[optional+80:], 0x100000)
		binary.LittleEndian.PutUint32(data[optional+84:], 0x1000)
		binary.LittleEndian.PutUint32(data[optional+92:], 16)
	} else {
		fixedSize = 112
		binary.LittleEndian.PutUint64(data[optional+24:], 0x140000000)
		binary.LittleEndian.PutUint64(data[optional+72:], 0x100000)
		binary.LittleEndian.PutUint64(data[optional+80:], 0x1000)
		binary.LittleEndian.PutUint64(data[optional+88:], 0x100000)
		binary.LittleEndian.PutUint64(data[optional+96:], 0x1000)
		binary.LittleEndian.PutUint32(data[optional+108:], 16)
	}

	directories := optional + fixedSize
	if !opts.omitExports {
		binary.LittleEndian.PutUint32(data[directories:], f.exportDirectoryRVA)
		binary.LittleEndian.PutUint32(data[directories+4:], f.exportDirectorySize)
	}
	if !opts.omitImports {
		binary.LittleEndian.PutUint32(data[directories+8:], f.importDirectoryRVA)
		binary.LittleEndian.PutUint32(data[directories+12:], f.importDirectorySize)
	}
	if !opts.omitResources {
		binary.LittleEndian.PutUint32(data[directories+16:], f.resourceDirectoryRVA)
		binary.LittleEndian.PutUint32(data[directories+20:], f.resourceDirectorySize)
	}

	section := optional + optionalSize
	f.sectionTableOffset = section
	copy(data[section:section+8], ".rdata")
	binary.LittleEndian.PutUint32(data[section+8:], uint32(len(content)))
	binary.LittleEndian.PutUint32(data[section+12:], fixtureRVA)
	binary.LittleEndian.PutUint32(data[section+16:], uint32(len(content)))
	binary.LittleEndian.PutUint32(data[section+20:], fixtureRawOffset)
	binary.LittleEndian.PutUint32(data[section+36:], 0x40000040)

	data = append(data, content...)

	if opts.certificates > 0 {
		for len(data)%8 != 0 {
			data = append(data, 0)
		}
		f.certificateOffset = uint64(len(data))
		records := [][]byte{
			certificateRecord(0x0200, 0x0002, []byte("signed-data")),
			certificateRecord(0x0100, 0x0001, []byte("x509")),
		}
		for i := 0; i < opts.certificates && i < len(records); i++ {
			data = append(data, records[i]...)
		}
		f.certificateSize = uint32(len(data)) - uint32(f.certificateOffset)
		security := optional + fixedSize + 4*8
		binary.LittleEndian.PutUint32(data[security:], uint32(f.certificateOffset))
		binary.LittleEndian.PutUint32(data[security+4:], f.certificateSize)
	}
	for i := 0; i < opts.overlayBytes; i++ {
		data = append(data, byte(i+1))
	}

	f.contentSize = len(content)
	f.data = data
	return f
}

// dataDirectoryOffset returns the file offset of one optional header data
// directory entry.
func (f *peFixture) dataDirectoryOffset(index int) int {
	fixed := 96
	if f.magic == repe.MagicPE32P {
		fixed = 112
	}
	return 0x98 + fixed + index*8
}

func (f *peFixture) parse(t testing.TB) *repe.File {
	t.Helper()

	file, err := repe.Parse(bytes.NewReader(f.data), int64(len(f.data)))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return file
}

// certificateRecord wraps body in a WIN_CERTIFICATE header and pads the record
// to the eight-byte table alignment.
func certificateRecord(revision, certificateType uint16, body []byte) []byte {
	length := 8 + len(body)
	raw := make([]byte, (length+7)&^7)
	binary.LittleEndian.PutUint32(raw[0:], uint32(length))
	binary.LittleEndian.PutUint16(raw[4:], revision)
	binary.LittleEndian.PutUint16(raw[6:], certificateType)
	copy(raw[8:], body)
	return raw
}
