package pe_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	repe "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/pe"
)

const (
	metadataRVA        = 0x1000
	metadataRawOffset  = 0x200
	metadataHeaderSize = 0x200
)

// thunkSpec describes one import thunk for the metadata fixture.
type thunkSpec struct {
	name      string
	hint      uint16
	ordinal   uint16
	byOrdinal bool
}

// importSpec describes one import descriptor for the metadata fixture.
type importSpec struct {
	name    string
	iatOnly bool
	thunks  []thunkSpec
}

// exportSpec describes one export address table slot for the metadata fixture.
type exportSpec struct {
	name      string
	rva       uint32
	forwarder string
}

// exportLayout records the RVAs the fixture assigned to the export arrays.
type exportLayout struct {
	directoryRVA uint32
	size         uint32
	functionsRVA uint32
	namesRVA     uint32
	ordinalsRVA  uint32
	nameCount    int
}

// metadataImage builds a one-section PE image whose .rdata section holds
// import, export, and string data at RVA 0x1000.
type metadataImage struct {
	magic          uint16
	content        []byte
	directories    [16][2]uint32
	directoryCount uint32
}

func newMetadataImage(magic uint16) *metadataImage {
	return &metadataImage{magic: magic, directoryCount: 16}
}

func (m *metadataImage) align() {
	for len(m.content)%4 != 0 {
		m.content = append(m.content, 0)
	}
}

func (m *metadataImage) put(raw []byte) uint32 {
	m.align()
	rva := uint32(metadataRVA + len(m.content))
	m.content = append(m.content, raw...)
	return rva
}

func (m *metadataImage) str(value string) uint32 {
	rva := uint32(metadataRVA + len(m.content))
	m.content = append(m.content, value...)
	m.content = append(m.content, 0)
	return rva
}

func (m *metadataImage) offset(rva uint32) int {
	return metadataRawOffset + int(rva-metadataRVA)
}

// addImports appends module names, thunk arrays, and a terminated descriptor
// array, then points the import directory at the descriptors.
func (m *metadataImage) addImports(modules []importSpec) uint32 {
	entrySize := 4
	if m.magic == repe.MagicPE32P {
		entrySize = 8
	}
	start := len(m.content)
	nameRVAs := make([]uint32, len(modules))
	thunkRVAs := make([]uint32, len(modules))

	for i, module := range modules {
		nameRVAs[i] = m.str(module.name)
		if len(module.thunks) == 0 {
			continue
		}
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
			values = append(values, uint64(m.put(record)))
		}
		raw := make([]byte, (len(values)+1)*entrySize)
		for j, value := range values {
			if entrySize == 8 {
				binary.LittleEndian.PutUint64(raw[j*8:], value)
			} else {
				binary.LittleEndian.PutUint32(raw[j*4:], uint32(value))
			}
		}
		thunkRVAs[i] = m.put(raw)
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
	directoryRVA := m.put(descriptors)
	m.directories[1] = [2]uint32{directoryRVA, uint32(len(m.content) - start)}
	return directoryRVA
}

// addExports appends a DLL name, function addresses, optional forwarder
// records, name strings, and the name and ordinal arrays, then points the
// export directory at the structure.
func (m *metadataImage) addExports(dll string, base uint32, entries []exportSpec) exportLayout {
	start := len(m.content)
	directoryRVA := m.put(make([]byte, 40))
	nameRVA := m.str(dll)

	functions := make([]uint32, len(entries))
	type nameRecord struct {
		rva   uint32
		index uint16
	}
	names := make([]nameRecord, 0, len(entries))
	for i, entry := range entries {
		if entry.forwarder != "" {
			target := m.str(entry.forwarder)
			raw := make([]byte, 4)
			binary.LittleEndian.PutUint32(raw, target)
			functions[i] = m.put(raw)
		} else {
			functions[i] = entry.rva
		}
		if entry.name != "" {
			names = append(names, nameRecord{rva: m.str(entry.name), index: uint16(i)})
		}
	}

	functionsRaw := make([]byte, len(functions)*4)
	for i, rva := range functions {
		binary.LittleEndian.PutUint32(functionsRaw[i*4:], rva)
	}
	functionsRVA := m.put(functionsRaw)

	namesRaw := make([]byte, len(names)*4)
	ordinalsRaw := make([]byte, len(names)*2)
	for i, name := range names {
		binary.LittleEndian.PutUint32(namesRaw[i*4:], name.rva)
		binary.LittleEndian.PutUint16(ordinalsRaw[i*2:], name.index)
	}
	namesRVA := m.put(namesRaw)
	ordinalsRVA := m.put(ordinalsRaw)

	raw := m.content[directoryRVA-metadataRVA:]
	binary.LittleEndian.PutUint32(raw[4:], 0x5f5e1000)
	binary.LittleEndian.PutUint16(raw[8:], 1)
	binary.LittleEndian.PutUint16(raw[10:], 2)
	binary.LittleEndian.PutUint32(raw[12:], nameRVA)
	binary.LittleEndian.PutUint32(raw[16:], base)
	binary.LittleEndian.PutUint32(raw[20:], uint32(len(entries)))
	binary.LittleEndian.PutUint32(raw[24:], uint32(len(names)))
	binary.LittleEndian.PutUint32(raw[28:], functionsRVA)
	binary.LittleEndian.PutUint32(raw[32:], namesRVA)
	binary.LittleEndian.PutUint32(raw[36:], ordinalsRVA)

	size := uint32(len(m.content) - start)
	m.directories[0] = [2]uint32{directoryRVA, size}
	return exportLayout{
		directoryRVA: directoryRVA,
		size:         size,
		functionsRVA: functionsRVA,
		namesRVA:     namesRVA,
		ordinalsRVA:  ordinalsRVA,
		nameCount:    len(names),
	}
}

func (m *metadataImage) build(t testing.TB) []byte {
	t.Helper()

	optionalSize := 224
	machine := uint16(0x14c)
	characteristics := uint16(0x0102)
	if m.magic == repe.MagicPE32P {
		optionalSize = 240
		machine = 0x8664
		characteristics = 0x0022
	}

	data := make([]byte, metadataHeaderSize, metadataHeaderSize+len(m.content))
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
	binary.LittleEndian.PutUint16(data[optional:], m.magic)
	binary.LittleEndian.PutUint32(data[optional+32:], 0x1000)
	binary.LittleEndian.PutUint32(data[optional+36:], 0x200)
	binary.LittleEndian.PutUint16(data[optional+40:], 6)
	binary.LittleEndian.PutUint16(data[optional+48:], 6)
	binary.LittleEndian.PutUint32(data[optional+56:], 0x2000)
	binary.LittleEndian.PutUint32(data[optional+60:], metadataHeaderSize)
	binary.LittleEndian.PutUint16(data[optional+68:], 3)

	fixedSize := 96
	if m.magic == repe.MagicPE32 {
		binary.LittleEndian.PutUint32(data[optional+28:], 0x400000)
		binary.LittleEndian.PutUint32(data[optional+72:], 0x100000)
		binary.LittleEndian.PutUint32(data[optional+76:], 0x1000)
		binary.LittleEndian.PutUint32(data[optional+80:], 0x100000)
		binary.LittleEndian.PutUint32(data[optional+84:], 0x1000)
		binary.LittleEndian.PutUint32(data[optional+92:], m.directoryCount)
	} else {
		fixedSize = 112
		binary.LittleEndian.PutUint64(data[optional+24:], 0x140000000)
		binary.LittleEndian.PutUint64(data[optional+72:], 0x100000)
		binary.LittleEndian.PutUint64(data[optional+80:], 0x1000)
		binary.LittleEndian.PutUint64(data[optional+88:], 0x100000)
		binary.LittleEndian.PutUint64(data[optional+96:], 0x1000)
		binary.LittleEndian.PutUint32(data[optional+108:], m.directoryCount)
	}

	directories := optional + fixedSize
	for i := 0; i < len(m.directories); i++ {
		binary.LittleEndian.PutUint32(data[directories+i*8:], m.directories[i][0])
		binary.LittleEndian.PutUint32(data[directories+i*8+4:], m.directories[i][1])
	}

	section := optional + optionalSize
	copy(data[section:section+8], ".rdata")
	binary.LittleEndian.PutUint32(data[section+8:], uint32(len(m.content)))
	binary.LittleEndian.PutUint32(data[section+12:], metadataRVA)
	binary.LittleEndian.PutUint32(data[section+16:], uint32(len(m.content)))
	binary.LittleEndian.PutUint32(data[section+20:], metadataRawOffset)
	binary.LittleEndian.PutUint32(data[section+36:], 0x40000040)

	return append(data, m.content...)
}

func parseImage(t testing.TB, image *metadataImage) *repe.File {
	t.Helper()
	return parseImageData(t, image.build(t))
}

func parseImageData(t testing.TB, data []byte) *repe.File {
	t.Helper()

	file, err := repe.Parse(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return file
}

func parseImageWithLimits(t testing.TB, image *metadataImage, limits repe.Limits) *repe.File {
	t.Helper()

	data := image.build(t)
	file, err := repe.ParseWithLimits(bytes.NewReader(data), int64(len(data)), limits)
	if err != nil {
		t.Fatalf("ParseWithLimits() error = %v", err)
	}
	return file
}
