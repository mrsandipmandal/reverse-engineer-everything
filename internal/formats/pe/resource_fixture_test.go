package pe_test

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"

	repe "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/pe"
)

// resourceLeaf is one resource data entry with its declared contents.
type resourceLeaf struct {
	blob     []byte
	codePage uint32
}

// resourceChild is a named or integer child of a resource directory. Exactly
// one of dir and leaf is set.
type resourceChild struct {
	id   uint32
	name string
	dir  *resourceDir
	leaf *resourceLeaf
}

// resourceDir is a resource directory node.
type resourceDir struct {
	children []resourceChild
}

// addResources lays out a resource tree at the end of the image content,
// including named strings, data entries, and leaf blobs, and points the
// resource directory at it. Directory entries keep their declaration order,
// with named children before integer children as the format requires.
func (m *metadataImage) addResources(root *resourceDir) uint32 {
	m.align()
	base := uint32(metadataRVA + len(m.content))

	directories := make([]*resourceDir, 0, 8)
	var collect func(*resourceDir)
	collect = func(directory *resourceDir) {
		directories = append(directories, directory)
		for _, child := range directory.children {
			if child.dir != nil {
				collect(child.dir)
			}
		}
	}
	collect(root)

	offsets := make(map[*resourceDir]uint32, len(directories))
	cursor := uint32(0)
	for _, directory := range directories {
		offsets[directory] = cursor
		cursor += resourceDirectoryHeader + resourceEntryBytes*uint32(len(directory.children))
	}

	nameOffsets := make(map[string]uint32, 4)
	var nameOrder []string
	for _, directory := range directories {
		for _, child := range directory.children {
			if child.name == "" {
				continue
			}
			if _, ok := nameOffsets[child.name]; ok {
				continue
			}
			nameOffsets[child.name] = cursor
			cursor += 2 + 2*uint32(len(utf16.Encode([]rune(child.name))))
			nameOrder = append(nameOrder, child.name)
		}
	}

	leafEntries := make(map[*resourceLeaf]uint32, 4)
	for _, directory := range directories {
		for _, child := range directory.children {
			if child.leaf == nil {
				continue
			}
			leafEntries[child.leaf] = cursor
			cursor += resourceDataEntryBytes
		}
	}
	leafBlobs := make(map[*resourceLeaf]uint32, 4)
	for _, directory := range directories {
		for _, child := range directory.children {
			if child.leaf == nil {
				continue
			}
			leafBlobs[child.leaf] = cursor
			cursor += uint32(len(child.leaf.blob))
		}
	}

	raw := make([]byte, cursor)
	for _, directory := range directories {
		offset := offsets[directory]
		named := make([]resourceChild, 0, len(directory.children))
		identified := make([]resourceChild, 0, len(directory.children))
		for _, child := range directory.children {
			if child.name != "" {
				named = append(named, child)
			} else {
				identified = append(identified, child)
			}
		}
		binary.LittleEndian.PutUint16(raw[offset+12:], uint16(len(named)))
		binary.LittleEndian.PutUint16(raw[offset+14:], uint16(len(identified)))

		position := offset + resourceDirectoryHeader
		for _, child := range append(named, identified...) {
			var nameField uint32
			if child.name != "" {
				nameField = resourceSubdirectoryFlag | nameOffsets[child.name]
			} else {
				nameField = child.id
			}
			var offsetField uint32
			if child.dir != nil {
				offsetField = resourceSubdirectoryFlag | offsets[child.dir]
			} else {
				offsetField = leafEntries[child.leaf]
			}
			binary.LittleEndian.PutUint32(raw[position:], nameField)
			binary.LittleEndian.PutUint32(raw[position+4:], offsetField)
			position += resourceEntryBytes
		}
	}

	for _, name := range nameOrder {
		offset := nameOffsets[name]
		units := utf16.Encode([]rune(name))
		binary.LittleEndian.PutUint16(raw[offset:], uint16(len(units)))
		for i, unit := range units {
			binary.LittleEndian.PutUint16(raw[offset+2+uint32(i)*2:], unit)
		}
	}

	for leaf, offset := range leafEntries {
		binary.LittleEndian.PutUint32(raw[offset:], base+leafBlobs[leaf])
		binary.LittleEndian.PutUint32(raw[offset+4:], uint32(len(leaf.blob)))
		binary.LittleEndian.PutUint32(raw[offset+8:], leaf.codePage)
	}
	for leaf, offset := range leafBlobs {
		copy(raw[offset:], leaf.blob)
	}

	m.content = append(m.content, raw...)
	m.directories[2] = [2]uint32{base, uint32(len(raw))}
	return base
}

const (
	resourceDirectoryHeader  = 16
	resourceEntryBytes       = 8
	resourceDataEntryBytes   = 16
	resourceSubdirectoryFlag = 0x80000000
)

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

// appendCertificateTable appends records to the artifact at an eight-byte
// boundary and returns the new artifact plus the table offset and size.
func appendCertificateTable(data []byte, records ...[]byte) ([]byte, uint64, uint32) {
	for len(data)%8 != 0 {
		data = append(data, 0)
	}
	offset := len(data)
	for _, record := range records {
		data = append(data, record...)
	}
	return data, uint64(offset), uint32(len(data) - offset)
}

// setSecurityDirectory writes the security directory, which stores a file
// offset rather than an RVA.
func setSecurityDirectory(data []byte, magic uint16, offset uint64, size uint32) {
	fixed := 96
	if magic == repe.MagicPE32P {
		fixed = 112
	}
	at := 0x98 + fixed + 4*8
	binary.LittleEndian.PutUint32(data[at:], uint32(offset))
	binary.LittleEndian.PutUint32(data[at+4:], size)
}

func buildResourceImage(t testing.TB, magic uint16, root *resourceDir) *metadataImage {
	t.Helper()

	image := newMetadataImage(magic)
	image.addResources(root)
	return image
}
