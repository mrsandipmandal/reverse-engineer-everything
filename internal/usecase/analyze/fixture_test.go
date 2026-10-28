package analyze

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// minimalELF64 is a valid ELF64 little-endian header with no sections, no
// segments, and no symbol table. The reader accepts it with complete coverage.
func minimalELF64() []byte {
	data := make([]byte, 64)
	copy(data[0:4], "\x7fELF")
	data[4] = 2                                    // ELFCLASS64
	data[5] = 1                                    // ELFDATA2LSB
	data[6] = 1                                    // EV_CURRENT
	binary.LittleEndian.PutUint16(data[16:], 2)    // ET_EXEC
	binary.LittleEndian.PutUint16(data[18:], 0x3e) // EM_X86_64
	binary.LittleEndian.PutUint32(data[20:], 1)    // e_version
	binary.LittleEndian.PutUint16(data[52:], 64)   // e_ehsize
	return data
}

// minimalPE32 is a valid 512-byte PE32 image with one optional header, no data
// directories, and no sections. SizeOfHeaders covers the whole file, so the
// reader reports no overlay and complete coverage.
func minimalPE32() []byte {
	const (
		peOffset  = 0x80
		coffSize  = 20
		optOffset = peOffset + 4 + coffSize
		flags     = 0x0102 // executable image, 32-bit
	)
	data := make([]byte, 512)
	binary.LittleEndian.PutUint16(data[0:], 0x5a4d) // MZ
	binary.LittleEndian.PutUint32(data[0x3c:], peOffset)

	copy(data[peOffset:], "PE\x00\x00")
	coff := data[peOffset+4:]
	binary.LittleEndian.PutUint16(coff[0:], 0x14c) // IMAGE_FILE_MACHINE_I386
	binary.LittleEndian.PutUint16(coff[2:], 0)     // NumberOfSections
	binary.LittleEndian.PutUint16(coff[16:], 96)   // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(coff[18:], flags)

	opt := data[optOffset:]
	binary.LittleEndian.PutUint16(opt[0:], 0x10b)     // PE32
	binary.LittleEndian.PutUint32(opt[28:], 0x400000) // ImageBase
	binary.LittleEndian.PutUint32(opt[32:], 0x1000)   // SectionAlignment
	binary.LittleEndian.PutUint32(opt[36:], 0x200)    // FileAlignment
	binary.LittleEndian.PutUint32(opt[56:], 0x1000)   // SizeOfImage
	binary.LittleEndian.PutUint32(opt[60:], 0x200)    // SizeOfHeaders
	binary.LittleEndian.PutUint16(opt[68:], 3)        // Subsystem
	binary.LittleEndian.PutUint32(opt[92:], 0)        // NumberOfRvaAndSizes
	return data
}

// writeArtifact writes data to a uniquely named file under the test's temporary
// directory and returns its path.
func writeArtifact(t testing.TB, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture %q: %v", name, err)
	}
	return path
}

// writeTempPath returns a path inside the test's temporary directory that does
// not exist yet.
func writeTempPath(t testing.TB, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}
