package analyze

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
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

// minimalMachO64 is a valid 64-bit little-endian Mach-O header with no load
// commands, no segments, and no sections. The reader accepts it with complete
// coverage.
func minimalMachO64() []byte {
	data := make([]byte, 32)
	binary.LittleEndian.PutUint32(data[0:], 0xfeedfacf) // MH_MAGIC_64
	binary.LittleEndian.PutUint32(data[4:], 0x01000007) // CPU_TYPE_X86_64
	binary.LittleEndian.PutUint32(data[8:], 3)          // CPU_SUBTYPE_X86_64_ALL
	binary.LittleEndian.PutUint32(data[12:], 2)         // MH_EXECUTE
	return data
}

// minimalFatMachO wraps images in a 32-bit universal header. Each slice starts
// at the next 4 KiB boundary so the declared alignment matches the layout.
func minimalFatMachO(images ...[]byte) []byte {
	const entrySize = 20
	offsets := make([]int, len(images))
	total := 8 + len(images)*entrySize
	for i, image := range images {
		if total%0x1000 != 0 {
			total += 0x1000 - total%0x1000
		}
		offsets[i] = total
		total += len(image)
	}
	data := make([]byte, total)
	binary.BigEndian.PutUint32(data[0:], 0xcafebabe) // FAT_MAGIC
	binary.BigEndian.PutUint32(data[4:], uint32(len(images)))
	for i, image := range images {
		entry := data[8+i*entrySize:]
		binary.BigEndian.PutUint32(entry[0:], 0x01000007) // CPU_TYPE_X86_64
		binary.BigEndian.PutUint32(entry[4:], 3)          // CPU_SUBTYPE_X86_64_ALL
		binary.BigEndian.PutUint32(entry[8:], uint32(offsets[i]))
		binary.BigEndian.PutUint32(entry[12:], uint32(len(image)))
		binary.BigEndian.PutUint32(entry[16:], 12) // 2^12 alignment
		copy(data[offsets[i]:], image)
	}
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

// minimalZIP returns a stored-method ZIP archive with one text file.
func minimalZIP(t testing.TB) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	file, err := writer.CreateHeader(&zip.FileHeader{Name: "hello.txt", Method: zip.Store})
	if err != nil {
		t.Fatalf("create zip member: %v", err)
	}
	if _, err := file.Write([]byte("hi")); err != nil {
		t.Fatalf("write zip member: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

// minimalAPK returns a ZIP package with the two members that identify an
// Android package. Neither member is decoded, so their content is arbitrary.
func minimalAPK(t testing.TB) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for name, body := range map[string][]byte{
		"AndroidManifest.xml": {0x03, 0x00, 0x08, 0x00},
		"classes.dex":         []byte("dex\n035\x00"),
	} {
		file, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatalf("create apk member %q: %v", name, err)
		}
		if _, err := file.Write(body); err != nil {
			t.Fatalf("write apk member %q: %v", name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close apk: %v", err)
	}
	return buf.Bytes()
}

// minimalTar returns a ustar archive with one text file.
func minimalTar(t testing.TB) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)
	body := []byte("hi")
	if err := writer.WriteHeader(&tar.Header{
		Name:     "hello.txt",
		Mode:     0o644,
		Size:     int64(len(body)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatalf("write tar body: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

// minimalGZip returns a single-member gzip stream.
func minimalGZip(t testing.TB) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	writer.Name = "hello.txt"
	if _, err := writer.Write([]byte("hi")); err != nil {
		t.Fatalf("write gzip body: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

// minimalASAR returns an ASAR with one packed file. The directory is padded to
// a four-byte boundary, as the Chromium Pickle writer does.
func minimalASAR(t testing.TB) []byte {
	t.Helper()
	directory, err := json.Marshal(map[string]any{
		"files": map[string]any{"a.txt": map[string]any{"size": 5, "offset": 0}},
	})
	if err != nil {
		t.Fatalf("marshal asar directory: %v", err)
	}
	aligned := (len(directory) + 3) / 4 * 4
	var buf bytes.Buffer
	var fixed [16]byte
	order := binary.LittleEndian
	order.PutUint32(fixed[0:], 4)
	order.PutUint32(fixed[4:], uint32(8+aligned))
	order.PutUint32(fixed[8:], uint32(aligned))
	order.PutUint32(fixed[12:], uint32(len(directory)))
	buf.Write(fixed[:])
	buf.Write(directory)
	buf.Write(make([]byte, aligned-len(directory)))
	buf.WriteString("hello")
	return buf.Bytes()
}

// minimalPlistXML returns an XML property list with a dictionary root.
func minimalPlistXML() []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>name</key><string>demo</string>
	<key>count</key><integer>3</integer>
</dict>
</plist>`)
}
