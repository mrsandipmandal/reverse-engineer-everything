package apk

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// buildZIP assembles a stored ZIP from names and contents in insertion order.
func buildZIP(t testing.TB, names []string, contents [][]byte) []byte {
	t.Helper()
	var body bytes.Buffer
	writer := zip.NewWriter(&body)
	for i, name := range names {
		header := &zip.FileHeader{Name: name, Method: zip.Store}
		file, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatalf("create %q: %v", name, err)
		}
		if _, err := file.Write(contents[i]); err != nil {
			t.Fatalf("write %q: %v", name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return body.Bytes()
}

// buildAPK assembles a stored ZIP with a signing block inserted before the
// central directory, the way a signed APK is laid out.
func buildAPK(t testing.TB, names []string, contents [][]byte, block []byte) []byte {
	t.Helper()
	data := buildZIP(t, names, contents)
	if len(block) == 0 {
		return data
	}
	offset := int(binary.LittleEndian.Uint32(data[len(data)-6:]))
	out := make([]byte, 0, len(data)+len(block))
	out = append(out, data[:offset]...)
	out = append(out, block...)
	out = append(out, data[offset:]...)
	binary.LittleEndian.PutUint32(out[len(out)-6:], uint32(offset+len(block)))
	return out
}

// signBlock assembles a signing block from pairs.
func signBlock(pairs ...[2][]byte) []byte {
	area := &bytes.Buffer{}
	for _, pair := range pairs {
		id := binary.LittleEndian.Uint32(pair[0])
		length := uint64(4 + len(pair[1]))
		var field [8]byte
		binary.LittleEndian.PutUint64(field[:], length)
		area.Write(field[:])
		var identity [4]byte
		binary.LittleEndian.PutUint32(identity[:], id)
		area.Write(identity[:])
		area.Write(pair[1])
	}
	declared := uint64(area.Len() + signingBlockFooterBytes)
	var field [8]byte
	binary.LittleEndian.PutUint64(field[:], declared)
	out := append([]byte(nil), field[:]...)
	out = append(out, area.Bytes()...)
	out = append(out, field[:]...)
	return append(out, signingBlockMagic...)
}

// pair assembles one signing pair identifier and value.
func pair(id uint32, value []byte) [2][]byte {
	var field [4]byte
	binary.LittleEndian.PutUint32(field[:], id)
	return [2][]byte{field[:], value}
}

// digest returns the lowercase SHA-256 of data.
func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hexString(sum[:])
}

func hexString(data []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(data)*2)
	for _, b := range data {
		out = append(out, digits[b>>4], digits[b&0x0F])
	}
	return string(out)
}

// standardFiles returns the well-known member layout of one package.
func standardFiles() ([]string, [][]byte) {
	names := []string{
		"AndroidManifest.xml",
		"classes.dex",
		"classes2.dex",
		"resources.arsc",
		"lib/arm64-v8a/libdemo.so",
		"res/layout/main.xml",
		"assets/data.bin",
		"META-INF/CERT.RSA",
		"META-INF/CERT.SF",
		"META-INF/MANIFEST.MF",
		"other.txt",
	}
	contents := [][]byte{
		[]byte("manifest-bytes"),
		[]byte("dex-one"),
		[]byte("dex-two"),
		[]byte("arsc"),
		[]byte("so"),
		[]byte("layout"),
		[]byte("asset"),
		[]byte("rsa"),
		[]byte("sf"),
		[]byte("mf"),
		[]byte("other"),
	}
	return names, contents
}

// parseAPK parses an in-memory package with the package limits.
func parseAPK(t testing.TB, data []byte) *APK {
	t.Helper()
	parsed, err := Parse(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed == nil {
		t.Fatal("Parse returned a nil APK without an error")
	}
	return parsed
}

// findEntry returns the classification index of name.
func findEntry(t testing.TB, parsed *APK, name string) int {
	t.Helper()
	for index := range parsed.ZIP.Entries {
		if parsed.ZIP.Entries[index].Name == name {
			return index
		}
	}
	t.Fatalf("entry %q is missing", name)
	return -1
}
