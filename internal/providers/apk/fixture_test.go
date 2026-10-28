package apk

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
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

// buildAPK inserts a signing block before the ZIP central directory.
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

// signBlock assembles a signing block from identity and value pairs.
func signBlock(pairs ...[2][]byte) []byte {
	area := &bytes.Buffer{}
	for _, pair := range pairs {
		var length [8]byte
		binary.LittleEndian.PutUint64(length[:], uint64(4+len(pair[1])))
		area.Write(length[:])
		area.Write(pair[0])
		area.Write(pair[1])
	}
	declared := uint64(area.Len() + 24)
	var field [8]byte
	binary.LittleEndian.PutUint64(field[:], declared)
	out := append([]byte(nil), field[:]...)
	out = append(out, area.Bytes()...)
	out = append(out, field[:]...)
	return append(out, "APK Sig Block 42"...)
}

// pair assembles one signing pair identity and value.
func pair(id uint32, value []byte) [2][]byte {
	var field [4]byte
	binary.LittleEndian.PutUint32(field[:], id)
	return [2][]byte{field[:], value}
}

// digest returns the lowercase SHA-256 of data.
func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// standardFiles returns the well-known member layout of one package.
func standardFiles() ([]string, [][]byte) {
	names := []string{
		"AndroidManifest.xml",
		"classes.dex",
		"resources.arsc",
		"lib/arm64-v8a/libdemo.so",
		"res/layout/main.xml",
		"META-INF/CERT.RSA",
	}
	contents := [][]byte{
		[]byte("manifest-bytes"),
		[]byte("dex-one"),
		[]byte("arsc"),
		[]byte("so"),
		[]byte("layout"),
		[]byte("rsa"),
	}
	return names, contents
}

// assetFiles returns a package with count extra asset entries.
func assetFiles(_ testing.TB, count int) ([]string, [][]byte) {
	names, contents := standardFiles()
	for i := 0; i < count; i++ {
		names = append(names, "assets/file"+string(rune('a'+i%26))+".bin")
		contents = append(contents, []byte("asset"))
	}
	return names, contents
}

// observeBytes observes an in-memory package with the default options.
func observeBytes(t testing.TB, data []byte) evidence.Evidence {
	t.Helper()
	record, err := Observe(bytes.NewReader(data), int64(len(data)), Options{ProviderVersion: "1.0.0"})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	return record
}

// decodePayload decodes a sealed record payload.
func decodePayload(t testing.TB, record evidence.Evidence) Payload {
	t.Helper()
	var payload Payload
	if err := json.Unmarshal(record.Payload, &payload); err != nil {
		t.Fatalf("payload: %v", err)
	}
	return payload
}
