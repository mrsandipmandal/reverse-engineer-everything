package cli

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeCLIFixture writes data to a temporary path with the given name.
func writeCLIFixture(t testing.TB, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// cliZIP builds a stored ZIP from alternating name and body arguments, in
// the order given, so the inventory order stays deterministic.
func cliZIP(t testing.TB, pairs ...string) []byte {
	t.Helper()
	if len(pairs)%2 != 0 {
		t.Fatalf("cliZIP needs name and body pairs, got %d arguments", len(pairs))
	}
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for i := 0; i < len(pairs); i += 2 {
		entry, err := writer.CreateHeader(&zip.FileHeader{Name: pairs[i], Method: zip.Store})
		if err != nil {
			t.Fatalf("create %s: %v", pairs[i], err)
		}
		if _, err := entry.Write([]byte(pairs[i+1])); err != nil {
			t.Fatalf("write %s: %v", pairs[i], err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

// cliAPK builds a stored ZIP with a root manifest and one DEX file.
func cliAPK(t testing.TB) []byte {
	t.Helper()
	return cliZIP(t,
		"AndroidManifest.xml", "\x03\x00\x08\x00",
		"classes.dex", "dex\n035\x00",
	)
}

// cliASAR builds a minimal ASAR with one file.
func cliASAR(t testing.TB) []byte {
	t.Helper()
	directory, err := json.Marshal(map[string]any{
		"files": map[string]any{"a.txt": map[string]any{"size": 2, "offset": 0}},
	})
	if err != nil {
		t.Fatalf("marshal directory: %v", err)
	}
	padded := (len(directory) + 3) &^ 3
	var buf bytes.Buffer
	var header [16]byte
	binary.LittleEndian.PutUint32(header[0:], 4)
	binary.LittleEndian.PutUint32(header[4:], uint32(8+padded))
	binary.LittleEndian.PutUint32(header[8:], uint32(padded))
	binary.LittleEndian.PutUint32(header[12:], uint32(len(directory)))
	buf.Write(header[:])
	buf.Write(directory)
	buf.Write(make([]byte, padded-len(directory)))
	buf.WriteString("hi")
	return buf.Bytes()
}

// cliPlist is an XML property list with two string values.
func cliPlist() []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>name</key><string>demo</string>
	<key>host</key><string>example.test</string>
</dict>
</plist>`)
}
