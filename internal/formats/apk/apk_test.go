package apk

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/archive"
)

func TestParseAPKInventory(t *testing.T) {
	names, contents := standardFiles()
	parsed := parseAPK(t, buildZIP(t, names, contents))

	if parsed.Truncated || len(parsed.Limitations) != 0 {
		t.Fatalf("truncated=%v limitations=%v", parsed.Truncated, parsed.Limitations)
	}
	if parsed.Size() != int64(len(buildZIP(t, names, contents))) {
		t.Fatal("Size does not report the artifact size")
	}
	if len(parsed.Entries) != len(parsed.ZIP.Entries) {
		t.Fatalf("classifications = %d, ZIP entries = %d",
			len(parsed.Entries), len(parsed.ZIP.Entries))
	}

	wants := map[string]Kind{
		"AndroidManifest.xml":      KindManifest,
		"classes.dex":              KindDEX,
		"classes2.dex":             KindDEX,
		"resources.arsc":           KindResources,
		"lib/arm64-v8a/libdemo.so": KindNativeLibrary,
		"res/layout/main.xml":      KindResource,
		"assets/data.bin":          KindAsset,
		"META-INF/CERT.RSA":        KindSignature,
		"META-INF/CERT.SF":         KindSignature,
		"META-INF/MANIFEST.MF":     KindOther,
		"other.txt":                KindOther,
	}
	for name, want := range wants {
		index := findEntry(t, parsed, name)
		if got := parsed.Entries[index].Kind; got != want {
			t.Fatalf("%s kind = %v, want %v", name, got, want)
		}
	}
	if abi := parsed.Entries[findEntry(t, parsed, "lib/arm64-v8a/libdemo.so")].ABI; abi != "arm64-v8a" {
		t.Fatalf("ABI = %q", abi)
	}
	if abi := parsed.Entries[findEntry(t, parsed, "classes.dex")].ABI; abi != "" {
		t.Fatalf("dex ABI = %q", abi)
	}

	for _, name := range []string{"AndroidManifest.xml", "classes.dex", "classes2.dex", "resources.arsc"} {
		index := findEntry(t, parsed, name)
		entry := parsed.Entries[index]
		if !entry.DigestAvailable {
			t.Fatalf("%s digest is unavailable: %v", name, entry.Limitations)
		}
		if want := digest(contents[index]); entry.Digest != want {
			t.Fatalf("%s digest = %q, want %q", name, entry.Digest, want)
		}
	}
	for _, name := range []string{"assets/data.bin", "other.txt", "META-INF/CERT.RSA"} {
		if entry := parsed.Entries[findEntry(t, parsed, name)]; entry.DigestAvailable {
			t.Fatalf("%s digest was computed", name)
		}
	}
	if parsed.Signing.Present {
		t.Fatal("unsigned package reports a signing block")
	}
}

func TestParseSigningBlock(t *testing.T) {
	names, contents := standardFiles()
	value2 := []byte("v2-signature-value")
	value3 := []byte("v3-signature-value")
	unknown := []byte{1, 2, 3}
	block := signBlock(
		pair(idV2, value2),
		pair(idV3, value3),
		pair(idV31, []byte("v31")),
		pair(idSourceStamp, []byte("stamp")),
		pair(idVerityPad, []byte("pad")),
		pair(0x12345678, unknown),
	)
	data := buildAPK(t, names, contents, block)
	parsed := parseAPK(t, data)

	signing := parsed.Signing
	if !signing.Present || signing.Truncated {
		t.Fatalf("signing = %#v", signing)
	}
	if signing.Size != uint64(len(block)) {
		t.Fatalf("size = %d, want %d", signing.Size, len(block))
	}
	cdOffset := int(binary.LittleEndian.Uint32(data[len(data)-6:]))
	if int(signing.Offset) != cdOffset-len(block) {
		t.Fatalf("offset = %d, want %d", signing.Offset, cdOffset-len(block))
	}
	if len(signing.Pairs) != 6 {
		t.Fatalf("pairs = %d", len(signing.Pairs))
	}
	schemes := []string{"v2", "v3", "v3.1", "source_stamp", "verity_padding", ""}
	for i, want := range schemes {
		if got := signing.Pairs[i].Scheme; got != want {
			t.Fatalf("pair %d scheme = %q, want %q", i, got, want)
		}
	}
	if got := signing.Pairs[0]; !got.DigestAvailable || got.Digest != digest(value2) ||
		got.ValueBytes != uint64(len(value2)) || got.ID != idV2 {
		t.Fatalf("v2 pair = %#v", got)
	}
	if got := signing.Pairs[5]; got.Digest != digest(unknown) || got.ID != 0x12345678 {
		t.Fatalf("unknown pair = %#v", got)
	}
	if parsed.Truncated {
		t.Fatal("signing block truncates an otherwise complete package")
	}
}

func TestParseSigningBlockLimits(t *testing.T) {
	names, contents := standardFiles()
	block := signBlock(
		pair(idV2, []byte("one")),
		pair(idV3, []byte("two")),
		pair(0x12345678, []byte("three")),
	)
	data := buildAPK(t, names, contents, block)

	parsed, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{SigningPairs: 2})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !parsed.Signing.Truncated || len(parsed.Signing.Pairs) != 2 {
		t.Fatalf("signing = %#v", parsed.Signing)
	}
	if !parsed.Truncated {
		t.Fatal("signing truncation did not truncate the package")
	}
	if !hasLimitation(parsed.Limitations, "signing pair limit 2 reached") {
		t.Fatalf("limitations = %v", parsed.Limitations)
	}

	parsed, err = ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{SigningBytes: 15})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !parsed.Signing.Truncated || len(parsed.Signing.Pairs) != 1 {
		t.Fatalf("signing = %#v", parsed.Signing)
	}
	if !hasLimitation(parsed.Signing.Limitations, "signing block pair area exceeds 15 bytes") {
		t.Fatalf("signing limitations = %v", parsed.Signing.Limitations)
	}
}

func TestParseSigningBlockInvalid(t *testing.T) {
	names, contents := standardFiles()
	block := signBlock(pair(idV2, []byte("value")))
	data := buildAPK(t, names, contents, block)
	cdOffset := int(binary.LittleEndian.Uint32(data[len(data)-6:]))
	blockStart := cdOffset - len(block)

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "head size",
			data: patch(data, blockStart, []byte{0, 0, 0, 0, 0, 0, 0, 9}),
		},
		{
			name: "size below footer",
			data: patch(data, cdOffset-24, []byte{0, 0, 0, 0, 0, 0, 0, 4}),
		},
		{
			name: "size past directory",
			data: patch(data, cdOffset-24, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F}),
		},
		{
			name: "pair length below identity",
			data: patch(data, blockStart+8, []byte{2, 0, 0, 0, 0, 0, 0, 0}),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := Parse(bytes.NewReader(test.data), int64(len(test.data)))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
			if parsed != nil {
				t.Fatal("APK returned with an error")
			}
		})
	}
}

func TestParseSigningBlockPairOutside(t *testing.T) {
	names, contents := standardFiles()
	block := signBlock(pair(idV2, []byte("value")))
	data := buildAPK(t, names, contents, block)
	cdOffset := int(binary.LittleEndian.Uint32(data[len(data)-6:]))
	blockStart := cdOffset - len(block)
	data = patch(data, blockStart+8, []byte{0, 0, 0, 0, 0, 0, 0xFF, 0xFF})

	if _, err := Parse(bytes.NewReader(data), int64(len(data))); !errors.Is(err, ErrTruncated) {
		t.Fatalf("error = %v, want ErrTruncated", err)
	}
}

func TestParseSigningBlockPartialPair(t *testing.T) {
	names, contents := standardFiles()
	block := signBlock(pair(idV2, []byte("0123456789")))
	data := buildAPK(t, names, contents, block)
	parsed, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{SigningBytes: 6})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !parsed.Signing.Truncated || len(parsed.Signing.Pairs) != 0 {
		t.Fatalf("signing = %#v", parsed.Signing)
	}
	if !hasLimitation(parsed.Signing.Limitations, "signing block ends inside a pair length") {
		t.Fatalf("limitations = %v", parsed.Signing.Limitations)
	}
}

func TestParseErrors(t *testing.T) {
	names, contents := standardFiles()
	tarLike := append([]byte("some tar bytes"), make([]byte, 300)...)
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"empty", nil, ErrTruncated},
		{"garbage", []byte("not a zip archive"), ErrInvalid},
		{"tar", tarLike, ErrInvalid},
		{"no manifest", buildZIP(t, []string{"classes.dex"}, [][]byte{[]byte("dex")}), ErrInvalid},
		{"manifest directory", buildZIP(t, []string{"AndroidManifest.xml/"}, [][]byte{nil}), ErrInvalid},
		{"manifest below root", buildZIP(t, []string{"assets/AndroidManifest.xml"}, [][]byte{[]byte("x")}), ErrInvalid},
		{"truncated", buildZIP(t, names, contents)[:20], ErrTruncated},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := Parse(bytes.NewReader(test.data), int64(len(test.data)))
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if parsed != nil {
				t.Fatal("APK returned with an error")
			}
		})
	}
}

func TestParseNilNegativeAndLimit(t *testing.T) {
	if _, err := Parse(nil, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil error = %v", err)
	}
	if _, err := Parse(bytes.NewReader(nil), -1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("negative error = %v", err)
	}
	names, contents := standardFiles()
	data := buildZIP(t, names, contents)
	if _, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{ArtifactBytes: 16}); !errors.Is(err, ErrLimit) {
		t.Fatalf("limit error = %v", err)
	}
}

func TestParseEntryLimitTruncates(t *testing.T) {
	names, contents := standardFiles()
	data := buildZIP(t, names, contents)
	parsed, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{Entries: 2})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !parsed.Truncated {
		t.Fatal("entry limit did not truncate")
	}
	if len(parsed.ZIP.Entries) != 2 || len(parsed.Entries) != 2 {
		t.Fatalf("entries = %d/%d", len(parsed.ZIP.Entries), len(parsed.Entries))
	}
	if len(parsed.Limitations) == 0 {
		t.Fatal("entry limit recorded no limitation")
	}
}

func TestParseDigestLimits(t *testing.T) {
	names, contents := standardFiles()
	data := buildZIP(t, names, contents)

	parsed, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{DigestBytes: 4})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	manifest := parsed.Entries[findEntry(t, parsed, "AndroidManifest.xml")]
	if manifest.DigestAvailable {
		t.Fatal("manifest was hashed above the digest limit")
	}
	if !hasLimitation(manifest.Limitations, "content digest skipped: declared size exceeds 4 bytes") {
		t.Fatalf("manifest limitations = %v", manifest.Limitations)
	}
	if !hasLimitation(parsed.Limitations, `content digest is unavailable for "AndroidManifest.xml"`) {
		t.Fatalf("limitations = %v", parsed.Limitations)
	}

	parsed, err = ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{TotalDigestBytes: 10})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !parsed.Entries[findEntry(t, parsed, "AndroidManifest.xml")].DigestAvailable {
		t.Fatal("first digest was skipped under the aggregate limit")
	}
	second := parsed.Entries[findEntry(t, parsed, "classes.dex")]
	if second.DigestAvailable {
		t.Fatal("second digest exceeded the aggregate limit")
	}
	if !hasLimitation(parsed.Limitations, "content digest limit 10 reached") {
		t.Fatalf("limitations = %v", parsed.Limitations)
	}
}

func TestParseDigestUnavailable(t *testing.T) {
	names := []string{"AndroidManifest.xml"}
	contents := [][]byte{[]byte("manifest")}
	data := buildZIP(t, names, contents)
	// Mark every entry encrypted in the local and central headers so the ZIP
	// reader refuses the content without decoding it.
	cdOffset := int(binary.LittleEndian.Uint32(data[len(data)-6:]))
	for pos := 0; pos+4 <= cdOffset; pos++ {
		if string(data[pos:pos+4]) == "PK\x03\x04" {
			flag := binary.LittleEndian.Uint16(data[pos+6:])
			binary.LittleEndian.PutUint16(data[pos+6:], flag|1)
		}
	}
	for pos := cdOffset; pos+4 <= len(data); pos++ {
		if string(data[pos:pos+4]) == "PK\x01\x02" {
			flag := binary.LittleEndian.Uint16(data[pos+8:])
			binary.LittleEndian.PutUint16(data[pos+8:], flag|1)
		}
	}
	parsed, err := Parse(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	entry := parsed.Entries[0]
	if entry.DigestAvailable {
		t.Fatal("encrypted member was hashed")
	}
	if !hasLimitation(entry.Limitations, "content digest unavailable: content is unavailable") {
		t.Fatalf("limitations = %v", entry.Limitations)
	}
}

func TestParseDuplicateManifest(t *testing.T) {
	names := []string{"AndroidManifest.xml", "./AndroidManifest.xml"}
	contents := [][]byte{[]byte("one"), []byte("two")}
	// "./AndroidManifest.xml" is not the root name, so the duplicate is a
	// second root-level manifest with the same decoded name after cleaning is
	// not performed by the reader.
	parsed := parseAPK(t, buildZIP(t, names, contents))
	if got := parsed.Entries[0].Kind; got != KindManifest {
		t.Fatalf("first kind = %v", got)
	}
	if got := parsed.Entries[1].Kind; got != KindOther {
		t.Fatalf("dotted kind = %v", got)
	}
	names = []string{"AndroidManifest.xml", "AndroidManifest.xml"}
	parsed = parseAPK(t, buildZIP(t, names, contents))
	if !hasLimitation(parsed.Limitations, "2 AndroidManifest.xml entries; the first is reported") {
		t.Fatalf("limitations = %v", parsed.Limitations)
	}
}

func TestLimitsDefaultsAndClamping(t *testing.T) {
	defaults := DefaultLimits()
	if defaults != (Limits{
		ArtifactBytes:    MaxArtifactBytes,
		Entries:          MaxEntries,
		SigningBytes:     MaxSigningBytes,
		SigningPairs:     MaxSigningPairs,
		DigestBytes:      MaxDigestBytes,
		TotalDigestBytes: MaxTotalDigestBytes,
	}) {
		t.Fatalf("defaults = %#v", defaults)
	}
	clamped := Limits{
		ArtifactBytes:    MaxArtifactBytes + 1,
		Entries:          MaxEntries + 1,
		SigningBytes:     MaxSigningBytes + 1,
		SigningPairs:     MaxSigningPairs + 1,
		DigestBytes:      MaxDigestBytes + 1,
		TotalDigestBytes: MaxTotalDigestBytes + 1,
	}.withDefaults()
	if clamped != defaults {
		t.Fatalf("clamped = %#v", clamped)
	}
	if zero := (Limits{}).withDefaults(); zero != defaults {
		t.Fatalf("zero = %#v", zero)
	}
	if lowered := (Limits{Entries: 5, SigningPairs: 3}).withDefaults(); lowered.Entries != 5 || lowered.SigningPairs != 3 {
		t.Fatalf("lowered = %#v", lowered)
	}
}

func TestKindString(t *testing.T) {
	kinds := map[Kind]string{
		KindOther:         "other",
		KindManifest:      "manifest",
		KindDEX:           "dex",
		KindResources:     "resources",
		KindNativeLibrary: "native_library",
		KindResource:      "resource",
		KindAsset:         "asset",
		KindSignature:     "signature",
	}
	for kind, want := range kinds {
		if got := kind.String(); got != want {
			t.Fatalf("Kind(%d) = %q, want %q", kind, got, want)
		}
	}
}

func TestClassifyNames(t *testing.T) {
	tests := []struct {
		name string
		kind Kind
		abi  string
	}{
		{"AndroidManifest.xml", KindManifest, ""},
		{"resources.arsc", KindResources, ""},
		{"classes.dex", KindDEX, ""},
		{"classes10.dex", KindDEX, ""},
		{"classes.dex.bak", KindOther, ""},
		{"sub/classes.dex", KindOther, ""},
		{"classes", KindOther, ""},
		{"lib/x86_64/liba.so", KindNativeLibrary, "x86_64"},
		{"lib/liba.so", KindNativeLibrary, ""},
		{"lib/x86/liba.dll", KindOther, ""},
		{"res/values/strings.xml", KindResource, ""},
		{"assets/index.html", KindAsset, ""},
		{"META-INF/CERT.EC", KindSignature, ""},
		{"META-INF/cert.rsa", KindSignature, ""},
		{"META-INF/MANIFEST.MF", KindOther, ""},
		{"META-INF/", KindOther, ""},
		{"kotlin/kotlin.kotlin_builtins", KindOther, ""},
	}
	for _, test := range tests {
		value := entryFor{name: test.name}
		got := classify(value.entry())
		if got.Kind != test.kind || got.ABI != test.abi {
			t.Fatalf("classify(%q) = %v/%q, want %v/%q",
				test.name, got.Kind, got.ABI, test.kind, test.abi)
		}
	}
}

func TestFindEndRecordComment(t *testing.T) {
	names, contents := standardFiles()
	data := buildZIP(t, names, contents)
	record, ok := findEndRecord(bytes.NewReader(data), int64(len(data)))
	if !ok {
		t.Fatal("end record not found")
	}
	if want := int64(len(data)) - 22; record.offset != want {
		t.Fatalf("offset = %d, want %d", record.offset, want)
	}
	if record.cdOffset <= 0 || record.cdOffset >= int64(len(data)) {
		t.Fatalf("central directory offset = %d", record.cdOffset)
	}

	comment := []byte("built by a test")
	withComment := append(append([]byte(nil), data...), comment...)
	binary.LittleEndian.PutUint16(withComment[len(data)-2:], uint16(len(comment)))
	record, ok = findEndRecord(bytes.NewReader(withComment), int64(len(withComment)))
	if !ok {
		t.Fatal("end record with a comment not found")
	}
	if record.offset != int64(len(data))-22 {
		t.Fatalf("offset with comment = %d", record.offset)
	}

	if _, ok := findEndRecord(bytes.NewReader([]byte("PK")), 2); ok {
		t.Fatal("short artifact reported an end record")
	}
	if _, ok := findEndRecord(failingReader{}, int64(len(data))); ok {
		t.Fatal("failing reader reported an end record")
	}
}

func TestZIP64CentralDirectory(t *testing.T) {
	const (
		endOffset     = 20
		locatorOffset = endOffset + 56
		recordOffset  = locatorOffset + 20
		totalSize     = recordOffset + 22
	)
	data := make([]byte, totalSize)
	copy(data[endOffset:], "PK\x06\x06")
	binary.LittleEndian.PutUint64(data[endOffset+40:], 4)
	binary.LittleEndian.PutUint64(data[endOffset+48:], 8)
	copy(data[locatorOffset:], "PK\x06\x07")
	binary.LittleEndian.PutUint64(data[locatorOffset+8:], endOffset)
	copy(data[recordOffset:], "PK\x05\x06")
	binary.LittleEndian.PutUint32(data[recordOffset+12:], 0xFFFFFFFF)
	binary.LittleEndian.PutUint32(data[recordOffset+16:], 0xFFFFFFFF)

	record, ok := findEndRecord(bytes.NewReader(data), totalSize)
	if !ok {
		t.Fatal("end record not found")
	}
	offset, ok := centralDirectoryOffset(bytes.NewReader(data), totalSize)
	if !ok || offset != 8 {
		t.Fatalf("offset = %d, ok = %v", offset, ok)
	}
	_, ok = zip64CentralDirectoryOffset(bytes.NewReader(data), totalSize, endRecord{offset: 0})
	if ok {
		t.Fatal("missing locator reported a central directory")
	}
	bad := append([]byte(nil), data...)
	copy(bad[endOffset:], "PK\x06\x07")
	if _, ok := zip64CentralDirectoryOffset(bytes.NewReader(bad), totalSize, record); ok {
		t.Fatal("bad end record signature reported a central directory")
	}
}

func TestReadAtBounds(t *testing.T) {
	data := []byte("0123456789")
	if got, err := readAt(bytes.NewReader(data), 2, 3, 10); err != nil || string(got) != "234" {
		t.Fatalf("readAt = %q, %v", got, err)
	}
	if _, err := readAt(bytes.NewReader(data), 8, 4, 10); !errors.Is(err, ErrTruncated) {
		t.Fatalf("truncated error = %v", err)
	}
	if _, err := readAt(bytes.NewReader(data), -1, 1, 10); !errors.Is(err, ErrTruncated) {
		t.Fatalf("negative error = %v", err)
	}
	if _, err := readAt(failingReader{}, 0, 1, 10); !errors.Is(err, ErrRead) {
		t.Fatalf("reader error = %v", err)
	}
	if got, err := readAt(bytes.NewReader(data), 0, 0, 10); err != nil || len(got) != 0 {
		t.Fatalf("empty read = %q, %v", got, err)
	}
}

// failingReader always fails.
type failingReader struct{}

func (failingReader) ReadAt([]byte, int64) (int, error) {
	return 0, io.ErrClosedPipe
}

// entryFor builds a ZIP entry view for classification tests.
type entryFor struct{ name string }

func (e *entryFor) entry() *archive.Entry {
	return &archive.Entry{
		Name:          e.name,
		NameAvailable: true,
	}
}

func hasLimitation(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func patch(data []byte, offset int, value []byte) []byte {
	out := append([]byte(nil), data...)
	copy(out[offset:], value)
	return out
}

func TestSigningBlockBounds(t *testing.T) {
	data := buildZIP(t, []string{"AndroidManifest.xml"}, [][]byte{[]byte("m")})
	for _, cdOffset := range []int64{0, 8, int64(len(data)) + 1} {
		block, err := parseSigningBlock(bytes.NewReader(data), int64(len(data)), cdOffset, DefaultLimits())
		if err != nil {
			t.Fatalf("cdOffset %d: %v", cdOffset, err)
		}
		if block.Present {
			t.Fatalf("cdOffset %d reported a block", cdOffset)
		}
	}
	// A footer that cannot be read inside the artifact is not a block.
	block, err := parseSigningBlock(failingReader{}, int64(len(data)), 40, DefaultLimits())
	if err != nil || block.Present {
		t.Fatalf("failing reader block = %#v, %v", block, err)
	}
}

func TestClassifyUnavailableName(t *testing.T) {
	entry := &archive.Entry{NameAvailable: false, NameUnsafe: "name is not valid UTF-8"}
	got := classify(entry)
	if got.Kind != KindOther || got.ABI != "" || got.DigestAvailable {
		t.Fatalf("classification = %#v", got)
	}
}

func TestAPKSizeNil(t *testing.T) {
	var parsed *APK
	if parsed.Size() != 0 {
		t.Fatal("nil Size is not zero")
	}
}

func TestMapArchiveError(t *testing.T) {
	tests := []struct {
		in   error
		want error
	}{
		{nil, nil},
		{fmt.Errorf("wrap: %w", archive.ErrInvalid), ErrInvalid},
		{fmt.Errorf("wrap: %w", archive.ErrTruncated), ErrTruncated},
		{fmt.Errorf("wrap: %w", archive.ErrLimit), ErrLimit},
		{fmt.Errorf("wrap: %w", archive.ErrRead), ErrRead},
		{errors.New("other"), ErrInvalid},
	}
	for _, test := range tests {
		got := mapArchiveError(test.in)
		if test.want == nil {
			if got != nil {
				t.Fatalf("mapArchiveError(nil) = %v", got)
			}
			continue
		}
		if !errors.Is(got, test.want) {
			t.Fatalf("mapArchiveError(%v) = %v, want %v", test.in, got, test.want)
		}
	}
}

func TestReason(t *testing.T) {
	tests := map[error]string{
		archive.ErrUnavailable: "content is unavailable",
		archive.ErrLimit:       "content exceeds the limit",
		archive.ErrTruncated:   "declared range is outside the artifact",
		archive.ErrRead:        "read failed",
		errors.New("odd"):      "content could not be decoded",
	}
	for in, want := range tests {
		if got := reason(in); got != want {
			t.Fatalf("reason(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestZIP64Failures(t *testing.T) {
	const (
		endOffset     = 20
		locatorOffset = endOffset + 56
		recordOffset  = locatorOffset + 20
		totalSize     = recordOffset + 22
	)
	base := func() []byte {
		data := make([]byte, totalSize)
		copy(data[endOffset:], "PK\x06\x06")
		binary.LittleEndian.PutUint64(data[endOffset+40:], 4)
		binary.LittleEndian.PutUint64(data[endOffset+48:], 8)
		copy(data[locatorOffset:], "PK\x06\x07")
		binary.LittleEndian.PutUint64(data[locatorOffset+8:], endOffset)
		copy(data[recordOffset:], "PK\x05\x06")
		return data
	}
	record := endRecord{offset: recordOffset}

	noLocator := base()
	copy(noLocator[locatorOffset:], "PK\x06\x08")
	if _, ok := zip64CentralDirectoryOffset(bytes.NewReader(noLocator), totalSize, record); ok {
		t.Fatal("missing locator signature reported a directory")
	}

	pastEnd := base()
	binary.LittleEndian.PutUint64(pastEnd[locatorOffset+8:], totalSize)
	if _, ok := zip64CentralDirectoryOffset(bytes.NewReader(pastEnd), totalSize, record); ok {
		t.Fatal("locator beyond the artifact reported a directory")
	}

	badSignature := base()
	copy(badSignature[endOffset:], "PK\x06\x08")
	if _, ok := zip64CentralDirectoryOffset(bytes.NewReader(badSignature), totalSize, record); ok {
		t.Fatal("bad end record signature reported a directory")
	}

	badRange := base()
	binary.LittleEndian.PutUint64(badRange[endOffset+48:], totalSize)
	if _, ok := zip64CentralDirectoryOffset(bytes.NewReader(badRange), totalSize, record); ok {
		t.Fatal("directory outside the artifact reported a directory")
	}

	tiny := endRecord{offset: 10}
	if _, ok := zip64CentralDirectoryOffset(bytes.NewReader(base()), totalSize, tiny); ok {
		t.Fatal("end record too close to the artifact start reported a directory")
	}
}

func TestFindEndRecordWindow(t *testing.T) {
	// A comment longer than the scan window leaves the record undiscovered.
	data := append([]byte("PK\x05\x06"), make([]byte, 22+0x10000)...)
	if _, ok := findEndRecord(bytes.NewReader(data), int64(len(data))); ok {
		t.Fatal("end record outside the window was found")
	}
}
