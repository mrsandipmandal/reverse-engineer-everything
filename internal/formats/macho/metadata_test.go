package macho

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestDylibs(t *testing.T) {
	file := parseMetadata(t, buildMetadata(t, defaultMetadataFixture()))
	table, err := file.Dylibs()
	if err != nil {
		t.Fatalf("Dylibs: %v", err)
	}
	if len(table.Dylibs) != 2 {
		t.Fatalf("got %d dylibs", len(table.Dylibs))
	}
	first := table.Dylibs[0]
	if first.Name != "/usr/lib/libSystem.B.dylib" || !first.NameAvailable {
		t.Fatalf("first name = %q available=%v", first.Name, first.NameAvailable)
	}
	if first.Command != CommandLoadDylib || first.Index != 0 {
		t.Fatalf("first command = %#x index %d", first.Command, first.Index)
	}
	if first.Timestamp != 1 || first.CurrentVersion != 0x00010000 || first.CompatibilityVersion != 0x00010000 {
		t.Fatalf("first versions = %#x %#x %#x", first.Timestamp, first.CurrentVersion, first.CompatibilityVersion)
	}
	if table.Dylibs[1].Command != CommandDylibID || table.Dylibs[1].Name != "@rpath/libsample.dylib" {
		t.Fatalf("second dylib = %#x %q", table.Dylibs[1].Command, table.Dylibs[1].Name)
	}
	if table.Truncated || len(table.Limitations) != 0 {
		t.Fatalf("clean table reports truncated=%v limitations=%v", table.Truncated, table.Limitations)
	}
}

func TestDylibsNotFound(t *testing.T) {
	file := parseMetadata(t, buildMetadata(t, metadataFixture{is64: true}))
	if _, err := file.Dylibs(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v", err)
	}
}

func TestDylibDefects(t *testing.T) {
	raw := func(nameOffset uint32, name string) []byte {
		// Fill the command with a non-zero byte so padding cannot supply the
		// terminator that a malformed name lacks.
		command := bytes.Repeat([]byte{'Z'}, align8(dylibCommandSize+len(name)))
		byteOrder(DataLittle).PutUint32(command[0:], CommandLoadDylib)
		byteOrder(DataLittle).PutUint32(command[4:], uint32(len(command)))
		byteOrder(DataLittle).PutUint32(command[8:], nameOffset)
		if int(nameOffset) >= dylibCommandSize && int(nameOffset) < len(command) {
			copy(command[nameOffset:], name)
		}
		return command
	}

	tests := []struct {
		name      string
		command   []byte
		limits    Limits
		wantNote  string
		wantAvail bool
	}{
		{
			name:      "invalid utf8",
			command:   raw(dylibCommandSize, "\xff\xfe\x00"),
			wantNote:  "not valid UTF-8",
			wantAvail: false,
		},
		{
			name:      "unterminated",
			command:   raw(dylibCommandSize, "ABCD"),
			wantNote:  "not NUL-terminated",
			wantAvail: false,
		},
		{
			name:      "offset before header",
			command:   raw(4, "lib.dylib\x00"),
			wantAvail: false,
		},
		{
			name:      "offset past command",
			command:   raw(1000, "lib.dylib\x00"),
			wantAvail: false,
		},
		{
			name:      "long name",
			command:   raw(dylibCommandSize, "liblongname.dylib\x00"),
			limits:    Limits{StringBytes: 4},
			wantNote:  "exceed 4 bytes",
			wantAvail: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := buildMetadata(t, metadataFixture{is64: true, extra: [][]byte{test.command}})
			artifact, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), test.limits)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			file := artifact.Slices[0].File
			table, err := file.Dylibs()
			if err != nil {
				t.Fatalf("Dylibs: %v", err)
			}
			if len(table.Dylibs) != 1 {
				t.Fatalf("got %d dylibs", len(table.Dylibs))
			}
			if table.Dylibs[0].NameAvailable != test.wantAvail {
				t.Fatalf("NameAvailable = %v", table.Dylibs[0].NameAvailable)
			}
			if test.wantNote != "" {
				if !strings.Contains(strings.Join(table.Limitations, "\n"), test.wantNote) {
					t.Fatalf("limitations = %v, want %q", table.Limitations, test.wantNote)
				}
			}
		})
	}
}

func TestDylibLimit(t *testing.T) {
	data := buildMetadata(t, defaultMetadataFixture())
	artifact, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{Dylibs: 1})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	table, err := artifact.Slices[0].File.Dylibs()
	if err != nil {
		t.Fatalf("Dylibs: %v", err)
	}
	if len(table.Dylibs) != 1 || !table.Truncated {
		t.Fatalf("dylibs=%d truncated=%v", len(table.Dylibs), table.Truncated)
	}
	if want := "dylib count 2 exceeds limit 1"; !strings.Contains(strings.Join(table.Limitations, "\n"), want) {
		t.Fatalf("limitations = %v", table.Limitations)
	}
}

func TestUUID(t *testing.T) {
	file := parseMetadata(t, buildMetadata(t, defaultMetadataFixture()))
	uuid, err := file.UUID()
	if err != nil {
		t.Fatalf("UUID: %v", err)
	}
	for i := 0; i < 16; i++ {
		if uuid[i] != byte(i) {
			t.Fatalf("uuid[%d] = %#x", i, uuid[i])
		}
	}

	if _, err := parseMetadata(t, buildMetadata(t, metadataFixture{is64: true})).UUID(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing UUID error = %v", err)
	}

	short := make([]byte, 8)
	byteOrder(DataLittle).PutUint32(short[0:], CommandUUID)
	byteOrder(DataLittle).PutUint32(short[4:], 8)
	file = parseMetadata(t, buildMetadata(t, metadataFixture{is64: true, extra: [][]byte{short}}))
	if _, err := file.UUID(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short UUID error = %v", err)
	}
}

func TestBuildVersion(t *testing.T) {
	file := parseMetadata(t, buildMetadata(t, defaultMetadataFixture()))
	version, err := file.BuildVersion()
	if err != nil {
		t.Fatalf("BuildVersion: %v", err)
	}
	if version.Command != CommandBuildVersion || !version.PlatformAvailable {
		t.Fatalf("command = %#x platformAvailable=%v", version.Command, version.PlatformAvailable)
	}
	if version.Platform != 1 || version.MinimumOS != 0x000d0000 || version.SDK != 0x000e0000 {
		t.Fatalf("version = %#x %#x %#x", version.Platform, version.MinimumOS, version.SDK)
	}
	if len(version.Tools) != 2 || version.Tools[1].Tool != 3 || version.Tools[1].Version != 0x000c0000 {
		t.Fatalf("tools = %+v", version.Tools)
	}

	legacy := parseMetadata(t, buildMetadata(t, metadataFixture{is64: true, legacy: true}))
	old, err := legacy.BuildVersion()
	if err != nil {
		t.Fatalf("legacy BuildVersion: %v", err)
	}
	if old.Command != CommandVersionMinMacOSX || old.PlatformAvailable {
		t.Fatalf("legacy command = %#x platformAvailable=%v", old.Command, old.PlatformAvailable)
	}
	if old.MinimumOS != 0x000a0f00 || old.SDK != 0x000b0000 || len(old.Tools) != 0 {
		t.Fatalf("legacy = %+v", old)
	}

	if _, err := parseMetadata(t, buildMetadata(t, metadataFixture{is64: true})).BuildVersion(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing build version error = %v", err)
	}
}

func TestBuildVersionToolLimit(t *testing.T) {
	data := buildMetadata(t, defaultMetadataFixture())
	artifact, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{BuildTools: 1})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	version, err := artifact.Slices[0].File.BuildVersion()
	if err != nil {
		t.Fatalf("BuildVersion: %v", err)
	}
	if len(version.Tools) != 1 || !version.Truncated {
		t.Fatalf("tools=%d truncated=%v", len(version.Tools), version.Truncated)
	}
	if !strings.Contains(strings.Join(version.Limitations, "\n"), "tool count 2 exceeds limit 1") {
		t.Fatalf("limitations = %v", version.Limitations)
	}
}

func TestEntryPoint(t *testing.T) {
	file := parseMetadata(t, buildMetadata(t, defaultMetadataFixture()))
	entry, err := file.EntryPoint()
	if err != nil {
		t.Fatalf("EntryPoint: %v", err)
	}
	if entry.EntryOffset != 0x1234 || entry.StackSize != 0x8000 {
		t.Fatalf("entry = %+v", entry)
	}
	if _, err := parseMetadata(t, buildMetadata(t, metadataFixture{is64: true})).EntryPoint(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing entry error = %v", err)
	}
}

func TestSymbols(t *testing.T) {
	file := parseMetadata(t, buildMetadata(t, defaultMetadataFixture()))
	table, err := file.Symbols()
	if err != nil {
		t.Fatalf("Symbols: %v", err)
	}
	if len(table.Symbols) != 3 || table.DeclaredCount != 3 {
		t.Fatalf("symbols=%d declared=%d", len(table.Symbols), table.DeclaredCount)
	}
	names := []string{"_main", "_helper", "_data"}
	for i, want := range names {
		if table.Symbols[i].Name != want || !table.Symbols[i].NameAvailable {
			t.Fatalf("symbol %d = %q available=%v", i, table.Symbols[i].Name, table.Symbols[i].NameAvailable)
		}
	}
	if table.Symbols[0].Type != 0x0f || table.Symbols[0].Section != 1 || table.Symbols[0].Value != 0x100001000 {
		t.Fatalf("first symbol = %+v", table.Symbols[0])
	}
	if table.Symbols[2].Description != 0x0010 || table.Symbols[2].Value != 0x100003000 {
		t.Fatalf("third symbol = %+v", table.Symbols[2])
	}
	if table.Truncated || len(table.Limitations) != 0 {
		t.Fatalf("truncated=%v limitations=%v", table.Truncated, table.Limitations)
	}

	thin := metadataFixture{
		is64: false,
		symbols: []metadataSymbol{
			{name: "_start", typ: 0x0f, sect: 1, value: 0x1000},
		},
	}
	table = mustSymbols(t, parseMetadata(t, buildMetadata(t, thin)))
	if len(table.Symbols) != 1 || table.Symbols[0].Value != 0x1000 {
		t.Fatalf("32-bit symbol = %+v", table.Symbols)
	}

	empty := metadataFixture{is64: true, symtab: &[4]uint32{0, 0, 0, 0}}
	table = mustSymbols(t, parseMetadata(t, buildMetadata(t, empty)))
	if len(table.Symbols) != 0 || table.DeclaredCount != 0 {
		t.Fatalf("empty table = %+v", table)
	}

	if _, err := parseMetadata(t, buildMetadata(t, metadataFixture{is64: true})).Symbols(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing symbol table error = %v", err)
	}
}

func mustSymbols(t *testing.T, file *File) SymbolTable {
	t.Helper()
	table, err := file.Symbols()
	if err != nil {
		t.Fatalf("Symbols: %v", err)
	}
	return table
}

func TestSymbolDefects(t *testing.T) {
	strx := uint32(999)
	tests := []struct {
		name     string
		fixture  metadataFixture
		limits   Limits
		wantNote string
		wantLen  int
	}{
		{
			name: "string index outside",
			fixture: metadataFixture{is64: true, symbols: []metadataSymbol{
				{name: "_main", strx: &strx},
			}},
			wantNote: "string indexes are outside the string table",
			wantLen:  1,
		},
		{
			name: "unterminated name",
			fixture: metadataFixture{is64: true, symbols: []metadataSymbol{
				{name: "_main", noNUL: true},
			}},
			wantNote: "not NUL-terminated",
			wantLen:  1,
		},
		{
			name: "invalid utf8",
			fixture: metadataFixture{
				is64:    true,
				strings: []byte{0, 0xff, 0xfe, 0},
				symbols: []metadataSymbol{{name: "ignored", strx: uint32Ptr(1)}},
			},
			wantNote: "not valid UTF-8",
			wantLen:  1,
		},
		{
			name:     "long name",
			fixture:  defaultMetadataFixture(),
			limits:   Limits{StringBytes: 3},
			wantNote: "symbol names exceed 3 bytes",
			wantLen:  3,
		},
		{
			name:     "symbol limit",
			fixture:  defaultMetadataFixture(),
			limits:   Limits{Symbols: 1},
			wantNote: "symbol count 3 exceeds limit 1",
			wantLen:  1,
		},
		{
			name:     "string table limit",
			fixture:  defaultMetadataFixture(),
			limits:   Limits{SymbolStringBytes: 4},
			wantNote: "symbol string table size",
			wantLen:  3,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := buildMetadata(t, test.fixture)
			artifact, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), test.limits)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			table := mustSymbols(t, artifact.Slices[0].File)
			if len(table.Symbols) != test.wantLen {
				t.Fatalf("symbols = %d, want %d", len(table.Symbols), test.wantLen)
			}
			if !strings.Contains(strings.Join(table.Limitations, "\n"), test.wantNote) {
				t.Fatalf("limitations = %v, want %q", table.Limitations, test.wantNote)
			}
		})
	}
}

func uint32Ptr(value uint32) *uint32 { return &value }

func TestCodeSignature(t *testing.T) {
	fixture := defaultMetadataFixture()
	fixture.signature.magics = map[int]uint32{1: 0xfade0c01}
	file := parseMetadata(t, buildMetadata(t, fixture))
	signature, err := file.CodeSignature()
	if err != nil {
		t.Fatalf("CodeSignature: %v", err)
	}
	if signature.Magic != CodeSignatureMagic {
		t.Fatalf("magic = %#x", signature.Magic)
	}
	if signature.Count != 2 || len(signature.Blobs) != 2 {
		t.Fatalf("count=%d blobs=%d", signature.Count, len(signature.Blobs))
	}
	if signature.Length == 0 || signature.Length > signature.DataSize {
		t.Fatalf("length=%d dataSize=%d", signature.Length, signature.DataSize)
	}
	first := signature.Blobs[0]
	if first.Type != testCodeDirectoryMagic || first.Magic != testCodeDirectoryMagic {
		t.Fatalf("first blob = %+v", first)
	}
	if first.Offset <= codeSignatureHeader || first.Length != uint32(blobHeaderSize+len("code-directory-body")) {
		t.Fatalf("first blob offset=%d length=%d", first.Offset, first.Length)
	}
	if signature.Blobs[1].Type != 0xfade0c01 {
		t.Fatalf("second type = %#x", signature.Blobs[1].Type)
	}

	if _, err := parseMetadata(t, buildMetadata(t, metadataFixture{is64: true})).CodeSignature(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing signature error = %v", err)
	}

	empty := defaultMetadataFixture()
	empty.codeSig = &[2]uint32{0, 0}
	if _, err := parseMetadata(t, buildMetadata(t, empty)).CodeSignature(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty signature error = %v", err)
	}
}

func TestCodeSignatureDefects(t *testing.T) {
	tests := []struct {
		name     string
		codeSig  *[2]uint32
		mutate   func(*metadataSignature)
		limits   Limits
		wantNote string
	}{
		{
			name:     "range outside slice",
			codeSig:  &[2]uint32{0xfffffff0, 32},
			wantNote: "outside the slice",
		},
		{
			name:     "bad magic",
			mutate:   func(s *metadataSignature) { s.magic = uint32Ptr(0xdeadbeef) },
			wantNote: "is not 0xfade0cc0",
		},
		{
			name:     "index beyond length",
			mutate:   func(s *metadataSignature) { s.length = uint32Ptr(12) },
			wantNote: "declares 2 blobs but holds 0 index entries",
		},
		{
			name:     "blob outside superblob",
			mutate:   func(s *metadataSignature) { s.offsets = map[int]uint32{0: 9999} },
			wantNote: "signature blobs lie outside the superblob",
		},
		{
			name:     "blob length short",
			mutate:   func(s *metadataSignature) { s.short = map[int]bool{0: true} },
			wantNote: "declare a length outside the superblob",
		},
		{
			name:     "blob count limit",
			limits:   Limits{CodeSignBlobs: 1},
			wantNote: "blob count 2 exceeds limit 1",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := defaultMetadataFixture()
			fixture.codeSig = test.codeSig
			if test.mutate != nil {
				test.mutate(fixture.signature)
			}
			data := buildMetadata(t, fixture)
			artifact, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), test.limits)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			signature, err := artifact.Slices[0].File.CodeSignature()
			if err != nil {
				t.Fatalf("CodeSignature: %v", err)
			}
			if !strings.Contains(strings.Join(signature.Limitations, "\n"), test.wantNote) {
				t.Fatalf("limitations = %v, want %q", signature.Limitations, test.wantNote)
			}
		})
	}
}

func TestMetadataCodesignByteLimit(t *testing.T) {
	data := buildMetadata(t, defaultMetadataFixture())
	artifact, err := ParseWithLimits(bytes.NewReader(data), int64(len(data)), Limits{CodeSignBytes: 12})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	signature, err := artifact.Slices[0].File.CodeSignature()
	if err != nil {
		t.Fatalf("CodeSignature: %v", err)
	}
	if !signature.Truncated || len(signature.Blobs) != 0 {
		t.Fatalf("truncated=%v blobs=%d", signature.Truncated, len(signature.Blobs))
	}
	if !strings.Contains(strings.Join(signature.Limitations, "\n"), "exceeds limit 12") {
		t.Fatalf("limitations = %v", signature.Limitations)
	}
}

func TestMetadataNilFile(t *testing.T) {
	var file *File
	if _, err := file.Dylibs(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Dylibs error = %v", err)
	}
	if _, err := file.UUID(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("UUID error = %v", err)
	}
	if _, err := file.BuildVersion(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("BuildVersion error = %v", err)
	}
	if _, err := file.EntryPoint(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("EntryPoint error = %v", err)
	}
	if _, err := file.Symbols(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Symbols error = %v", err)
	}
	if _, err := file.CodeSignature(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("CodeSignature error = %v", err)
	}
}

func TestMetadataReaderFailure(t *testing.T) {
	file := parseMetadata(t, buildMetadata(t, defaultMetadataFixture()))
	file.reader = failingReader{}
	if _, err := file.Dylibs(); !errors.Is(err, ErrRead) {
		t.Fatalf("Dylibs error = %v", err)
	}
	if _, err := file.Symbols(); !errors.Is(err, ErrRead) {
		t.Fatalf("Symbols error = %v", err)
	}
	if _, err := file.CodeSignature(); !errors.Is(err, ErrRead) {
		t.Fatalf("CodeSignature error = %v", err)
	}
}

func TestMetadataLimitsClamping(t *testing.T) {
	limits := Limits{
		Dylibs:            1 << 20,
		StringBytes:       1 << 20,
		BuildTools:        1 << 20,
		Symbols:           1 << 30,
		SymbolStringBytes: 1 << 40,
		CodeSignBlobs:     1 << 20,
		CodeSignBytes:     1 << 40,
	}.withDefaults()
	if limits.Dylibs != MaxDylibs || limits.StringBytes != MaxStringBytes ||
		limits.BuildTools != MaxBuildTools || limits.Symbols != MaxSymbols ||
		limits.SymbolStringBytes != MaxSymbolStringBytes ||
		limits.CodeSignBlobs != MaxCodeSignBlobs || limits.CodeSignBytes != MaxCodeSignBytes {
		t.Fatalf("clamped limits = %+v", limits)
	}

	defaults := Limits{}.withDefaults()
	if defaults.Dylibs != MaxDylibs || defaults.StringBytes != MaxStringBytes ||
		defaults.BuildTools != MaxBuildTools || defaults.Symbols != MaxSymbols ||
		defaults.SymbolStringBytes != MaxSymbolStringBytes ||
		defaults.CodeSignBlobs != MaxCodeSignBlobs || defaults.CodeSignBytes != MaxCodeSignBytes {
		t.Fatalf("default limits = %+v", defaults)
	}

	negative := Limits{
		Dylibs: -1, StringBytes: -1, BuildTools: -1, Symbols: -1,
		SymbolStringBytes: -1, CodeSignBlobs: -1, CodeSignBytes: -1,
	}.withDefaults()
	if negative != defaults {
		t.Fatalf("negative limits = %+v", negative)
	}
}
