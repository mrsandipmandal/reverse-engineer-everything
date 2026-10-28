package macho

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	remacho "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/macho"
)

func observeBytes(t *testing.T, data []byte) evidence.Evidence {
	t.Helper()
	record, err := Observe(bytes.NewReader(data), int64(len(data)), Options{ProviderVersion: "0.1.0"})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	return record
}

func observeWith(t *testing.T, data []byte, opts Options) evidence.Evidence {
	t.Helper()
	record, err := Observe(bytes.NewReader(data), int64(len(data)), opts)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	return record
}

func decodePayload(t *testing.T, record evidence.Evidence) Payload {
	t.Helper()
	var payload Payload
	if err := json.Unmarshal(record.Payload, &payload); err != nil {
		t.Fatalf("payload decode: %v", err)
	}
	return payload
}

func TestObserveThin(t *testing.T) {
	data := buildFixture(t, defaultFixture())
	record := observeBytes(t, data)

	if record.Schema != evidence.Schema {
		t.Fatalf("schema = %q", record.Schema)
	}
	if record.Provider.ID != ProviderID || record.Provider.Version != "0.1.0" || record.Provider.Profile != ProviderProfile {
		t.Fatalf("provider = %+v", record.Provider)
	}
	if record.Authority != evidence.AuthorityObserved {
		t.Fatalf("authority = %q", record.Authority)
	}
	sum := sha256.Sum256(data)
	if record.Subject.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("subject digest = %q", record.Subject.SHA256)
	}
	if record.Subject.Size != int64(len(data)) {
		t.Fatalf("subject size = %d", record.Subject.Size)
	}
	if record.Coverage != evidence.CoverageComplete {
		t.Fatalf("coverage = %q limitations=%v unknowns=%v", record.Coverage, record.Limitations, record.Unknowns)
	}

	payload := decodePayload(t, record)
	if payload.Schema != PayloadSchema {
		t.Fatalf("payload schema = %q", payload.Schema)
	}
	if payload.Artifact.MagicName != "mach-o-64" || payload.Artifact.Fat {
		t.Fatalf("artifact = %+v", payload.Artifact)
	}
	if payload.Artifact.Size != uint64String(uint64(len(data))) {
		t.Fatalf("artifact size = %q", payload.Artifact.Size)
	}
	if payload.Artifact.SliceCount != 1 || payload.Artifact.LoadedSliceCount != 1 {
		t.Fatalf("slice counts = %d/%d", payload.Artifact.SliceCount, payload.Artifact.LoadedSliceCount)
	}
	if len(payload.Slices) != 1 {
		t.Fatalf("slices = %d", len(payload.Slices))
	}
	slice := payload.Slices[0]
	if slice.Status != statusParsed {
		t.Fatalf("status = %q", slice.Status)
	}
	if slice.Header == nil || !slice.Header.Is64 || slice.Header.FileTypeName != "dylib" {
		t.Fatalf("header = %+v", slice.Header)
	}
	if slice.Header.DeclaredCommandCount != 1 || slice.Header.LoadedCommandCount != 1 {
		t.Fatalf("command counts = %d/%d", slice.Header.DeclaredCommandCount, slice.Header.LoadedCommandCount)
	}
	if len(slice.Segments) != 1 || slice.Segments[0].Name != "__TEXT" || !slice.Segments[0].NameAvailable {
		t.Fatalf("segments = %+v", slice.Segments)
	}
	if slice.Segments[0].NameHex != hex.EncodeToString(padName("__TEXT")) {
		t.Fatalf("segment name hex = %q", slice.Segments[0].NameHex)
	}
	if len(slice.Sections) != 2 {
		t.Fatalf("sections = %d", len(slice.Sections))
	}
	text := slice.Sections[0]
	if text.Name != "__text" || text.DataSHA256 == nil {
		t.Fatalf("section = %+v", text)
	}
	want := sha256.Sum256([]byte("text-bytes"))
	if *text.DataSHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("section digest = %q", *text.DataSHA256)
	}
	if slice.Sections[1].Name != "__const" || slice.Sections[1].DataSHA256 == nil {
		t.Fatalf("second section = %+v", slice.Sections[1])
	}
	if slice.Dylibs != nil || slice.Symbols != nil || slice.CodeSignature != nil {
		t.Fatalf("absent tables projected: %+v", slice)
	}
}

func padName(name string) []byte {
	out := make([]byte, nameBytes)
	copy(out, name)
	return out
}

func TestObserveDeterministic(t *testing.T) {
	data := buildFixture(t, defaultFixture())
	first := observeBytes(t, data)
	second := observeBytes(t, data)
	if !bytes.Equal(first.Payload, second.Payload) {
		t.Fatal("payload is not deterministic")
	}
	firstBytes, err := evidence.Encode(first)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	secondBytes, err := evidence.Encode(second)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("sealed record is not deterministic")
	}
}

func TestObserveMetadata(t *testing.T) {
	data := metadataImage(t, defaultMetadataFixture())
	record := observeWith(t, data, Options{ProviderVersion: "0.1.0"})
	payload := decodePayload(t, record)
	slice := payload.Slices[0]

	if slice.Dylibs == nil {
		t.Fatal("dylibs not projected")
	}
	if len(slice.Dylibs.Dylibs) != 2 {
		t.Fatalf("dylibs = %d", len(slice.Dylibs.Dylibs))
	}
	if slice.Dylibs.InstallName == nil || *slice.Dylibs.InstallName != "@rpath/libsample.dylib" {
		t.Fatalf("install name = %v", slice.Dylibs.InstallName)
	}
	if !slice.Dylibs.InstallNameAvailable {
		t.Fatal("install name reported unavailable")
	}
	if slice.Dylibs.Dylibs[0].Kind != "load" || slice.Dylibs.Dylibs[0].CommandName != "LC_LOAD_DYLIB" {
		t.Fatalf("first dylib = %+v", slice.Dylibs.Dylibs[0])
	}

	if slice.Build == nil || slice.Build.PlatformName != "macos" || !slice.Build.PlatformAvailable {
		t.Fatalf("build = %+v", slice.Build)
	}
	if slice.Build.CommandName != "LC_BUILD_VERSION" || len(slice.Build.Tools) != 2 {
		t.Fatalf("build = %+v", slice.Build)
	}
	if slice.Build.Tools[0].ToolName != "clang" || slice.Build.Tools[1].ToolName != "ld" {
		t.Fatalf("tools = %+v", slice.Build.Tools)
	}

	if slice.Entry == nil || slice.Entry.EntryOffset != "4660" || slice.Entry.StackSize != "32768" {
		t.Fatalf("entry = %+v", slice.Entry)
	}

	if slice.Symbols == nil || len(slice.Symbols.Symbols) != 2 {
		t.Fatalf("symbols = %+v", slice.Symbols)
	}
	if slice.Symbols.Symbols[0].Name != "_main" || slice.Symbols.Symbols[0].Value != "4294971392" {
		t.Fatalf("first symbol = %+v", slice.Symbols.Symbols[0])
	}

	if slice.CodeSignature == nil {
		t.Fatal("code signature not projected")
	}
	if slice.CodeSignature.Magic != embeddedSignatures || slice.CodeSignature.Count != 2 {
		t.Fatalf("signature = %+v", slice.CodeSignature)
	}
	if len(slice.CodeSignature.Blobs) != 2 || slice.CodeSignature.Blobs[0].Magic != codeDirectoryMagic {
		t.Fatalf("blobs = %+v", slice.CodeSignature.Blobs)
	}

	if record.Coverage != evidence.CoveragePartial {
		t.Fatalf("coverage = %q", record.Coverage)
	}
	for _, want := range []string{
		"code signatures are not validated",
		"entitlements are not decoded",
	} {
		if !contains(record.Unknowns, want) {
			t.Fatalf("unknowns = %v, want %q", record.Unknowns, want)
		}
	}
}

func TestObserveLegacyBuild(t *testing.T) {
	data := metadataImage(t, metadataFixture{is64: true, legacy: true})
	payload := decodePayload(t, observeBytes(t, data))
	build := payload.Slices[0].Build
	if build == nil || build.CommandName != "LC_VERSION_MIN_MACOSX" || build.PlatformAvailable {
		t.Fatalf("build = %+v", build)
	}
	if build.PlatformName != "" || build.MinimumOS != 0x000a0f00 || len(build.Tools) != 0 {
		t.Fatalf("build = %+v", build)
	}
}

func TestObserveBuildToolLimit(t *testing.T) {
	data := metadataImage(t, defaultMetadataFixture())
	record := observeWith(t, data, Options{ProviderVersion: "0.1.0", Limits: remacho.Limits{BuildTools: 1}})
	payload := decodePayload(t, record)
	if len(payload.Slices[0].Build.Tools) != 1 {
		t.Fatalf("tools = %+v", payload.Slices[0].Build.Tools)
	}
	found := false
	for _, limitation := range record.Limitations {
		if strings.Contains(limitation, "tool count 2 exceeds limit 1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("limitations = %v", record.Limitations)
	}
}

func TestObserveAbsentMetadata(t *testing.T) {
	data := metadataImage(t, metadataFixture{is64: true})
	record := observeBytes(t, data)
	payload := decodePayload(t, record)
	slice := payload.Slices[0]
	if slice.Dylibs != nil || slice.Build != nil || slice.Entry != nil || slice.Symbols != nil || slice.CodeSignature != nil {
		t.Fatalf("absent metadata projected: %+v", slice)
	}
	if record.Coverage != evidence.CoverageComplete {
		t.Fatalf("coverage = %q limitations=%v", record.Coverage, record.Limitations)
	}
}

func TestObserveFatSlice(t *testing.T) {
	good := buildFixture(t, defaultFixture())
	bad := []byte("not a mach-o image")
	fat := buildFatFixture(t, [][]byte{good, bad})
	record := observeBytes(t, fat)
	payload := decodePayload(t, record)

	if !payload.Artifact.Fat || payload.Artifact.MagicName != "fat-32" {
		t.Fatalf("artifact = %+v", payload.Artifact)
	}
	if payload.Artifact.SliceCount != 2 || payload.Artifact.LoadedSliceCount != 1 {
		t.Fatalf("slice counts = %d/%d", payload.Artifact.SliceCount, payload.Artifact.LoadedSliceCount)
	}
	if len(payload.Slices) != 2 {
		t.Fatalf("slices = %d", len(payload.Slices))
	}
	if payload.Slices[0].Status != statusParsed || payload.Slices[0].Header == nil {
		t.Fatalf("good slice = %+v", payload.Slices[0])
	}
	broken := payload.Slices[1]
	if broken.Status != statusInvalid || broken.Header != nil {
		t.Fatalf("bad slice = %+v", broken)
	}
	if len(broken.Limitations) != 1 || broken.Limitations[0] == "" {
		t.Fatalf("bad slice limitations = %v", broken.Limitations)
	}
	if record.Coverage != evidence.CoveragePartial {
		t.Fatalf("coverage = %q", record.Coverage)
	}
	found := false
	for _, limitation := range record.Limitations {
		if strings.Contains(limitation, "slice 1 could not be parsed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("limitations = %v", record.Limitations)
	}
}

func TestObserveOptions(t *testing.T) {
	data := buildFixture(t, defaultFixture())
	if _, err := Observe(bytes.NewReader(data), int64(len(data)), Options{}); !errors.Is(err, ErrOptions) {
		t.Fatalf("missing version error = %v", err)
	}

	defaults := (Options{}).withDefaults()
	if defaults.PayloadBytes != DefaultPayloadBytes || defaults.ContentBytes != DefaultContentBytes {
		t.Fatalf("defaults = %+v", defaults)
	}
	small := Options{PayloadBytes: 1, ContentBytes: -1}.withDefaults()
	if small.PayloadBytes != MinPayloadBytes || small.ContentBytes != DefaultContentBytes {
		t.Fatalf("small = %+v", small)
	}
	large := Options{PayloadBytes: 1 << 30, ContentBytes: 1 << 40}.withDefaults()
	if large.PayloadBytes != MaxPayloadBytes || large.ContentBytes != MaxContentBytes {
		t.Fatalf("large = %+v", large)
	}
}

func TestObservePayloadBudget(t *testing.T) {
	fixture := defaultFixture()
	sections := make([]fixtureSection, 0, 200)
	for i := 0; i < 200; i++ {
		sections = append(sections, fixtureSection{name: "__text", data: []byte("0123456789abcdef")})
	}
	fixture.segments[0] = sections
	data := buildFixture(t, fixture)
	record := observeWith(t, data, Options{ProviderVersion: "0.1.0", PayloadBytes: MinPayloadBytes})
	payload := decodePayload(t, record)
	slice := payload.Slices[0]
	if len(slice.Sections) >= len(sections) {
		t.Fatalf("budget did not trim sections: %d", len(slice.Sections))
	}
	if record.Coverage != evidence.CoveragePartial {
		t.Fatalf("coverage = %q", record.Coverage)
	}
	found := false
	for _, limitation := range record.Limitations {
		if strings.Contains(limitation, "payload budget omitted") {
			found = true
		}
	}
	if !found {
		t.Fatalf("limitations = %v", record.Limitations)
	}
	if _, err := evidence.Encode(record); err != nil {
		t.Fatalf("Encode: %v", err)
	}
}

func TestObserveContentBudget(t *testing.T) {
	data := buildFixture(t, defaultFixture())
	record := observeWith(t, data, Options{ProviderVersion: "0.1.0", ContentBytes: 4})
	payload := decodePayload(t, record)
	for _, section := range payload.Slices[0].Sections {
		if section.DataSHA256 != nil {
			t.Fatalf("section %d digested above the content budget", section.Index)
		}
	}
	found := false
	for _, limitation := range record.Limitations {
		if strings.Contains(limitation, "content hashing budget omitted") {
			found = true
		}
	}
	if !found {
		t.Fatalf("limitations = %v", record.Limitations)
	}
}

func TestObserveSectionDigests(t *testing.T) {
	fixture := defaultFixture()
	fixture.segments[0] = []fixtureSection{
		{name: "__one", data: []byte("first-bytes")},
		{name: "__two", data: []byte("second-bytes")},
	}
	data := buildFixture(t, fixture)
	payload := decodePayload(t, observeBytes(t, data))
	first, second := payload.Slices[0].Sections[0], payload.Slices[0].Sections[1]
	if first.DataSHA256 == nil || second.DataSHA256 == nil {
		t.Fatalf("digests missing: %+v %+v", first, second)
	}
	if *first.DataSHA256 == *second.DataSHA256 {
		t.Fatal("distinct content produced one digest")
	}
	want := sha256.Sum256([]byte("second-bytes"))
	if *second.DataSHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("second digest = %q", *second.DataSHA256)
	}
}

func TestObserveReaderFailure(t *testing.T) {
	data := buildFixture(t, defaultFixture())
	if _, err := Observe(failingReader{}, int64(len(data)), Options{ProviderVersion: "0.1.0"}); !errors.Is(err, remacho.ErrRead) {
		t.Fatalf("error = %v", err)
	}
}

func TestObserveInvalidArtifact(t *testing.T) {
	if _, err := Observe(bytes.NewReader([]byte("NOPE")), 4, Options{ProviderVersion: "0.1.0"}); !errors.Is(err, remacho.ErrInvalid) {
		t.Fatalf("error = %v", err)
	}
	if _, err := Observe(nil, 0, Options{ProviderVersion: "0.1.0"}); !errors.Is(err, remacho.ErrInvalid) {
		t.Fatalf("nil reader error = %v", err)
	}
}

func TestObserveNamelessSection(t *testing.T) {
	fixture := defaultFixture()
	fixture.segments[0] = []fixtureSection{{name: "", data: []byte("x")}}
	data := buildFixture(t, fixture)
	payload := decodePayload(t, observeBytes(t, data))
	section := payload.Slices[0].Sections[0]
	if section.NameAvailable || section.Name != "" {
		t.Fatalf("section = %+v", section)
	}
	if section.NameHex != strings.Repeat("00", nameBytes) {
		t.Fatalf("name hex = %q", section.NameHex)
	}
}

func TestObserveUnknowns(t *testing.T) {
	fixture := defaultFixture()
	fixture.segments[0] = []fixtureSection{
		{name: "__objc_classlist", data: []byte("0000")},
		{name: "__text", data: []byte("text")},
	}
	fixture.subtype = 0x80000002 // arm64e
	fixture.extras = []fixtureExtra{
		{command: 0x80000034, body: []byte("chained")}, // LC_DYLD_CHAINED_FIXUPS
		{command: 0x80000033, body: []byte("trie")},    // LC_DYLD_EXPORTS_TRIE
	}
	record := observeBytes(t, buildFixture(t, fixture))
	for _, want := range []string{
		"ARM64e pointer authentication is not interpreted",
		"Objective-C metadata is not interpreted",
		"chained fixups are not decoded",
		"exported symbol trie is not decoded",
	} {
		if !contains(record.Unknowns, want) {
			t.Fatalf("unknowns = %v, want %q", record.Unknowns, want)
		}
	}
	if record.Coverage != evidence.CoveragePartial {
		t.Fatalf("coverage = %q", record.Coverage)
	}
}

func TestSliceStatus(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{nil, statusParsed},
		{remacho.ErrInvalid, statusInvalid},
		{remacho.ErrTruncated, statusTruncated},
		{remacho.ErrLimit, statusLimit},
		{remacho.ErrUnavailable, statusUnavailable},
		{remacho.ErrRead, statusRead},
		{remacho.ErrOutOfRange, statusInvalid},
	}
	for _, test := range tests {
		if got := sliceStatus(test.err); got != test.want {
			t.Fatalf("sliceStatus(%v) = %q, want %q", test.err, got, test.want)
		}
	}
}

func TestNaming(t *testing.T) {
	magics := map[uint32]string{
		remacho.Magic32: "mach-o-32", remacho.Magic64: "mach-o-64",
		remacho.FatMagic: "fat-32", remacho.FatMagic64: "fat-64", 0: "",
	}
	for magic, want := range magics {
		if got := magicName(magic); got != want {
			t.Fatalf("magicName(%#x) = %q, want %q", magic, got, want)
		}
	}
	orders := map[remacho.Data]string{remacho.DataLittle: "little", remacho.DataBig: "big", remacho.DataNone: ""}
	for order, want := range orders {
		if got := byteOrderName(order); got != want {
			t.Fatalf("byteOrderName(%d) = %q, want %q", order, got, want)
		}
	}
	fileTypes := map[uint32]string{
		1: "object", 2: "execute", 3: "fvmlib", 4: "core", 5: "preload",
		6: "dylib", 7: "dylinker", 8: "bundle", 9: "dylib_stub",
		10: "dsym", 11: "kext_bundle", 12: "fileset", 13: "",
	}
	for value, want := range fileTypes {
		if got := fileTypeName(value); got != want {
			t.Fatalf("fileTypeName(%d) = %q, want %q", value, got, want)
		}
	}
	commands := map[uint32]string{
		remacho.CommandSegment: "LC_SEGMENT", remacho.CommandSegment64: "LC_SEGMENT_64",
		remacho.CommandSymtab: "LC_SYMTAB", remacho.CommandDylibID: "LC_ID_DYLIB",
		remacho.CommandLoadDylib: "LC_LOAD_DYLIB", remacho.CommandLoadWeakDylib: "LC_LOAD_WEAK_DYLIB",
		remacho.CommandReexportDylib: "LC_REEXPORT_DYLIB", remacho.CommandLazyLoadDylib: "LC_LAZY_LOAD_DYLIB",
		remacho.CommandLoadUpwardDylib: "LC_LOAD_UPWARD_DYLIB", remacho.CommandUUID: "LC_UUID",
		remacho.CommandCodeSignature: "LC_CODE_SIGNATURE", remacho.CommandVersionMinMacOSX: "LC_VERSION_MIN_MACOSX",
		remacho.CommandVersionMinIPhoneOS: "LC_VERSION_MIN_IPHONEOS", remacho.CommandVersionMinTVOS: "LC_VERSION_MIN_TVOS",
		remacho.CommandVersionMinWatchOS: "LC_VERSION_MIN_WATCHOS", remacho.CommandBuildVersion: "LC_BUILD_VERSION",
		remacho.CommandMain: "LC_MAIN", commandDyldInfo: "LC_DYLD_INFO",
		commandDyldInfoOnly: "LC_DYLD_INFO_ONLY", commandDyldExportsTrie: "LC_DYLD_EXPORTS_TRIE",
		commandDyldChainedFixups: "LC_DYLD_CHAINED_FIXUPS", 0x99: "",
	}
	for value, want := range commands {
		if got := commandName(value); got != want {
			t.Fatalf("commandName(%#x) = %q, want %q", value, got, want)
		}
	}
	platforms := map[uint32]string{
		1: "macos", 2: "ios", 3: "tvos", 4: "watchos", 5: "bridgeos",
		6: "maccatalyst", 7: "ios-simulator", 8: "tvos-simulator",
		9: "watchos-simulator", 10: "driverkit", 11: "visionos",
		12: "visionos-simulator", 99: "",
	}
	for value, want := range platforms {
		if got := platformName(value); got != want {
			t.Fatalf("platformName(%d) = %q, want %q", value, got, want)
		}
	}
	tools := map[uint32]string{1: "clang", 2: "swift", 3: "ld", 9: ""}
	for value, want := range tools {
		if got := toolName(value); got != want {
			t.Fatalf("toolName(%d) = %q, want %q", value, got, want)
		}
	}
	kinds := map[uint32]string{
		remacho.CommandDylibID: "id", remacho.CommandLoadDylib: "load",
		remacho.CommandLoadWeakDylib: "weak", remacho.CommandReexportDylib: "reexport",
		remacho.CommandLazyLoadDylib: "lazy", remacho.CommandLoadUpwardDylib: "upward", 0x99: "",
	}
	for value, want := range kinds {
		if got := dylibKind(value); got != want {
			t.Fatalf("dylibKind(%#x) = %q, want %q", value, got, want)
		}
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

type failingReader struct{}

func (failingReader) ReadAt([]byte, int64) (int, error) {
	return 0, errors.New("boom")
}
