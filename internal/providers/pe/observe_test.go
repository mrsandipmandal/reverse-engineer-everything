package pe

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	repe "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/pe"
)

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func observeFixture(t *testing.T, data []byte, opts Options) evidence.Evidence {
	t.Helper()

	if opts.ProviderVersion == "" {
		opts.ProviderVersion = "test"
	}
	rec, err := Observe(bytes.NewReader(data), int64(len(data)), opts)
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	return rec
}

func decodePayload(t *testing.T, rec evidence.Evidence) Payload {
	t.Helper()

	var payload Payload
	if err := json.Unmarshal(rec.Payload, &payload); err != nil {
		t.Fatalf("payload decode error = %v", err)
	}
	return payload
}

func hasStatement(statements []string, fragment string) bool {
	for _, statement := range statements {
		if strings.Contains(statement, fragment) {
			return true
		}
	}
	return false
}

func TestObserveFixture(t *testing.T) {
	t.Parallel()

	fixture := newPEFixture(t, fixtureOptions{magic: repe.MagicPE32, certificates: 2, overlayBytes: 8})
	rec := observeFixture(t, fixture.data, Options{})

	if rec.Schema != evidence.Schema {
		t.Fatalf("schema = %q", rec.Schema)
	}
	if rec.Subject.SHA256 != sha256Hex(fixture.data) || rec.Subject.Size != int64(len(fixture.data)) {
		t.Fatalf("subject = %+v", rec.Subject)
	}
	wantProvider := evidence.Provider{ID: ProviderID, Version: "test", Profile: ProviderProfile}
	if rec.Provider != wantProvider {
		t.Fatalf("provider = %+v, want %+v", rec.Provider, wantProvider)
	}
	if rec.Authority != evidence.AuthorityObserved {
		t.Fatalf("authority = %q", rec.Authority)
	}
	if len(rec.Limitations) != 0 {
		t.Fatalf("limitations = %v", rec.Limitations)
	}
	if rec.Coverage != evidence.CoveragePartial {
		t.Fatalf("coverage = %q with unknowns %v", rec.Coverage, rec.Unknowns)
	}
	if !hasStatement(rec.Unknowns, "certificate signatures are not validated") ||
		!hasStatement(rec.Unknowns, "resource data is not interpreted") {
		t.Fatalf("unknowns = %v", rec.Unknowns)
	}

	payload := decodePayload(t, rec)
	if payload.Schema != PayloadSchema {
		t.Fatalf("payload schema = %q", payload.Schema)
	}

	header := payload.Header
	if header.DOSMagic != 0x5a4d || header.PEHeaderOffset != 0x80 {
		t.Fatalf("DOS header = %+v", header)
	}
	if header.Machine != 0x14c || header.NumberOfSections != 1 || header.TimeDateStamp != 0x5f5e1000 {
		t.Fatalf("COFF header = %+v", header)
	}
	if header.SizeOfOptionalHeader != 224 || header.Characteristics != 0x0102 {
		t.Fatalf("COFF header = %+v", header)
	}
	if header.Optional.Magic != repe.MagicPE32 || header.Optional.ImageBase != "4194304" {
		t.Fatalf("optional header = %+v", header.Optional)
	}
	if header.Optional.SizeOfImage != 0x2000 || header.Optional.SizeOfHeaders != 0x200 ||
		header.Optional.NumberOfRvaAndSizes != 16 {
		t.Fatalf("optional header = %+v", header.Optional)
	}
	if header.LoadedDataDirectories != 16 || header.LoadedSections != 1 {
		t.Fatalf("loaded counts = %d/%d", header.LoadedDataDirectories, header.LoadedSections)
	}

	if len(payload.DataDirectories) != 16 {
		t.Fatalf("data directory count = %d", len(payload.DataDirectories))
	}
	if directory := payload.DataDirectories[1]; directory.VirtualAddress != fixture.importDirectoryRVA ||
		directory.Size != fixture.importDirectorySize {
		t.Fatalf("import directory = %+v", directory)
	}
	if directory := payload.DataDirectories[4]; directory.VirtualAddress != uint32(fixture.certificateOffset) ||
		directory.Size != fixture.certificateSize {
		t.Fatalf("security directory = %+v", directory)
	}

	if len(payload.Sections) != 1 {
		t.Fatalf("section count = %d", len(payload.Sections))
	}
	section := payload.Sections[0]
	if section.Name != ".rdata" || !section.NameAvailable || section.NameHex != "2e72646174610000" {
		t.Fatalf("section name = %+v", section)
	}
	if section.VirtualAddress != fixtureRVA || section.SizeOfRawData != uint32(fixture.contentSize) {
		t.Fatalf("section = %+v", section)
	}
	wantDigest := sha256Hex(fixture.data[fixtureRawOffset : fixtureRawOffset+fixture.contentSize])
	if section.DataSHA256 == nil || *section.DataSHA256 != wantDigest {
		t.Fatalf("section digest = %v, want %s", section.DataSHA256, wantDigest)
	}

	if payload.Overlay == nil {
		t.Fatal("overlay is missing")
	}
	wantOverlayOffset := fixtureRawOffset + fixture.contentSize
	if payload.Overlay.Offset != uint64String(uint64(wantOverlayOffset)) {
		t.Fatalf("overlay offset = %s, want %d", payload.Overlay.Offset, wantOverlayOffset)
	}
	if payload.Overlay.Size != uint64String(uint64(len(fixture.data)-wantOverlayOffset)) {
		t.Fatalf("overlay size = %s", payload.Overlay.Size)
	}

	if payload.Imports == nil || len(payload.Imports.Modules) != 2 {
		t.Fatalf("imports = %+v", payload.Imports)
	}
	kernel := payload.Imports.Modules[0]
	if kernel.Name != "KERNEL32.dll" || !kernel.NameAvailable || kernel.ThunkSource != "original_first_thunk" {
		t.Fatalf("kernel module = %+v", kernel)
	}
	if len(kernel.Thunks) != 2 {
		t.Fatalf("kernel thunks = %+v", kernel.Thunks)
	}
	if thunk := kernel.Thunks[0]; thunk.ByOrdinal || !thunk.NameAvailable || thunk.Name != "Sleep" || thunk.Hint != 0 {
		t.Fatalf("named thunk = %+v", thunk)
	}
	if thunk := kernel.Thunks[1]; !thunk.ByOrdinal || thunk.Ordinal != 12 || thunk.NameAvailable || thunk.NameRVA != 0 {
		t.Fatalf("ordinal thunk = %+v", thunk)
	}
	user := payload.Imports.Modules[1]
	if user.Name != "USER32.dll" || user.ThunkSource != "first_thunk" || len(user.Thunks) != 1 {
		t.Fatalf("user module = %+v", user)
	}
	if user.Thunks[0].Name != "MessageBoxA" || user.Thunks[0].Hint != 7 || !user.Thunks[0].NameAvailable {
		t.Fatalf("user thunk = %+v", user.Thunks[0])
	}

	exports := payload.Exports
	if exports == nil || exports.Name != "sample.dll" || !exports.NameAvailable {
		t.Fatalf("exports = %+v", exports)
	}
	if exports.Base != 1 || exports.NumberOfFunctions != 3 || exports.NumberOfNames != 2 {
		t.Fatalf("export counts = %+v", exports)
	}
	if len(exports.Exports) != 3 {
		t.Fatalf("export count = %d", len(exports.Exports))
	}
	alpha := exports.Exports[0]
	if alpha.Ordinal != 1 || alpha.RVA != 0x2000 || alpha.Name != "Alpha" || !alpha.NameAvailable {
		t.Fatalf("alpha = %+v", alpha)
	}
	forwarded := exports.Exports[1]
	if forwarded.Name != "Forwarded" || !forwarded.ForwarderAvailable || forwarded.Forwarder != "KERNEL32.Sleep" {
		t.Fatalf("forwarded = %+v", forwarded)
	}
	if unnamed := exports.Exports[2]; unnamed.NameAvailable || unnamed.NameRVA != 0 || unnamed.RVA != 0x2004 {
		t.Fatalf("unnamed = %+v", unnamed)
	}

	resources := payload.Resources
	if resources == nil || len(resources.Resources) != 1 {
		t.Fatalf("resources = %+v", resources)
	}
	resource := resources.Resources[0]
	if len(resource.Path) != 3 {
		t.Fatalf("resource path = %+v", resource.Path)
	}
	if got := resource.Path[0]; got.IsName || got.ID != 10 {
		t.Fatalf("path[0] = %+v", got)
	}
	if got := resource.Path[1]; !got.IsName || !got.NameAvailable || got.Name != "RCDATA" {
		t.Fatalf("path[1] = %+v", got)
	}
	if got := resource.Path[2]; got.IsName || got.ID != 1033 {
		t.Fatalf("path[2] = %+v", got)
	}
	if resource.DataSize != 13 || resource.CodePage != 1252 || !resource.DataAvailable {
		t.Fatalf("resource = %+v", resource)
	}

	certificates := payload.Certificates
	if certificates == nil || len(certificates.Certificates) != 2 {
		t.Fatalf("certificates = %+v", certificates)
	}
	if certificates.Offset != uint64String(fixture.certificateOffset) || certificates.Size != fixture.certificateSize {
		t.Fatalf("certificate table = %+v", certificates)
	}
	first := certificates.Certificates[0]
	if first.Index != 0 || first.Length != 19 || first.Revision != 0x0200 || first.Type != 2 || first.DataSize != 11 {
		t.Fatalf("certificate 0 = %+v", first)
	}
	second := certificates.Certificates[1]
	if second.Index != 1 || second.Length != 12 || second.Revision != 0x0100 || second.Type != 1 || second.DataSize != 4 {
		t.Fatalf("certificate 1 = %+v", second)
	}
}

func TestObservePE32Plus(t *testing.T) {
	t.Parallel()

	fixture := newPEFixture(t, fixtureOptions{magic: repe.MagicPE32P})
	rec := observeFixture(t, fixture.data, Options{})
	payload := decodePayload(t, rec)

	if payload.Header.Optional.Magic != repe.MagicPE32P {
		t.Fatalf("magic = %#x", payload.Header.Optional.Magic)
	}
	if payload.Header.Optional.ImageBase != "5368709120" {
		t.Fatalf("image base = %q", payload.Header.Optional.ImageBase)
	}
	if payload.Header.Optional.SizeOfStackReserve != "1048576" {
		t.Fatalf("stack reserve = %q", payload.Header.Optional.SizeOfStackReserve)
	}
	if payload.Header.Machine != 0x8664 {
		t.Fatalf("machine = %#x", payload.Header.Machine)
	}
	if thunk := payload.Imports.Modules[0].Thunks[1]; !thunk.ByOrdinal || thunk.Ordinal != 12 {
		t.Fatalf("ordinal thunk = %+v", thunk)
	}
}

func TestObserveAbsentDirectories(t *testing.T) {
	t.Parallel()

	fixture := newPEFixture(t, fixtureOptions{
		omitImports:   true,
		omitExports:   true,
		omitResources: true,
	})
	rec := observeFixture(t, fixture.data, Options{})

	if rec.Coverage != evidence.CoverageComplete {
		t.Fatalf("coverage = %q, limitations = %v, unknowns = %v",
			rec.Coverage, rec.Limitations, rec.Unknowns)
	}
	payload := decodePayload(t, rec)
	if payload.Imports != nil || payload.Exports != nil || payload.Resources != nil || payload.Certificates != nil {
		t.Fatalf("absent directories were reported: %+v", payload)
	}
	if payload.Overlay != nil {
		t.Fatalf("overlay = %+v", payload.Overlay)
	}
	if len(payload.Sections) != 1 || payload.Sections[0].SizeOfRawData != 0 ||
		payload.Sections[0].DataSHA256 != nil {
		t.Fatalf("sections = %+v", payload.Sections)
	}
}

func TestObserveDeterministicRoundTrip(t *testing.T) {
	t.Parallel()

	data := newPEFixture(t, fixtureOptions{certificates: 1}).data
	first := observeFixture(t, data, Options{ProviderVersion: "1.2.3"})
	second := observeFixture(t, data, Options{ProviderVersion: "1.2.3"})

	firstBytes, err := evidence.Encode(first)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	secondBytes, err := evidence.Encode(second)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatalf("two observations of the same artifact produced different records")
	}

	decoded, err := evidence.Decode(firstBytes)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	reencoded, err := evidence.Encode(decoded)
	if err != nil {
		t.Fatalf("Encode(decoded) error = %v", err)
	}
	if !bytes.Equal(reencoded, firstBytes) {
		t.Fatalf("round-trip record changed")
	}
	if decoded.Provider.Version != "1.2.3" {
		t.Fatalf("round-trip provider = %+v", decoded.Provider)
	}
}

func TestObserveRequiresProviderVersion(t *testing.T) {
	t.Parallel()

	data := newPEFixture(t, fixtureOptions{}).data
	if _, err := Observe(bytes.NewReader(data), int64(len(data)), Options{}); !errors.Is(err, ErrOptions) {
		t.Fatalf("Observe() error = %v, want ErrOptions", err)
	}
}

func TestObserveRejectsNonPE(t *testing.T) {
	t.Parallel()

	data := bytes.Repeat([]byte("x"), 0x100)
	if _, err := Observe(bytes.NewReader(data), int64(len(data)), Options{ProviderVersion: "test"}); !errors.Is(err, repe.ErrInvalid) {
		t.Fatalf("Observe() error = %v, want ErrInvalid", err)
	}
}

func TestObserveTruncatedSectionTable(t *testing.T) {
	t.Parallel()

	fixture := newPEFixture(t, fixtureOptions{})
	data := append([]byte(nil), fixture.data...)
	binary.LittleEndian.PutUint16(data[0x86:], 2)
	data = data[:fixture.sectionTableOffset+40]

	rec := observeFixture(t, data, Options{})
	if rec.Coverage != evidence.CoveragePartial {
		t.Fatalf("coverage = %q", rec.Coverage)
	}
	if !hasStatement(rec.Limitations, "section table") {
		t.Fatalf("limitations = %v", rec.Limitations)
	}
	payload := decodePayload(t, rec)
	if payload.Header.NumberOfSections != 2 || payload.Header.LoadedSections != 1 {
		t.Fatalf("section counts = %+v", payload.Header)
	}
	if len(payload.Sections) != 1 || payload.Sections[0].DataSHA256 != nil {
		t.Fatalf("sections = %+v", payload.Sections)
	}
	if !hasStatement(rec.Limitations, "section digests unavailable") {
		t.Fatalf("limitations = %v", rec.Limitations)
	}
}

func TestObservePayloadBudget(t *testing.T) {
	t.Parallel()

	fixture := newPEFixture(t, fixtureOptions{extraExports: 400})
	rec := observeFixture(t, fixture.data, Options{PayloadBytes: MinPayloadBytes})
	payload := decodePayload(t, rec)

	if payload.Exports == nil {
		t.Fatal("exports are missing")
	}
	if len(payload.Exports.Exports) == 0 || len(payload.Exports.Exports) >= fixture.exportCount {
		t.Fatalf("export count = %d, want a trimmed prefix", len(payload.Exports.Exports))
	}
	if !payload.Exports.Truncated {
		t.Fatal("trimmed exports are not marked truncated")
	}
	for i, entry := range payload.Exports.Exports {
		if entry.Index != i {
			t.Fatalf("export %d index = %d, prefix is not contiguous", i, entry.Index)
		}
	}
	if !hasStatement(rec.Limitations, "payload budget omitted") {
		t.Fatalf("limitations = %v", rec.Limitations)
	}
	if rec.Coverage != evidence.CoveragePartial {
		t.Fatalf("coverage = %q", rec.Coverage)
	}
	if encoded, err := evidence.Encode(rec); err != nil || len(encoded) > evidence.MaxRecordBytes {
		t.Fatalf("trimmed record encoding = %d bytes, error %v", len(encoded), err)
	}
}

func TestObserveContentBudget(t *testing.T) {
	t.Parallel()

	rec := observeFixture(t, newPEFixture(t, fixtureOptions{}).data, Options{ContentBytes: 1})
	payload := decodePayload(t, rec)
	for _, section := range payload.Sections {
		if section.DataSHA256 != nil {
			t.Fatalf("section %d digest present above the content budget", section.Index)
		}
	}
	if !hasStatement(rec.Limitations, "content hashing budget omitted") {
		t.Fatalf("limitations = %v", rec.Limitations)
	}
	if rec.Coverage != evidence.CoveragePartial {
		t.Fatalf("coverage = %q", rec.Coverage)
	}
}

func TestObserveDirectoryLimits(t *testing.T) {
	t.Parallel()

	fixture := newPEFixture(t, fixtureOptions{})
	limits := repe.DefaultLimits()
	limits.DataDirectories = 2
	rec := observeFixture(t, fixture.data, Options{Limits: limits})
	payload := decodePayload(t, rec)

	if payload.Imports == nil || payload.Exports == nil {
		t.Fatalf("loaded directories were dropped: %+v", payload)
	}
	if payload.Resources != nil || payload.Certificates != nil {
		t.Fatalf("unloaded directories were reported: %+v", payload)
	}
	if !hasStatement(rec.Limitations, "resource directory unavailable") ||
		!hasStatement(rec.Limitations, "security directory unavailable") {
		t.Fatalf("limitations = %v", rec.Limitations)
	}
}

func TestObserveInvalidImportDirectory(t *testing.T) {
	t.Parallel()

	fixture := newPEFixture(t, fixtureOptions{})
	data := append([]byte(nil), fixture.data...)
	at := fixture.dataDirectoryOffset(1)
	binary.LittleEndian.PutUint32(data[at:], 0)
	binary.LittleEndian.PutUint32(data[at+4:], 20)

	rec := observeFixture(t, data, Options{})
	payload := decodePayload(t, rec)
	if payload.Imports != nil {
		t.Fatalf("invalid import directory was reported: %+v", payload.Imports)
	}
	if payload.Exports == nil {
		t.Fatal("a bad import directory suppressed exports")
	}
	if !hasStatement(rec.Limitations, "import directory unavailable") {
		t.Fatalf("limitations = %v", rec.Limitations)
	}
}

func TestObserveSectionNameUnavailable(t *testing.T) {
	t.Parallel()

	fixture := newPEFixture(t, fixtureOptions{})
	data := append([]byte(nil), fixture.data...)
	data[fixture.sectionTableOffset] = 0xff

	rec := observeFixture(t, data, Options{})
	payload := decodePayload(t, rec)
	section := payload.Sections[0]
	if section.NameAvailable || section.Name != "" || section.NameHex[:2] != "ff" {
		t.Fatalf("section = %+v", section)
	}
	if !hasStatement(rec.Limitations, "section name") {
		t.Fatalf("limitations = %v", rec.Limitations)
	}
}

func TestObserveCoffSymbolsUnknown(t *testing.T) {
	t.Parallel()

	fixture := newPEFixture(t, fixtureOptions{})
	data := append([]byte(nil), fixture.data...)
	binary.LittleEndian.PutUint32(data[0x8c:], 0x200)
	binary.LittleEndian.PutUint32(data[0x90:], 4)

	rec := observeFixture(t, data, Options{})
	if !hasStatement(rec.Unknowns, "COFF symbols are not decoded") {
		t.Fatalf("unknowns = %v", rec.Unknowns)
	}
}

func TestObserveOutOfScopeDirectoriesUnknown(t *testing.T) {
	t.Parallel()

	fixture := newPEFixture(t, fixtureOptions{})
	data := append([]byte(nil), fixture.data...)
	for _, index := range []int{5, 6, 9, 11, 13, 14} {
		at := fixture.dataDirectoryOffset(index)
		binary.LittleEndian.PutUint32(data[at:], fixtureRVA)
		binary.LittleEndian.PutUint32(data[at+4:], 16)
	}

	rec := observeFixture(t, data, Options{})
	for _, fragment := range []string{
		"base relocations are not decoded",
		"debug directory and PDB references are not decoded",
		"TLS callbacks are not decoded",
		"bound imports are not decoded",
		"delay-load imports are not decoded",
		"CLR metadata is not decoded",
	} {
		if !hasStatement(rec.Unknowns, fragment) {
			t.Fatalf("unknowns = %v, want %q", rec.Unknowns, fragment)
		}
	}
}

// rangeFailReader fails when a requested range overlaps [start, end).
type rangeFailReader struct {
	data  []byte
	start int64
	end   int64
}

func (r rangeFailReader) ReadAt(p []byte, off int64) (int, error) {
	if off < r.end && off+int64(len(p)) > r.start {
		return 0, io.ErrUnexpectedEOF
	}
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	return copy(p, r.data[off:]), nil
}

// offsetSizeFailReader fails only for one exact offset and read size, so
// parsing and the subject digest pass can succeed.
type offsetSizeFailReader struct {
	data []byte
	off  int64
	size int
}

func (r offsetSizeFailReader) ReadAt(p []byte, off int64) (int, error) {
	if off == r.off && len(p) == r.size {
		return 0, io.ErrUnexpectedEOF
	}
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	return copy(p, r.data[off:]), nil
}

func TestObserveSubjectDigestFailure(t *testing.T) {
	t.Parallel()

	fixture := newPEFixture(t, fixtureOptions{})
	reader := rangeFailReader{
		data:  fixture.data,
		start: fixtureRawOffset,
		end:   fixtureRawOffset + 1,
	}
	if _, err := Observe(reader, int64(len(fixture.data)), Options{ProviderVersion: "test"}); !errors.Is(err, repe.ErrRead) {
		t.Fatalf("Observe() error = %v, want ErrRead", err)
	}
}

func TestObserveTableReadFailure(t *testing.T) {
	t.Parallel()

	fixture := newPEFixture(t, fixtureOptions{certificates: 1})
	importOffset := int64(fixtureRawOffset + int(fixture.importDirectoryRVA-fixtureRVA))

	tests := []struct {
		name string
		off  int64
		size int
	}{
		{name: "imports", off: importOffset, size: 20},
		{name: "certificates", off: int64(fixture.certificateOffset), size: 8},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			reader := offsetSizeFailReader{data: fixture.data, off: test.off, size: test.size}
			if _, err := Observe(reader, int64(len(fixture.data)), Options{ProviderVersion: "test"}); !errors.Is(err, repe.ErrRead) {
				t.Fatalf("Observe() error = %v, want ErrRead", err)
			}
		})
	}
}

func TestObserveContentReadFailure(t *testing.T) {
	t.Parallel()

	fixture := newPEFixture(t, fixtureOptions{
		omitImports:   true,
		omitResources: true,
	})
	reader := offsetSizeFailReader{
		data: fixture.data,
		off:  fixtureRawOffset,
		size: fixture.contentSize,
	}
	if _, err := Observe(reader, int64(len(fixture.data)), Options{ProviderVersion: "test"}); !errors.Is(err, repe.ErrRead) {
		t.Fatalf("Observe() error = %v, want ErrRead", err)
	}
}

func TestObserveOverlay(t *testing.T) {
	t.Parallel()

	fixture := newPEFixture(t, fixtureOptions{
		omitImports:   true,
		omitExports:   true,
		omitResources: true,
		overlayBytes:  8,
	})
	rec := observeFixture(t, fixture.data, Options{})
	payload := decodePayload(t, rec)

	if payload.Overlay == nil {
		t.Fatal("overlay is missing")
	}
	wantOffset := fixtureRawOffset + fixture.contentSize
	if payload.Overlay.Offset != uint64String(uint64(wantOffset)) {
		t.Fatalf("overlay offset = %s, want %d", payload.Overlay.Offset, wantOffset)
	}
	if payload.Overlay.Size != "8" {
		t.Fatalf("overlay size = %s", payload.Overlay.Size)
	}
	if rec.Coverage != evidence.CoverageComplete {
		t.Fatalf("coverage = %q, limitations = %v", rec.Coverage, rec.Limitations)
	}
}
