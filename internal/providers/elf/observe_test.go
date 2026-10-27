package elf

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	reeelf "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/elf"
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

	fixture := newELFFixture(t, fixtureOptions{})
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
	if rec.Coverage != evidence.CoverageComplete {
		t.Fatalf("coverage = %q, limitations = %v, unknowns = %v", rec.Coverage, rec.Limitations, rec.Unknowns)
	}
	if len(rec.Limitations) != 0 || len(rec.Unknowns) != 0 {
		t.Fatalf("limitations = %v, unknowns = %v", rec.Limitations, rec.Unknowns)
	}

	payload := decodePayload(t, rec)
	if payload.Schema != PayloadSchema {
		t.Fatalf("payload schema = %q", payload.Schema)
	}
	if payload.Header.Class != "ELF64" || payload.Header.Data != "little-endian" {
		t.Fatalf("header class/data = %q/%q", payload.Header.Class, payload.Header.Data)
	}
	if payload.Header.Type != 3 || payload.Header.Machine != 62 || payload.Header.Entry != "120" {
		t.Fatalf("header identity = %+v", payload.Header)
	}
	if payload.Header.SectionHeaderCount != "8" || payload.Header.LoadedSectionHeaderCount != 8 {
		t.Fatalf("section header counts = %q/%d",
			payload.Header.SectionHeaderCount, payload.Header.LoadedSectionHeaderCount)
	}
	if payload.Header.SectionNameIndex != fixtureShstrtab {
		t.Fatalf("section name index = %d", payload.Header.SectionNameIndex)
	}
	if payload.Header.ExtendedSectionHeaderCount || payload.Header.ExtendedProgramHeaderCount ||
		payload.Header.ExtendedSectionNameIndex {
		t.Fatalf("unexpected extended numbering: %+v", payload.Header)
	}

	if len(payload.Sections) != fixtureSectionCount {
		t.Fatalf("section count = %d", len(payload.Sections))
	}
	text := payload.Sections[1]
	if text.Name != ".text" || !text.NameAvailable || text.Type != 1 || text.Size != "8" {
		t.Fatalf("section 1 = %+v", text)
	}
	if text.DataSHA256 == nil || *text.DataSHA256 != sha256Hex(fixture.text()) {
		t.Fatalf("section 1 digest = %v, want %s", text.DataSHA256, sha256Hex(fixture.text()))
	}
	if payload.Sections[0].NameAvailable != true || payload.Sections[0].Name != "" {
		t.Fatalf("null section = %+v", payload.Sections[0])
	}

	if len(payload.Segments) != 1 {
		t.Fatalf("segment count = %d", len(payload.Segments))
	}
	segment := payload.Segments[0]
	if segment.Type != 1 || segment.Flags != 5 || segment.FileSize != "8" {
		t.Fatalf("segment = %+v", segment)
	}
	if segment.DataSHA256 == nil || *segment.DataSHA256 != *text.DataSHA256 {
		t.Fatalf("segment digest = %v, want the shared section digest", segment.DataSHA256)
	}

	if len(payload.Symbols) != 2 {
		t.Fatalf("symbol count = %d", len(payload.Symbols))
	}
	if payload.Symbols[0].Index != 0 || payload.Symbols[0].Name != "" || payload.Symbols[0].TableIndex != 5 {
		t.Fatalf("null symbol = %+v", payload.Symbols[0])
	}
	if payload.Symbols[1].Name != "main" || payload.Symbols[1].Value != "120" ||
		payload.Symbols[1].Size != "8" || payload.Symbols[1].Info != 0x12 {
		t.Fatalf("main symbol = %+v", payload.Symbols[1])
	}

	if len(payload.Relocations) != 2 {
		t.Fatalf("relocation count = %d", len(payload.Relocations))
	}
	first := payload.Relocations[0]
	if first.SectionIndex != 6 || first.TargetSectionIndex != 1 || first.Offset != "8" ||
		first.SymbolIndex != 1 || first.Type != 1 || !first.HasAddend || first.Addend != "-4" {
		t.Fatalf("relocation 0 = %+v", first)
	}
	if payload.Relocations[1].Addend != "8" || payload.Relocations[1].SymbolIndex != 2 {
		t.Fatalf("relocation 1 = %+v", payload.Relocations[1])
	}

	if len(payload.Notes) != 1 {
		t.Fatalf("note count = %d", len(payload.Notes))
	}
	note := payload.Notes[0]
	if note.Name != "GNU" || note.Type != 3 || note.SectionIndex != 3 || note.DescriptorSize != 8 {
		t.Fatalf("note = %+v", note)
	}
	if note.DescriptorHex == nil || *note.DescriptorHex != hex.EncodeToString(fixture.buildID()) {
		t.Fatalf("note descriptor = %v", note.DescriptorHex)
	}
	if note.DescriptorSHA256 != sha256Hex(fixture.buildID()) {
		t.Fatalf("note descriptor digest = %q", note.DescriptorSHA256)
	}
	if payload.BuildID == nil || payload.BuildID.Hex != hex.EncodeToString(fixture.buildID()) ||
		payload.BuildID.Size != 8 {
		t.Fatalf("build id = %+v", payload.BuildID)
	}

	if len(payload.Comments) != len(fixture.comment) {
		t.Fatalf("comment count = %d", len(payload.Comments))
	}
	for i, entry := range fixture.comment {
		if payload.Comments[i] != entry {
			t.Fatalf("comment %d = %q, want %q", i, payload.Comments[i], entry)
		}
	}
}

func TestObserveDeterministicRoundTrip(t *testing.T) {
	t.Parallel()

	data := newELFFixture(t, fixtureOptions{relType: 4}).data
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

	data := newELFFixture(t, fixtureOptions{}).data
	if _, err := Observe(bytes.NewReader(data), int64(len(data)), Options{}); !errors.Is(err, ErrOptions) {
		t.Fatalf("Observe() error = %v, want ErrOptions", err)
	}
}

func TestObserveRejectsNonELF(t *testing.T) {
	t.Parallel()

	data := []byte("not an ELF artifact")
	if _, err := Observe(bytes.NewReader(data), int64(len(data)), Options{ProviderVersion: "test"}); !errors.Is(err, reeelf.ErrInvalid) {
		t.Fatalf("Observe() error = %v, want ErrInvalid", err)
	}
}

func TestObserveTruncatedArtifact(t *testing.T) {
	t.Parallel()

	fixture := newELFFixture(t, fixtureOptions{})
	cut := fixture.shOff + 7*64
	rec := observeFixture(t, fixture.data[:cut], Options{})

	if rec.Coverage != evidence.CoveragePartial {
		t.Fatalf("coverage = %q", rec.Coverage)
	}
	if !hasStatement(rec.Limitations, "section header table is incomplete") {
		t.Fatalf("limitations = %v", rec.Limitations)
	}
	payload := decodePayload(t, rec)
	if payload.Header.LoadedSectionHeaderCount != 7 {
		t.Fatalf("loaded section headers = %d", payload.Header.LoadedSectionHeaderCount)
	}
	if payload.Sections[1].NameAvailable {
		t.Fatalf("section name reported available without a name table: %+v", payload.Sections[1])
	}
	if !hasStatement(rec.Limitations, "section names unavailable") {
		t.Fatalf("limitations = %v", rec.Limitations)
	}
}

func TestObserveRelocationWithoutAddend(t *testing.T) {
	t.Parallel()

	fixture := newELFFixture(t, fixtureOptions{relType: 9})
	rec := observeFixture(t, fixture.data, Options{})

	payload := decodePayload(t, rec)
	if len(payload.Relocations) != 2 {
		t.Fatalf("relocation count = %d", len(payload.Relocations))
	}
	for i, rel := range payload.Relocations {
		if rel.HasAddend || rel.Addend != "0" {
			t.Fatalf("relocation %d = %+v", i, rel)
		}
	}
	if !hasStatement(rec.Unknowns, "relocations without an explicit addend are not resolved") {
		t.Fatalf("unknowns = %v", rec.Unknowns)
	}
	if rec.Coverage != evidence.CoveragePartial {
		t.Fatalf("coverage = %q", rec.Coverage)
	}
}

func TestObserveContentBudget(t *testing.T) {
	t.Parallel()

	fixture := newELFFixture(t, fixtureOptions{})
	rec := observeFixture(t, fixture.data, Options{ContentBytes: 4})

	payload := decodePayload(t, rec)
	for _, section := range payload.Sections {
		if section.DataSHA256 != nil {
			t.Fatalf("section %d digest present above the content budget", section.Index)
		}
	}
	for _, segment := range payload.Segments {
		if segment.DataSHA256 != nil {
			t.Fatalf("segment %d digest present above the content budget", segment.Index)
		}
	}
	if !hasStatement(rec.Limitations, "content hashing budget omitted") {
		t.Fatalf("limitations = %v", rec.Limitations)
	}
	if rec.Coverage != evidence.CoveragePartial {
		t.Fatalf("coverage = %q", rec.Coverage)
	}
}

func TestObservePayloadBudget(t *testing.T) {
	t.Parallel()

	fixture := newELFFixture(t, fixtureOptions{extraSymbols: 400})
	rec := observeFixture(t, fixture.data, Options{PayloadBytes: MinPayloadBytes})

	payload := decodePayload(t, rec)
	if len(payload.Symbols) == 0 || len(payload.Symbols) >= 402 {
		t.Fatalf("symbol count = %d, want a trimmed prefix", len(payload.Symbols))
	}
	if payload.Symbols[0].TableIndex != 5 || payload.Symbols[0].Index != 0 {
		t.Fatalf("first symbol = %+v", payload.Symbols[0])
	}
	for i, sym := range payload.Symbols {
		if sym.Index != i {
			t.Fatalf("symbol %d index = %d, prefix is not contiguous", i, sym.Index)
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

func TestObserveNoteDescriptorLimit(t *testing.T) {
	t.Parallel()

	fixture := newELFFixture(t, fixtureOptions{descSize: 5000})
	rec := observeFixture(t, fixture.data, Options{})

	payload := decodePayload(t, rec)
	if len(payload.Notes) != 1 {
		t.Fatalf("note count = %d", len(payload.Notes))
	}
	note := payload.Notes[0]
	if note.DescriptorHex != nil {
		t.Fatalf("oversized descriptor hex was inlined")
	}
	if note.DescriptorSHA256 != sha256Hex(fixture.buildID()) || note.DescriptorSize != 5000 {
		t.Fatalf("note = %+v", note)
	}
	if payload.BuildID != nil {
		t.Fatalf("build id above the build-id limit was accepted: %+v", payload.BuildID)
	}
	if !hasStatement(rec.Limitations, "GNU build-id unavailable") {
		t.Fatalf("limitations = %v", rec.Limitations)
	}
}

// failingReader fails only inside a byte range so parsing can succeed while the
// full-artifact digest pass fails.
type failingReader struct {
	data  []byte
	start int64
	end   int64
}

func (r failingReader) ReadAt(p []byte, off int64) (int, error) {
	if off < r.end && off+int64(len(p)) > r.start {
		return 0, io.ErrUnexpectedEOF
	}
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	return copy(p, r.data[off:]), nil
}

func TestObserveReaderFailure(t *testing.T) {
	t.Parallel()

	fixture := newELFFixture(t, fixtureOptions{})
	reader := failingReader{
		data:  fixture.data,
		start: int64(fixture.textOff),
		end:   int64(fixture.textOff + 8),
	}
	if _, err := Observe(reader, int64(len(fixture.data)), Options{ProviderVersion: "test"}); !errors.Is(err, reeelf.ErrRead) {
		t.Fatalf("Observe() error = %v, want ErrRead", err)
	}
}

// offsetFailReader fails only for one exact read offset so parsing, the
// subject digest pass, and earlier table reads can succeed.
type offsetFailReader struct {
	data []byte
	off  int64
}

func (r offsetFailReader) ReadAt(p []byte, off int64) (int, error) {
	if off == r.off {
		return 0, io.ErrUnexpectedEOF
	}
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	return copy(p, r.data[off:]), nil
}

func TestObserveReadFailurePerTable(t *testing.T) {
	t.Parallel()

	fixture := newELFFixture(t, fixtureOptions{})

	tests := []struct {
		name string
		opts Options
		off  int64
	}{
		{name: "section content digest", opts: Options{}, off: int64(fixture.textOff)},
		{name: "symbols", opts: Options{ContentBytes: 1}, off: int64(fixture.symtabOff)},
		{name: "relocations", opts: Options{ContentBytes: 1}, off: int64(fixture.relOff)},
		{name: "notes", opts: Options{ContentBytes: 1}, off: int64(fixture.noteOff)},
		{name: "comments", opts: Options{ContentBytes: 1}, off: int64(fixture.commentOff)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			test.opts.ProviderVersion = "test"
			reader := offsetFailReader{data: fixture.data, off: test.off}
			if _, err := Observe(reader, int64(len(fixture.data)), test.opts); !errors.Is(err, reeelf.ErrRead) {
				t.Fatalf("Observe() error = %v, want ErrRead", err)
			}
		})
	}
}
