package macho

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	remacho "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/macho"
)

func TestPayloadBudget(t *testing.T) {
	budget := newPayloadBudget(-1)
	if budget.remaining != 0 {
		t.Fatalf("negative budget remaining = %d", budget.remaining)
	}
	budget = newPayloadBudget(1000)
	budget.reserve(100)
	if budget.remaining != 900 {
		t.Fatalf("remaining = %d", budget.remaining)
	}
	budget.start(50)
	if budget.allowance != 450 {
		t.Fatalf("allowance = %d", budget.allowance)
	}
	if !budget.fits(450) || budget.fits(451) {
		t.Fatal("fits boundary wrong")
	}
	budget.add(200)
	budget.finish()
	if budget.remaining != 700 {
		t.Fatalf("remaining after finish = %d", budget.remaining)
	}
	budget.take(1000)
	if budget.remaining != 0 {
		t.Fatalf("clamped remaining = %d", budget.remaining)
	}
	budget.reserve(1000)
	if budget.remaining != 0 {
		t.Fatalf("clamped reserve = %d", budget.remaining)
	}
}

func TestJSONSize(t *testing.T) {
	if got := jsonSize("abc"); got != 5 {
		t.Fatalf("jsonSize = %d", got)
	}
	if got := jsonSize(func() {}); got != 0 {
		t.Fatalf("unmeasurable jsonSize = %d", got)
	}
}

func TestUint64String(t *testing.T) {
	if got := uint64String(1<<63 + 1); got != "9223372036854775809" {
		t.Fatalf("uint64String = %q", got)
	}
}

func TestCollectorBounds(t *testing.T) {
	notes := &collector{}
	for i := 0; i < 200; i++ {
		notes.addLimitation(fmt.Sprintf("limitation %d", i))
		notes.addUnknown(fmt.Sprintf("unknown %d", i))
	}
	limitations, unknowns := notes.finish()
	if len(limitations) != maxRecordLimitations {
		t.Fatalf("limitations = %d", len(limitations))
	}
	if limitations[len(limitations)-1] != "additional limitations omitted" {
		t.Fatalf("last limitation = %q", limitations[len(limitations)-1])
	}
	if len(unknowns) != maxRecordUnknowns {
		t.Fatalf("unknowns = %d", len(unknowns))
	}
	if unknowns[len(unknowns)-1] != "additional unknowns omitted" {
		t.Fatalf("last unknown = %q", unknowns[len(unknowns)-1])
	}

	dedupe := &collector{}
	dedupe.addLimitation("same")
	dedupe.addLimitation("same")
	dedupe.addLimitation("")
	dedupe.addUnknown("one")
	dedupe.addUnknown("one")
	limitations, unknowns = dedupe.finish()
	if len(limitations) != 1 || len(unknowns) != 1 {
		t.Fatalf("dedupe = %v %v", limitations, unknowns)
	}
}

func TestNoteTableError(t *testing.T) {
	notes := &collector{}
	if err := noteTableError(notes, 0, "table", nil); err != nil {
		t.Fatalf("nil error = %v", err)
	}
	if err := noteTableError(notes, 0, "table", remacho.ErrNotFound); err != nil {
		t.Fatalf("not found = %v", err)
	}
	if len(notes.limitations) != 0 {
		t.Fatalf("absence produced limitations: %v", notes.limitations)
	}
	readErr := fmt.Errorf("%w: boom", remacho.ErrRead)
	if err := noteTableError(notes, 1, "table", readErr); !errors.Is(err, remacho.ErrRead) {
		t.Fatalf("read error = %v", err)
	}
	if err := noteTableError(notes, 2, "table", remacho.ErrUnavailable); err != nil {
		t.Fatalf("unavailable error = %v", err)
	}
	if len(notes.limitations) != 1 || !strings.Contains(notes.limitations[0], "slice 2 table unavailable") {
		t.Fatalf("limitations = %v", notes.limitations)
	}
}

func TestInstallNameAbsent(t *testing.T) {
	if got := installName([]remacho.Dylib{{Command: remacho.CommandLoadDylib, Name: "x"}}); got != nil {
		t.Fatalf("installName = %+v", got)
	}
}

func TestBuildPayloadSliceErrors(t *testing.T) {
	artifact := &remacho.Artifact{
		Magic: remacho.Magic64,
		Slices: []remacho.Slice{{
			Index: 0,
			Err:   fmt.Errorf("%w: boom", remacho.ErrRead),
		}},
	}
	if _, err := buildPayload(artifact, Options{PayloadBytes: 4096, ContentBytes: 1024}, &collector{}); !errors.Is(err, remacho.ErrRead) {
		t.Fatalf("read failure = %v", err)
	}

	artifact = &remacho.Artifact{
		Magic:       remacho.Magic64,
		Fat:         true,
		Truncated:   true,
		Limitations: []string{"artifact limitation"},
		Slices: []remacho.Slice{{
			Index: 1,
			Err:   fmt.Errorf("%w: bad slice", remacho.ErrInvalid),
		}},
	}
	notes := &collector{}
	payload, err := buildPayload(artifact, Options{PayloadBytes: 4096, ContentBytes: 1024}, notes)
	if err != nil {
		t.Fatalf("buildPayload: %v", err)
	}
	if len(payload.Slices) != 1 || payload.Slices[0].Status != statusInvalid {
		t.Fatalf("slices = %+v", payload.Slices)
	}
	if len(payload.Slices[0].Limitations) != 1 {
		t.Fatalf("slice limitations = %v", payload.Slices[0].Limitations)
	}
	limitations, _ := notes.finish()
	if !contains(limitations, "artifact limitation") || !contains(limitations, "artifact header coverage is partial") {
		t.Fatalf("limitations = %v", limitations)
	}
}

func TestBuildTableOmissions(t *testing.T) {
	thinData := buildFixture(t, defaultFixture())
	thin, err := remacho.Parse(bytes.NewReader(thinData), int64(len(thinData)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	data := metadataImage(t, defaultMetadataFixture())
	artifact, err := remacho.Parse(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	file := artifact.Slices[0].File
	hasher := newContentHasher(1024)
	notes := &collector{}

	closed := newPayloadBudget(0)
	closed.start(shareSegments)
	if segments := buildSegments(thin.Slices[0].File, notes, closed); len(segments) != 0 {
		t.Fatalf("segments = %d", len(segments))
	}
	closed.finish()

	closed = newPayloadBudget(0)
	closed.start(shareSections)
	sections, err := buildSections(thin.Slices[0].File, hasher, notes, closed)
	if err != nil || len(sections) != 0 {
		t.Fatalf("sections = %d, %v", len(sections), err)
	}
	closed.finish()

	closed = newPayloadBudget(0)
	closed.start(shareDylibs)
	dylibs, err := buildDylibs(file, notes, 0, closed)
	if err != nil || dylibs == nil || !dylibs.Truncated || len(dylibs.Dylibs) != 0 {
		t.Fatalf("dylibs = %+v, %v", dylibs, err)
	}
	closed.finish()

	closed = newPayloadBudget(0)
	closed.start(shareSymbols)
	symbols, err := buildSymbols(file, notes, 0, closed)
	if err != nil || symbols == nil || !symbols.Truncated || len(symbols.Symbols) != 0 {
		t.Fatalf("symbols = %+v, %v", symbols, err)
	}
	closed.finish()

	closed = newPayloadBudget(0)
	closed.start(shareCodeSignature)
	signature, err := buildCodeSignature(file, notes, 0, closed)
	if err != nil || signature == nil || !signature.Truncated || len(signature.Blobs) != 0 {
		t.Fatalf("signature = %+v, %v", signature, err)
	}
	closed.finish()

	limitations, _ := notes.finish()
	want := []string{
		"payload budget omitted 1 segments",
		"payload budget omitted 2 sections",
		"payload budget omitted 2 dylib commands",
		"payload budget omitted 2 symbols",
		"payload budget omitted 2 signature blobs",
	}
	for _, limitation := range want {
		if !contains(limitations, limitation) {
			t.Fatalf("limitations = %v, want %q", limitations, limitation)
		}
	}
}

func TestHasherUnavailable(t *testing.T) {
	data := buildFixture(t, defaultFixture())
	artifact, err := remacho.Parse(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	file := artifact.Slices[0].File
	file.Sections[0].Size = 1 << 40
	hasher := newContentHasher(1 << 42)
	digest, err := hasher.section(file, &file.Sections[0])
	if err != nil {
		t.Fatalf("section: %v", err)
	}
	if digest != nil {
		t.Fatalf("digest = %q", *digest)
	}
	if hasher.unavailable != 1 || hasher.firstUnavailable == "" {
		t.Fatalf("hasher = %+v", hasher)
	}

	notes := &collector{}
	reportHashing(hasher, notes)
	if len(notes.limitations) != 1 || !strings.Contains(notes.limitations[0], "section digests unavailable") {
		t.Fatalf("limitations = %v", notes.limitations)
	}
}

func TestCodeSignaturePresent(t *testing.T) {
	if codeSignaturePresent(&Payload{}) {
		t.Fatal("empty payload reports a signature")
	}
	payload := &Payload{Slices: []PayloadSlice{{}, {CodeSignature: &PayloadCodeSignature{}}}}
	if !codeSignaturePresent(payload) {
		t.Fatal("signature not detected")
	}
}
