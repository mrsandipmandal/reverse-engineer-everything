package elf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	reeelf "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/elf"
)

func TestOptionsWithDefaults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		in          Options
		wantPayload int
		wantContent int64
	}{
		{name: "zero selects defaults", in: Options{}, wantPayload: DefaultPayloadBytes, wantContent: DefaultContentBytes},
		{name: "below minimum", in: Options{PayloadBytes: 1, ContentBytes: 1}, wantPayload: MinPayloadBytes, wantContent: 1},
		{name: "above maximum", in: Options{PayloadBytes: MaxPayloadBytes + 1, ContentBytes: MaxContentBytes + 1}, wantPayload: MaxPayloadBytes, wantContent: MaxContentBytes},
		{name: "negative selects defaults", in: Options{PayloadBytes: -1, ContentBytes: -1}, wantPayload: DefaultPayloadBytes, wantContent: DefaultContentBytes},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := test.in.withDefaults()
			if got.PayloadBytes != test.wantPayload {
				t.Fatalf("payload bytes = %d, want %d", got.PayloadBytes, test.wantPayload)
			}
			if got.ContentBytes != test.wantContent {
				t.Fatalf("content bytes = %d, want %d", got.ContentBytes, test.wantContent)
			}
		})
	}
}

func TestPayloadBudget(t *testing.T) {
	t.Parallel()

	t.Run("shares leave the remainder for later tables", func(t *testing.T) {
		t.Parallel()

		budget := newPayloadBudget(1000)
		budget.start(25)
		if budget.allowance != 250 {
			t.Fatalf("sections allowance = %d", budget.allowance)
		}
		budget.add(100)
		budget.finish()
		if budget.remaining != 900 {
			t.Fatalf("remaining = %d", budget.remaining)
		}
		budget.start(10)
		if budget.allowance != 120 {
			t.Fatalf("segments allowance = %d", budget.allowance)
		}
		budget.finish()
	})

	t.Run("zero budget admits nothing", func(t *testing.T) {
		t.Parallel()

		budget := newPayloadBudget(0)
		budget.start(25)
		if budget.fits(0) != true || budget.fits(1) != false {
			t.Fatalf("zero budget accepted an entry")
		}
	})

	t.Run("reserve never goes negative", func(t *testing.T) {
		t.Parallel()

		budget := newPayloadBudget(10)
		budget.reserve(50)
		if budget.remaining != 0 {
			t.Fatalf("remaining = %d", budget.remaining)
		}
		budget.start(100)
		if budget.fits(1) {
			t.Fatalf("empty budget accepted content")
		}
	})

	t.Run("negative total is treated as zero", func(t *testing.T) {
		t.Parallel()

		budget := newPayloadBudget(-1)
		if budget.remaining != 0 {
			t.Fatalf("remaining = %d", budget.remaining)
		}
	})

	t.Run("exhausted shares admit nothing", func(t *testing.T) {
		t.Parallel()

		budget := newPayloadBudget(100)
		budget.start(100)
		if budget.allowance != 100 {
			t.Fatalf("allowance = %d", budget.allowance)
		}
		budget.add(100)
		budget.finish()
		budget.start(1)
		if budget.fits(1) {
			t.Fatalf("exhausted budget accepted an entry")
		}
	})
}

func TestCollector(t *testing.T) {
	t.Parallel()

	t.Run("deduplicates", func(t *testing.T) {
		t.Parallel()

		c := &collector{}
		c.addLimitation("a")
		c.addLimitation("a")
		c.addLimitation("")
		c.addUnknown("b")
		c.addUnknown("b")
		c.addUnknown("")
		limitations, unknowns := c.finish()
		if len(limitations) != 1 || limitations[0] != "a" {
			t.Fatalf("limitations = %v", limitations)
		}
		if len(unknowns) != 1 || unknowns[0] != "b" {
			t.Fatalf("unknowns = %v", unknowns)
		}
	})

	t.Run("caps limitations", func(t *testing.T) {
		t.Parallel()

		c := &collector{}
		for i := 0; i < maxRecordLimitations+10; i++ {
			c.addLimitation(strings.Repeat("x", i+1))
		}
		limitations, _ := c.finish()
		if len(limitations) != maxRecordLimitations {
			t.Fatalf("limitation count = %d", len(limitations))
		}
		if limitations[len(limitations)-1] != "additional limitations omitted" {
			t.Fatalf("last limitation = %q", limitations[len(limitations)-1])
		}
	})

	t.Run("caps unknowns", func(t *testing.T) {
		t.Parallel()

		c := &collector{}
		for i := 0; i < maxRecordUnknowns+10; i++ {
			c.addUnknown(strings.Repeat("y", i+1))
		}
		_, unknowns := c.finish()
		if len(unknowns) != maxRecordUnknowns {
			t.Fatalf("unknown count = %d", len(unknowns))
		}
		if unknowns[len(unknowns)-1] != "additional unknowns omitted" {
			t.Fatalf("last unknown = %q", unknowns[len(unknowns)-1])
		}
	})

	t.Run("returns copies", func(t *testing.T) {
		t.Parallel()

		c := &collector{}
		c.addLimitation("a")
		limitations, _ := c.finish()
		limitations[0] = "changed"
		again, _ := c.finish()
		if again[0] != "a" {
			t.Fatalf("finish returned shared storage")
		}
	})
}

func TestFailureTally(t *testing.T) {
	t.Parallel()

	var tally failureTally
	tally.fail(nil)
	tally.fail(errors.New("first"))
	tally.fail(errors.New("second"))
	if tally.count != 2 || tally.first != "first" {
		t.Fatalf("tally = %+v", tally)
	}
}

func TestCollectUnknowns(t *testing.T) {
	t.Parallel()

	file := &reeelf.File{SectionHeaders: []reeelf.SectionHeader{
		{Type: sectionTypeGNUVersym},
		{Type: sectionTypeDynamic},
		{Flags: sectionFlagCompressed},
	}}
	notes := &collector{}
	payload := Payload{Relocations: []PayloadRelocation{{HasAddend: false}}}
	collectUnknowns(file, &payload, notes)

	_, unknowns := notes.finish()
	if len(unknowns) != 4 {
		t.Fatalf("unknowns = %v", unknowns)
	}

	clean := &collector{}
	collectUnknowns(&reeelf.File{}, &Payload{Relocations: []PayloadRelocation{{HasAddend: true}}}, clean)
	if _, unknown := clean.finish(); len(unknown) != 0 {
		t.Fatalf("unexpected unknowns = %v", unknown)
	}
}

func TestJSONSize(t *testing.T) {
	t.Parallel()

	if size := jsonSize(map[string]string{"a": "b"}); size != len(`{"a":"b"}`) {
		t.Fatalf("jsonSize = %d", size)
	}
	if size := jsonSize(func() {}); size != 0 {
		t.Fatalf("jsonSize of an unmarshalable value = %d", size)
	}
}

func TestUint64String(t *testing.T) {
	t.Parallel()

	if got := uint64String(1 << 63); got != "9223372036854775808" {
		t.Fatalf("uint64String = %q", got)
	}
	if got := int64String(-1 << 63); got != "-9223372036854775808" {
		t.Fatalf("int64String = %q", got)
	}
}

func TestContentHasherUnavailable(t *testing.T) {
	t.Parallel()

	fixture := newELFFixture(t, fixtureOptions{})
	// Point .text beyond the artifact so its content is unavailable.
	binary.LittleEndian.PutUint64(fixture.data[fixture.shOff+64+24:], uint64(len(fixture.data)+64))

	rec := observeFixture(t, fixture.data, Options{})
	payload := decodePayload(t, rec)
	if payload.Sections[1].DataSHA256 != nil {
		t.Fatalf("unavailable section has a digest")
	}
	if !hasStatement(rec.Limitations, "section or segment digests unavailable") {
		t.Fatalf("limitations = %v", rec.Limitations)
	}
}

func TestContentHasherLimitFailure(t *testing.T) {
	t.Parallel()

	fixture := newELFFixture(t, fixtureOptions{})
	limits := reeelf.DefaultLimits()
	limits.SectionDataBytes = 4
	rec := observeFixture(t, fixture.data, Options{Limits: limits})

	payload := decodePayload(t, rec)
	if payload.Sections[1].DataSHA256 != nil {
		t.Fatalf("over-limit section has a digest")
	}
	if payload.Segments[0].DataSHA256 == nil {
		t.Fatalf("segment digest missing")
	}
	if !hasStatement(rec.Limitations, "section or segment digests failed") {
		t.Fatalf("limitations = %v", rec.Limitations)
	}
}

func TestBuildTablesWithExhaustedBudget(t *testing.T) {
	t.Parallel()

	fixture := newELFFixture(t, fixtureOptions{})
	file, err := reeelf.Parse(bytes.NewReader(fixture.data), int64(len(fixture.data)))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	payload := &Payload{}
	notes := &collector{}
	hasher := newContentHasher(file, 0)

	if err := buildSections(file, payload, newPayloadBudget(0), hasher, &failureTally{}, notes); err != nil {
		t.Fatalf("buildSections() error = %v", err)
	}
	if err := buildSegments(file, payload, newPayloadBudget(0), hasher, notes); err != nil {
		t.Fatalf("buildSegments() error = %v", err)
	}
	if err := buildSymbols(file, payload, newPayloadBudget(0), notes); err != nil {
		t.Fatalf("buildSymbols() error = %v", err)
	}
	if err := buildRelocations(file, payload, newPayloadBudget(0), notes); err != nil {
		t.Fatalf("buildRelocations() error = %v", err)
	}
	if err := buildNotes(file, payload, newPayloadBudget(0), notes); err != nil {
		t.Fatalf("buildNotes() error = %v", err)
	}
	if err := buildComments(file, payload, newPayloadBudget(0), notes); err != nil {
		t.Fatalf("buildComments() error = %v", err)
	}

	if len(payload.Sections)+len(payload.Segments)+len(payload.Symbols)+
		len(payload.Relocations)+len(payload.Notes)+len(payload.Comments) != 0 {
		t.Fatalf("exhausted budget emitted entries: %+v", payload)
	}
	if payload.BuildID != nil {
		t.Fatalf("exhausted budget emitted the build-id")
	}

	limitations, _ := notes.finish()
	for _, fragment := range []string{
		"payload budget omitted 8 sections",
		"payload budget omitted 1 segments",
		"payload budget omitted 2 symbols",
		"payload budget omitted 2 relocations",
		"payload budget omitted the GNU build-id",
		"payload budget omitted 1 notes",
		"payload budget omitted 2 .comment entries",
	} {
		if !hasStatement(limitations, fragment) {
			t.Fatalf("limitations = %v, want %q", limitations, fragment)
		}
	}
}

func TestBuildCommentsWithoutSection(t *testing.T) {
	t.Parallel()

	fixture := newELFFixture(t, fixtureOptions{})
	// Rename .comment to .text so the artifact has no .comment section.
	binary.LittleEndian.PutUint32(fixture.data[fixture.shOff+2*64:], 1)

	file, err := reeelf.Parse(bytes.NewReader(fixture.data), int64(len(fixture.data)))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	payload := &Payload{}
	notes := &collector{}
	if err := buildComments(file, payload, newPayloadBudget(DefaultPayloadBytes), notes); err != nil {
		t.Fatalf("buildComments() error = %v", err)
	}
	if len(payload.Comments) != 0 {
		t.Fatalf("comments = %v", payload.Comments)
	}
	if limitations, _ := notes.finish(); len(limitations) != 0 {
		t.Fatalf("absent .comment produced limitations: %v", limitations)
	}
}

func TestBuildCommentsInvalidEntry(t *testing.T) {
	t.Parallel()

	fixture := newELFFixture(t, fixtureOptions{})
	fixture.data[fixture.commentOff] = 0xff

	file, err := reeelf.Parse(bytes.NewReader(fixture.data), int64(len(fixture.data)))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	payload := &Payload{}
	notes := &collector{}
	if err := buildComments(file, payload, newPayloadBudget(DefaultPayloadBytes), notes); err != nil {
		t.Fatalf("buildComments() error = %v", err)
	}
	limitations, _ := notes.finish()
	if !hasStatement(limitations, ".comment unavailable") {
		t.Fatalf("limitations = %v", limitations)
	}
}

func TestSegmentWithoutFileSize(t *testing.T) {
	t.Parallel()

	hasher := newContentHasher(&reeelf.File{}, DefaultContentBytes)
	if digest, err := hasher.segment(reeelf.ProgramHeader{}); err != nil || digest != nil {
		t.Fatalf("segment() = %v, %v", digest, err)
	}
}

func TestHashArtifactShortRead(t *testing.T) {
	t.Parallel()

	data := []byte("12345678")
	if _, err := hashArtifact(bytes.NewReader(data[:7]), int64(len(data))); !errors.Is(err, reeelf.ErrRead) {
		t.Fatalf("hashArtifact() error = %v, want ErrRead", err)
	}
}

func TestPayloadBudgetFinishClamps(t *testing.T) {
	t.Parallel()

	budget := newPayloadBudget(10)
	budget.start(100)
	budget.add(20)
	budget.finish()
	if budget.remaining != 0 {
		t.Fatalf("remaining = %d", budget.remaining)
	}
}
