package pe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	repe "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/pe"
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
		if !budget.fits(0) || budget.fits(1) {
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

func TestNoteUnavailable(t *testing.T) {
	t.Parallel()

	t.Run("reader failure propagates", func(t *testing.T) {
		t.Parallel()

		notes := &collector{}
		if err := noteUnavailable(notes, "import", repe.ErrRead); !errors.Is(err, repe.ErrRead) {
			t.Fatalf("noteUnavailable() error = %v", err)
		}
		if limitations, _ := notes.finish(); len(limitations) != 0 {
			t.Fatalf("limitations = %v", limitations)
		}
	})

	t.Run("absent directory is not a limitation", func(t *testing.T) {
		t.Parallel()

		notes := &collector{}
		if err := noteUnavailable(notes, "import", repe.ErrNotFound); err != nil {
			t.Fatalf("noteUnavailable() error = %v", err)
		}
		if limitations, _ := notes.finish(); len(limitations) != 0 {
			t.Fatalf("limitations = %v", limitations)
		}
	})

	t.Run("other errors become limitations", func(t *testing.T) {
		t.Parallel()

		notes := &collector{}
		if err := noteUnavailable(notes, "import", repe.ErrInvalid); err != nil {
			t.Fatalf("noteUnavailable() error = %v", err)
		}
		if limitations, _ := notes.finish(); len(limitations) != 1 ||
			!strings.Contains(limitations[0], "import directory unavailable") {
			t.Fatalf("limitations = %v", limitations)
		}
	})
}

func TestCollectUnknowns(t *testing.T) {
	t.Parallel()

	file := &repe.File{
		Header: repe.Header{PointerToSymbolTable: 1, NumberOfSymbols: 1},
		DataDirectories: []repe.DataDirectory{
			{Index: 5, VirtualAddress: 0x1000, Size: 1},
			{Index: 6, VirtualAddress: 0x1000, Size: 1},
			{Index: 9, VirtualAddress: 0x1000, Size: 1},
			{Index: 11, VirtualAddress: 0x1000, Size: 1},
			{Index: 13, VirtualAddress: 0x1000, Size: 1},
			{Index: 14, VirtualAddress: 0x1000, Size: 1},
			{Index: 15, VirtualAddress: 0, Size: 0},
		},
	}
	payload := &Payload{
		Certificates: &PayloadCertificates{Certificates: []PayloadCertificate{{}}},
		Resources:    &PayloadResources{Resources: []PayloadResource{{}}},
	}
	notes := &collector{}
	collectUnknowns(file, payload, notes)

	_, unknowns := notes.finish()
	if len(unknowns) != 9 {
		t.Fatalf("unknowns = %v", unknowns)
	}

	clean := &collector{}
	collectUnknowns(&repe.File{}, &Payload{}, clean)
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
}

func TestContentHasherCache(t *testing.T) {
	t.Parallel()

	hasher := newContentHasher(&repe.File{}, 100)
	reads := 0
	read := func() ([]byte, error) {
		reads++
		return []byte("payload"), nil
	}
	key := contentKey{offset: 0x10, size: 7}
	first, err := hasher.digest(key, read)
	if err != nil || first == nil {
		t.Fatalf("digest() = %v, %v", first, err)
	}
	second, err := hasher.digest(key, read)
	if err != nil || second == nil || *second != *first {
		t.Fatalf("second digest() = %v, %v", second, err)
	}
	if reads != 1 {
		t.Fatalf("read count = %d, want one cached read", reads)
	}
}

func TestContentHasherBudget(t *testing.T) {
	t.Parallel()

	hasher := newContentHasher(&repe.File{}, 4)
	reads := 0
	digest, err := hasher.digest(contentKey{size: 8}, func() ([]byte, error) {
		reads++
		return make([]byte, 8), nil
	})
	if err != nil || digest != nil {
		t.Fatalf("digest() = %v, %v", digest, err)
	}
	if reads != 0 || hasher.omitted != 1 {
		t.Fatalf("reads = %d, omitted = %d", reads, hasher.omitted)
	}
}

func TestContentHasherFailures(t *testing.T) {
	t.Parallel()

	t.Run("read failure propagates", func(t *testing.T) {
		t.Parallel()

		hasher := newContentHasher(&repe.File{}, 100)
		_, err := hasher.digest(contentKey{size: 8}, func() ([]byte, error) {
			return nil, repe.ErrRead
		})
		if !errors.Is(err, repe.ErrRead) {
			t.Fatalf("digest() error = %v", err)
		}
	})

	t.Run("unavailable content is counted", func(t *testing.T) {
		t.Parallel()

		hasher := newContentHasher(&repe.File{}, 100)
		digest, err := hasher.digest(contentKey{size: 8}, func() ([]byte, error) {
			return nil, repe.ErrUnavailable
		})
		if err != nil || digest != nil || hasher.unavailable != 1 || hasher.firstUnavailable == "" {
			t.Fatalf("digest() = %v, %v; hasher = %+v", digest, err, hasher)
		}
	})

	t.Run("limit failure is counted as unavailable", func(t *testing.T) {
		t.Parallel()

		hasher := newContentHasher(&repe.File{}, 100)
		digest, err := hasher.digest(contentKey{size: 8}, func() ([]byte, error) {
			return nil, repe.ErrLimit
		})
		if err != nil || digest != nil || hasher.unavailable != 1 {
			t.Fatalf("digest() = %v, %v; hasher = %+v", digest, err, hasher)
		}
	})

	t.Run("other failures are counted", func(t *testing.T) {
		t.Parallel()

		hasher := newContentHasher(&repe.File{}, 100)
		digest, err := hasher.digest(contentKey{size: 8}, func() ([]byte, error) {
			return nil, errors.New("boom")
		})
		if err != nil || digest != nil || hasher.failed != 1 || hasher.firstFailure != "boom" {
			t.Fatalf("digest() = %v, %v; hasher = %+v", digest, err, hasher)
		}
	})
}

func TestContentHasherSection(t *testing.T) {
	t.Parallel()

	t.Run("empty section has no digest", func(t *testing.T) {
		t.Parallel()

		hasher := newContentHasher(&repe.File{}, DefaultContentBytes)
		digest, err := hasher.section(repe.SectionHeader{SizeOfRawData: 0})
		if err != nil || digest != nil {
			t.Fatalf("section() = %v, %v", digest, err)
		}
	})

	t.Run("unavailable section is counted", func(t *testing.T) {
		t.Parallel()

		fixture := newPEFixture(t, fixtureOptions{})
		data := append([]byte(nil), fixture.data...)
		binary.LittleEndian.PutUint32(data[fixture.sectionTableOffset+20:], uint32(len(data)+0x100))
		file, err := repe.Parse(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		hasher := newContentHasher(file, DefaultContentBytes)
		digest, err := hasher.section(file.Sections[0])
		if err != nil || digest != nil || hasher.unavailable != 1 {
			t.Fatalf("section() = %v, %v; hasher = %+v", digest, err, hasher)
		}
	})

	t.Run("over-limit section is counted", func(t *testing.T) {
		t.Parallel()

		fixture := newPEFixture(t, fixtureOptions{})
		limits := repe.DefaultLimits()
		limits.SectionDataBytes = 4
		file, err := repe.ParseWithLimits(bytes.NewReader(fixture.data), int64(len(fixture.data)), limits)
		if err != nil {
			t.Fatalf("ParseWithLimits() error = %v", err)
		}
		hasher := newContentHasher(file, DefaultContentBytes)
		digest, err := hasher.section(file.Sections[0])
		if err != nil || digest != nil || hasher.unavailable != 1 {
			t.Fatalf("section() = %v, %v; hasher = %+v", digest, err, hasher)
		}
	})
}

func TestBuildPayloadExhaustedBudget(t *testing.T) {
	t.Parallel()

	fixture := newPEFixture(t, fixtureOptions{certificates: 2})
	file := fixture.parse(t)
	notes := &collector{}
	payload, err := buildPayload(file, Options{PayloadBytes: 0, ContentBytes: 1}, notes)
	if err != nil {
		t.Fatalf("buildPayload() error = %v", err)
	}

	if len(payload.Sections) != 0 {
		t.Fatalf("sections = %+v", payload.Sections)
	}
	if payload.Imports == nil || len(payload.Imports.Modules) != 0 || !payload.Imports.Truncated {
		t.Fatalf("imports = %+v", payload.Imports)
	}
	if payload.Exports == nil || len(payload.Exports.Exports) != 0 || !payload.Exports.Truncated {
		t.Fatalf("exports = %+v", payload.Exports)
	}
	if payload.Resources == nil || len(payload.Resources.Resources) != 0 || !payload.Resources.Truncated {
		t.Fatalf("resources = %+v", payload.Resources)
	}
	if payload.Certificates == nil || len(payload.Certificates.Certificates) != 0 || !payload.Certificates.Truncated {
		t.Fatalf("certificates = %+v", payload.Certificates)
	}

	limitations, _ := notes.finish()
	for _, fragment := range []string{
		"payload budget omitted 1 sections",
		"payload budget omitted 2 import modules",
		"payload budget omitted 3 import thunks",
		"payload budget omitted 3 exports",
		"payload budget omitted 1 resources",
		"payload budget omitted 2 certificates",
	} {
		if !hasStatement(limitations, fragment) {
			t.Fatalf("limitations = %v, want %q", limitations, fragment)
		}
	}
}
