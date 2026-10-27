package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/canonical"
	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
)

const (
	goldenBundleDigest = "d96b0340592cc1822ead1bd390b8e1de6b0fd5c6ebad822019a3edccd55957ec"
	goldenRecordA      = "0c0644222654a35f8435654f47e1ef73a48c4f04c1f38a23764629a6baaea464"
	goldenRecordB      = "b00cf45d7c1722453719ecad81f8aa9e7c6fee98141b0d8971748a428dbd5d9c"
	recordASubject     = "c7c5c1d70c5dec4416ab6158afd0b223ef40c29b1dc1f97ed9428b94d4cadb1c"
	recordBSubject     = "6462d191923d0d849234de241cf341d949f88488593f29e3601b94bd645b7dee"
)

func recordA() evidence.Evidence {
	return evidence.Evidence{
		Subject:     evidence.Subject{SHA256: recordASubject, Size: 8},
		Provider:    evidence.Provider{ID: "builtin.example", Version: "1.0.0", Profile: "default"},
		Authority:   evidence.AuthorityObserved,
		Coverage:    evidence.CoveragePartial,
		Limitations: []string{"fixture covers one artifact only"},
		Unknowns:    []string{"other platforms were not examined"},
		Payload:     json.RawMessage(`{"arch":"amd64","format":"elf"}`),
	}
}

func recordB() evidence.Evidence {
	return evidence.Evidence{
		Subject:     evidence.Subject{SHA256: recordBSubject, Size: 10},
		Provider:    evidence.Provider{ID: "builtin.example", Version: "1.0.0", Profile: "default"},
		Authority:   evidence.AuthorityDerived,
		Coverage:    evidence.CoverageComplete,
		Limitations: []string{},
		Unknowns:    []string{},
		Payload:     json.RawMessage(`{"format":"pe"}`),
	}
}

func goldenBundle(t *testing.T) []byte {
	t.Helper()

	data, err := os.ReadFile("testdata/bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(data)
}

func mustEncodeRecord(t *testing.T, record evidence.Evidence) json.RawMessage {
	t.Helper()

	data, err := evidence.Encode(record)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func buildBundle(t *testing.T, records []json.RawMessage) []byte {
	t.Helper()

	sum, err := documentDigest(records)
	if err != nil {
		t.Fatal(err)
	}
	data, err := encodeDocument(records, integrity{Algorithm: AlgorithmSHA256, Digest: sum})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func canonicalize(t *testing.T, document string) []byte {
	t.Helper()

	data, err := canonical.Bytes([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestGolden(t *testing.T) {
	t.Parallel()

	want := goldenBundle(t)
	got, err := Export([]evidence.Evidence{recordB(), recordA()})
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Export() = %s, want %s", got, want)
	}

	doc, err := decodeDocument(want)
	if err != nil {
		t.Fatalf("decodeDocument() error = %v", err)
	}
	if doc.integrity.Digest != goldenBundleDigest {
		t.Fatalf("bundle digest = %q, want %q", doc.integrity.Digest, goldenBundleDigest)
	}
	if len(doc.records) != 2 {
		t.Fatalf("records = %d, want 2", len(doc.records))
	}
	if got := canonical.SHA256(doc.records[0]); got != goldenRecordA {
		t.Fatalf("first record digest = %q, want %q", got, goldenRecordA)
	}
	if got := canonical.SHA256(doc.records[1]); got != goldenRecordB {
		t.Fatalf("second record digest = %q, want %q", got, goldenRecordB)
	}

	records, err := Import(want)
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("Import() returned %d records, want 2", len(records))
	}
	if records[0].Subject.SHA256 != recordASubject || string(records[0].Payload) != `{"arch":"amd64","format":"elf"}` {
		t.Fatalf("first imported record = %+v", records[0])
	}
	if records[1].Subject.SHA256 != recordBSubject || string(records[1].Payload) != `{"format":"pe"}` {
		t.Fatalf("second imported record = %+v", records[1])
	}
}

func TestExportDeterministic(t *testing.T) {
	t.Parallel()

	first, err := Export([]evidence.Evidence{recordA(), recordB()})
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	second, err := Export([]evidence.Evidence{recordB(), recordA()})
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("record order changed the bundle: %s then %s", first, second)
	}

	empty, err := Export(nil)
	if err != nil {
		t.Fatalf("Export(nil) error = %v", err)
	}
	if !strings.Contains(string(empty), `"records":[]`) {
		t.Fatalf("empty bundle records are not an array: %s", empty)
	}
	records, err := Import(empty)
	if err != nil {
		t.Fatalf("Import(empty) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Import(empty) returned %d records", len(records))
	}
	again, err := Export(records)
	if err != nil {
		t.Fatalf("Export(empty records) error = %v", err)
	}
	if !bytes.Equal(empty, again) {
		t.Fatalf("empty bundle round trip changed bytes: %s then %s", empty, again)
	}
}

func TestExportRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		records []evidence.Evidence
		wantErr error
	}{
		{
			name:    "duplicate record",
			records: []evidence.Evidence{recordA(), recordA()},
			wantErr: ErrDuplicateRecord,
		},
		{
			name:    "too many records",
			records: make([]evidence.Evidence, MaxRecords+1),
			wantErr: ErrLimit,
		},
		{
			name:    "invalid record",
			records: []evidence.Evidence{{}},
			wantErr: ErrInvalid,
		},
		{
			name: "record over payload limit",
			records: []evidence.Evidence{{
				Subject:     recordA().Subject,
				Provider:    recordA().Provider,
				Authority:   evidence.AuthorityObserved,
				Coverage:    evidence.CoveragePartial,
				Limitations: []string{},
				Unknowns:    []string{},
				Payload:     json.RawMessage(`"` + strings.Repeat("a", evidence.MaxPayloadBytes) + `"`),
			}},
			wantErr: ErrLimit,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := Export(tt.records); !errors.Is(err, tt.wantErr) {
				t.Fatalf("Export() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestImportRejects(t *testing.T) {
	t.Parallel()

	golden := string(goldenBundle(t))
	zeroDigest := strings.Repeat("0", 64)
	replace := func(old, replacement string) []byte {
		t.Helper()
		if !strings.Contains(golden, old) {
			t.Fatalf("golden bundle does not contain %q", old)
		}
		return []byte(strings.Replace(golden, old, replacement, 1))
	}

	tests := []struct {
		name    string
		input   []byte
		wantErr error
	}{
		{name: "empty", input: nil, wantErr: ErrInvalid},
		{name: "null", input: []byte(`null`), wantErr: ErrInvalid},
		{name: "array", input: []byte(`[]`), wantErr: ErrInvalid},
		{name: "leading whitespace", input: append([]byte(" "), golden...), wantErr: ErrNotCanonical},
		{name: "trailing newline", input: append([]byte(golden), '\n'), wantErr: ErrNotCanonical},
		{
			name: "reordered members",
			input: func() []byte {
				withoutSchema := strings.Replace(golden, `,"schema":"ree.bundle/1"`, ``, 1)
				return []byte(`{"schema":"ree.bundle/1",` + withoutSchema[1:])
			}(),
			wantErr: ErrNotCanonical,
		},
		{name: "unknown member", input: replace(`{"integrity"`, `{"aa":1,"integrity"`), wantErr: ErrInvalid},
		{name: "wrong schema", input: replace(`"ree.bundle/1"`, `"ree.bundle/2"`), wantErr: ErrUnsupportedSchema},
		{name: "tampered record", input: replace(`"arch":"amd64"`, `"arch":"arm64"`), wantErr: ErrDigestMismatch},
		{name: "wrong algorithm", input: replace(`"algorithm":"sha256"`, `"algorithm":"md5"`), wantErr: ErrUnsupportedAlgorithm},
		{name: "malformed digest", input: replace(goldenBundleDigest, "abc"), wantErr: ErrInvalid},
		{name: "zeroed digest", input: replace(goldenBundleDigest, zeroDigest), wantErr: ErrDigestMismatch},
		{
			name:    "missing records",
			input:   canonicalize(t, `{"integrity":{"algorithm":"sha256","digest":"`+zeroDigest+`"},"schema":"ree.bundle/1"}`),
			wantErr: ErrInvalid,
		},
		{
			name:    "null records",
			input:   canonicalize(t, `{"integrity":{"algorithm":"sha256","digest":"`+zeroDigest+`"},"records":null,"schema":"ree.bundle/1"}`),
			wantErr: ErrInvalid,
		},
		{
			name:    "records not an array",
			input:   canonicalize(t, `{"integrity":{"algorithm":"sha256","digest":"`+zeroDigest+`"},"records":{},"schema":"ree.bundle/1"}`),
			wantErr: ErrInvalid,
		},
		{
			name:    "missing integrity",
			input:   canonicalize(t, `{"records":[],"schema":"ree.bundle/1"}`),
			wantErr: ErrInvalid,
		},
		{
			name:    "case-variant member",
			input:   canonicalize(t, `{"Schema":"ree.bundle/1","integrity":{"algorithm":"sha256","digest":"`+zeroDigest+`"},"records":[]}`),
			wantErr: ErrInvalid,
		},
		{
			name:    "case-variant nested member",
			input:   canonicalize(t, `{"integrity":{"Algorithm":"sha256","digest":"`+zeroDigest+`"},"records":[],"schema":"ree.bundle/1"}`),
			wantErr: ErrInvalid,
		},
		{
			name:    "invalid record",
			input:   buildBundle(t, []json.RawMessage{json.RawMessage(`{"schema":"ree.evidence/1"}`)}),
			wantErr: ErrInvalid,
		},
		{
			name:    "duplicate record",
			input:   buildBundle(t, []json.RawMessage{mustEncodeRecord(t, recordA()), mustEncodeRecord(t, recordA())}),
			wantErr: ErrDuplicateRecord,
		},
		{
			name:    "unsorted records",
			input:   buildBundle(t, []json.RawMessage{mustEncodeRecord(t, recordB()), mustEncodeRecord(t, recordA())}),
			wantErr: ErrUnsortedRecords,
		},
		{
			name: "too many records",
			input: buildBundle(t, func() []json.RawMessage {
				record := mustEncodeRecord(t, recordA())
				records := make([]json.RawMessage, MaxRecords+1)
				for i := range records {
					records[i] = record
				}
				return records
			}()),
			wantErr: ErrLimit,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := Import(tt.input); !errors.Is(err, tt.wantErr) {
				t.Fatalf("Import() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestImportOversizedBundle(t *testing.T) {
	t.Parallel()

	input := bytes.Repeat([]byte("x"), MaxBytes+1)
	if _, err := Import(input); !errors.Is(err, ErrLimit) {
		t.Fatalf("Import(oversized) error = %v, want %v", err, ErrLimit)
	}
}

func TestNestedPayloadDepth(t *testing.T) {
	t.Parallel()

	record := recordA()
	record.Payload = json.RawMessage(strings.Repeat("[", canonical.DefaultMaxDepth) + "0" + strings.Repeat("]", canonical.DefaultMaxDepth))

	data, err := Export([]evidence.Evidence{record})
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	records, err := Import(data)
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Import() returned %d records", len(records))
	}
	if !bytes.Equal(records[0].Payload, record.Payload) {
		t.Fatalf("payload changed: %s", records[0].Payload)
	}
}

func TestImportDigestCoversMetadata(t *testing.T) {
	t.Parallel()

	record := recordA()
	record.Subject = evidence.Subject{SHA256: strings.Repeat("a", 64), Size: 1}
	data, err := Export([]evidence.Evidence{record})
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	tampered := bytes.Replace(data, []byte(strings.Repeat("a", 64)), []byte(strings.Repeat("b", 64)), 1)
	if _, err := Import(tampered); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("Import(tampered metadata) error = %v, want %v", err, ErrDigestMismatch)
	}
}

func FuzzImport(f *testing.F) {
	data, err := os.ReadFile("testdata/bundle.json")
	if err != nil {
		f.Fatal(err)
	}
	empty, err := Export(nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(bytes.TrimSpace(data))
	f.Add(empty)
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))

	f.Fuzz(func(t *testing.T, input []byte) {
		records, err := Import(input)
		if err != nil {
			return
		}
		exported, err := Export(records)
		if err != nil {
			t.Fatalf("Export(Import(input)) error = %v", err)
		}
		if !bytes.Equal(exported, input) {
			t.Fatalf("re-exporting an imported bundle changed its bytes: %s then %s", input, exported)
		}
	})
}
