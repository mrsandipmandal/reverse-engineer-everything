package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/canonical"
)

const (
	goldenRecordDigest  = "0c0644222654a35f8435654f47e1ef73a48c4f04c1f38a23764629a6baaea464"
	goldenPayloadDigest = "0e75d1e5a9c98433dc9234c4ad2bd136b15ee16c732072617060eb53515cecce"
	goldenSubject       = "c7c5c1d70c5dec4416ab6158afd0b223ef40c29b1dc1f97ed9428b94d4cadb1c"
)

func goldenRecord() Evidence {
	return Evidence{
		Subject:     Subject{SHA256: goldenSubject, Size: 8},
		Provider:    Provider{ID: "builtin.example", Version: "1.0.0", Profile: "default"},
		Authority:   AuthorityObserved,
		Coverage:    CoveragePartial,
		Limitations: []string{"fixture covers one artifact only"},
		Unknowns:    []string{"other platforms were not examined"},
		Payload:     json.RawMessage(`{"arch":"amd64","format":"elf"}`),
	}
}

func goldenBytes(t *testing.T) []byte {
	t.Helper()

	data, err := os.ReadFile("testdata/evidence.json")
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(data)
}

func TestGolden(t *testing.T) {
	t.Parallel()

	want := goldenBytes(t)
	got, err := Encode(goldenRecord())
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Encode() = %s, want %s", got, want)
	}

	digest, err := goldenRecord().Digest()
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	if digest != goldenRecordDigest {
		t.Fatalf("Digest() = %q, want %q", digest, goldenRecordDigest)
	}

	rec, err := Decode(want)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if rec.Integrity.Digest != goldenPayloadDigest {
		t.Fatalf("Integrity.Digest = %q, want %q", rec.Integrity.Digest, goldenPayloadDigest)
	}
	if rec.Schema != Schema || rec.Subject.SHA256 != goldenSubject || rec.Subject.Size != 8 {
		t.Fatalf("decoded record identity = %+v", rec)
	}
	if rec.Provider != goldenRecord().Provider {
		t.Fatalf("Provider = %+v, want %+v", rec.Provider, goldenRecord().Provider)
	}
	if rec.Authority != AuthorityObserved || rec.Coverage != CoveragePartial {
		t.Fatalf("authority/coverage = %q/%q", rec.Authority, rec.Coverage)
	}
	if !bytes.Equal(rec.Payload, []byte(`{"arch":"amd64","format":"elf"}`)) {
		t.Fatalf("Payload = %s", rec.Payload)
	}
}

func TestEncodeNormalizes(t *testing.T) {
	t.Parallel()

	want := goldenBytes(t)

	rec := goldenRecord()
	rec.Limitations = []string{"fixture covers one artifact only"}
	rec.Unknowns = []string{"other platforms were not examined"}
	rec.Payload = json.RawMessage("{\n  \"format\" : \"elf\",\n  \"arch\": \"amd64\"\n}")
	got, err := Encode(rec)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Encode() = %s, want %s", got, want)
	}

	// An empty schema is filled in; lists are sorted and empty lists stay
	// present as arrays.
	rec = goldenRecord()
	rec.Schema = ""
	rec.Limitations = []string{"b", "a"}
	rec.Unknowns = nil
	got, err = Encode(rec)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if !strings.Contains(string(got), `"limitations":["a","b"]`) {
		t.Fatalf("limitations were not sorted: %s", got)
	}
	if !strings.Contains(string(got), `"unknowns":[]`) {
		t.Fatalf("unknowns were not emitted as an array: %s", got)
	}

	// A correct seal is accepted and reproduced unchanged.
	sealed := goldenRecord()
	sealed.Integrity = Integrity{Algorithm: AlgorithmSHA256, Digest: goldenPayloadDigest}
	got, err = Encode(sealed)
	if err != nil {
		t.Fatalf("Encode(sealed) error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Encode(sealed) = %s, want %s", got, want)
	}
}

func TestEncodeRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*Evidence)
		wantErr error
	}{
		{
			name:    "wrong schema",
			mutate:  func(e *Evidence) { e.Schema = "ree.evidence/2" },
			wantErr: ErrUnsupportedSchema,
		},
		{
			name:    "wrong algorithm",
			mutate:  func(e *Evidence) { e.Integrity.Algorithm = "md5" },
			wantErr: ErrUnsupportedAlgorithm,
		},
		{
			name:    "wrong digest",
			mutate:  func(e *Evidence) { e.Integrity.Digest = strings.Repeat("0", 64) },
			wantErr: ErrDigestMismatch,
		},
		{
			name:    "missing payload",
			mutate:  func(e *Evidence) { e.Payload = nil },
			wantErr: ErrInvalid,
		},
		{
			name:    "invalid payload",
			mutate:  func(e *Evidence) { e.Payload = json.RawMessage(`{`) },
			wantErr: ErrInvalid,
		},
		{
			name:    "duplicate payload member",
			mutate:  func(e *Evidence) { e.Payload = json.RawMessage(`{"a":1,"a":2}`) },
			wantErr: ErrInvalid,
		},
		{
			name:    "empty provider id",
			mutate:  func(e *Evidence) { e.Provider.ID = "  " },
			wantErr: ErrInvalid,
		},
		{
			name:    "invalid utf8 provider id",
			mutate:  func(e *Evidence) { e.Provider.ID = "bad\xff" },
			wantErr: ErrInvalid,
		},
		{
			name:    "uppercase subject digest",
			mutate:  func(e *Evidence) { e.Subject.SHA256 = strings.ToUpper(goldenSubject) },
			wantErr: ErrInvalid,
		},
		{
			name:    "negative subject size",
			mutate:  func(e *Evidence) { e.Subject.Size = -1 },
			wantErr: ErrInvalid,
		},
		{
			name:    "unknown authority",
			mutate:  func(e *Evidence) { e.Authority = "guessed" },
			wantErr: ErrInvalid,
		},
		{
			name:    "unknown coverage",
			mutate:  func(e *Evidence) { e.Coverage = "mostly" },
			wantErr: ErrInvalid,
		},
		{
			name:    "blank limitation",
			mutate:  func(e *Evidence) { e.Limitations = []string{" "} },
			wantErr: ErrInvalid,
		},
		{
			name:    "duplicate limitation",
			mutate:  func(e *Evidence) { e.Limitations = []string{"a", "a"} },
			wantErr: ErrInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := goldenRecord()
			tt.mutate(&rec)
			if _, err := Encode(rec); !errors.Is(err, tt.wantErr) {
				t.Fatalf("Encode() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecodeRejects(t *testing.T) {
	t.Parallel()

	golden := string(goldenBytes(t))
	replace := func(old, replacement string) []byte {
		t.Helper()
		if !strings.Contains(golden, old) {
			t.Fatalf("golden record does not contain %q", old)
		}
		return []byte(strings.Replace(golden, old, replacement, 1))
	}

	tests := []struct {
		name    string
		input   []byte
		wantErr error
	}{
		{name: "empty", input: nil, wantErr: ErrInvalid},
		{name: "not an object", input: []byte(`[]`), wantErr: ErrInvalid},
		{name: "leading whitespace", input: append([]byte(" "), golden...), wantErr: ErrNotCanonical},
		{name: "trailing newline", input: append([]byte(golden), '\n'), wantErr: ErrNotCanonical},
		{
			name: "reordered members",
			input: func() []byte {
				withoutSchema := strings.Replace(golden, `"schema":"ree.evidence/1",`, ``, 1)
				return []byte(`{"schema":"ree.evidence/1",` + withoutSchema[1:])
			}(),
			wantErr: ErrNotCanonical,
		},
		{name: "trailing data", input: append([]byte(golden), []byte(`{}`)...), wantErr: ErrInvalid},
		{name: "unknown member", input: replace(`{"authority"`, `{"aa":1,"authority"`), wantErr: ErrInvalid},
		{name: "case-variant member", input: replace(`"authority":"observed"`, `"AuthoritY":"observed"`), wantErr: ErrInvalid},
		{name: "case-variant nested member", input: replace(`"sha256":"`+goldenSubject, `"SHA256":"`+goldenSubject), wantErr: ErrInvalid},
		{name: "wrong schema", input: replace(`"ree.evidence/1"`, `"ree.evidence/2"`), wantErr: ErrUnsupportedSchema},
		{name: "null limitations", input: replace(`"limitations":["fixture covers one artifact only"]`, `"limitations":null`), wantErr: ErrInvalid},
		{name: "missing limitations", input: replace(`"limitations":["fixture covers one artifact only"],`, ``), wantErr: ErrInvalid},
		{name: "unsorted limitations", input: replace(`"limitations":["fixture covers one artifact only"]`, `"limitations":["b","a"]`), wantErr: ErrInvalid},
		{name: "duplicate limitations", input: replace(`"limitations":["fixture covers one artifact only"]`, `"limitations":["a","a"]`), wantErr: ErrInvalid},
		{name: "null unknowns", input: replace(`"unknowns":["other platforms were not examined"]`, `"unknowns":null`), wantErr: ErrInvalid},
		{name: "missing provider", input: replace(`"provider":{"id":"builtin.example","profile":"default","version":"1.0.0"},`, ``), wantErr: ErrInvalid},
		{name: "missing payload", input: replace(`"payload":{"arch":"amd64","format":"elf"},`, ``), wantErr: ErrInvalid},
		{name: "tampered payload", input: replace(`"arch":"amd64"`, `"arch":"arm64"`), wantErr: ErrDigestMismatch},
		{name: "wrong algorithm", input: replace(`"algorithm":"sha256"`, `"algorithm":"md5"`), wantErr: ErrUnsupportedAlgorithm},
		{name: "zeroed digest", input: replace(goldenPayloadDigest, strings.Repeat("0", 64)), wantErr: ErrDigestMismatch},
		{name: "missing integrity", input: replace(`"integrity":{"algorithm":"sha256","digest":"`+goldenPayloadDigest+`"},`, ``), wantErr: ErrInvalid},
		{name: "uppercase subject digest", input: replace(goldenSubject, strings.ToUpper(goldenSubject)), wantErr: ErrInvalid},
		{name: "negative subject size", input: replace(`"size":8`, `"size":-1`), wantErr: ErrInvalid},
		{name: "unknown authority", input: replace(`"authority":"observed"`, `"authority":"guessed"`), wantErr: ErrInvalid},
		{name: "unknown coverage", input: replace(`"coverage":"partial"`, `"coverage":"mostly"`), wantErr: ErrInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := Decode(tt.input); !errors.Is(err, tt.wantErr) {
				t.Fatalf("Decode() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecodeOversizedRecord(t *testing.T) {
	t.Parallel()

	input := bytes.Repeat([]byte("x"), MaxRecordBytes+1)
	if _, err := Decode(input); !errors.Is(err, ErrLimit) {
		t.Fatalf("Decode(oversized) error = %v, want %v", err, ErrLimit)
	}
}

func TestEncodeLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Evidence)
	}{
		{
			name:   "payload bytes",
			mutate: func(e *Evidence) { e.Payload = json.RawMessage(`"` + strings.Repeat("a", MaxPayloadBytes) + `"`) },
		},
		{
			name:   "payload nesting",
			mutate: func(e *Evidence) { e.Payload = json.RawMessage(strings.Repeat("[", 129) + strings.Repeat("]", 129)) },
		},
		{
			name:   "payload string",
			mutate: func(e *Evidence) { e.Payload = json.RawMessage(`"` + strings.Repeat("a", MaxStringBytes+1) + `"`) },
		},
		{
			name:   "payload object members",
			mutate: func(e *Evidence) { e.Payload = json.RawMessage(objectWithMembers(MaxObjectMembers + 1)) },
		},
		{
			name:   "payload array elements",
			mutate: func(e *Evidence) { e.Payload = json.RawMessage(arrayWithElements(MaxArrayElements + 1)) },
		},
		{
			name:   "limitation string",
			mutate: func(e *Evidence) { e.Limitations = []string{strings.Repeat("a", MaxStringBytes+1)} },
		},
		{
			name:   "limitation count",
			mutate: func(e *Evidence) { e.Limitations = distinctStrings(MaxArrayElements+1, "a") },
		},
		{
			name:   "provider string",
			mutate: func(e *Evidence) { e.Provider.Version = strings.Repeat("1", MaxStringBytes+1) },
		},
		{
			name: "record bytes",
			mutate: func(e *Evidence) {
				// The payload limit is per payload, so several maximum-length
				// limitations can still push the whole record over its limit.
				e.Limitations = distinctStrings(9, strings.Repeat("x", MaxStringBytes-16))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := goldenRecord()
			tt.mutate(&rec)
			if _, err := Encode(rec); !errors.Is(err, ErrLimit) {
				t.Fatalf("Encode() error = %v, want %v", err, ErrLimit)
			}
		})
	}
}

func TestPayloadValues(t *testing.T) {
	t.Parallel()

	for _, payload := range []string{`null`, `true`, `0`, `"text"`, `[]`, `{}`, `[{"a":1}]`} {
		rec := goldenRecord()
		rec.Payload = json.RawMessage(payload)
		data, err := Encode(rec)
		if err != nil {
			t.Fatalf("Encode(payload %s) error = %v", payload, err)
		}
		decoded, err := Decode(data)
		if err != nil {
			t.Fatalf("Decode(payload %s) error = %v", payload, err)
		}
		if string(decoded.Payload) != payload {
			t.Fatalf("Payload = %s, want %s", decoded.Payload, payload)
		}
	}
}

func TestDigestCoversPayloadOnly(t *testing.T) {
	t.Parallel()

	rec := goldenRecord()
	rec.Subject = Subject{SHA256: strings.Repeat("a", 64), Size: 1}
	rec.Coverage = CoverageComplete

	data, err := Encode(rec)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	digest := canonical.SHA256(data)
	if digest == goldenRecordDigest {
		t.Fatal("record digest did not change after metadata changed")
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if decoded.Integrity.Digest != goldenPayloadDigest {
		t.Fatalf("payload digest changed: %q", decoded.Integrity.Digest)
	}
}

func TestIdempotent(t *testing.T) {
	t.Parallel()

	first, err := Encode(goldenRecord())
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	rec, err := Decode(first)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	second, err := Encode(rec)
	if err != nil {
		t.Fatalf("Encode(decoded) error = %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("round trip changed bytes: %s then %s", first, second)
	}
}

func FuzzDecode(f *testing.F) {
	data, err := os.ReadFile("testdata/evidence.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(bytes.TrimSpace(data))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"schema":"ree.evidence/1"}`))
	f.Add([]byte(`{"payload":null}`))

	f.Fuzz(func(t *testing.T, input []byte) {
		rec, err := Decode(input)
		if err != nil {
			return
		}
		encoded, err := Encode(rec)
		if err != nil {
			t.Fatalf("Encode(Decode(input)) error = %v", err)
		}
		if !bytes.Equal(encoded, input) {
			t.Fatalf("re-encoding a decoded record changed its bytes: %s then %s", input, encoded)
		}
	})
}

func objectWithMembers(n int) string {
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%q:0", fmt.Sprintf("k%d", i))
	}
	b.WriteByte('}')
	return b.String()
}

func arrayWithElements(n int) string {
	var b strings.Builder
	b.WriteByte('[')
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('0')
	}
	b.WriteByte(']')
	return b.String()
}

func distinctStrings(count int, values ...string) []string {
	out := make([]string, 0, count)
	for len(out) < count {
		for _, value := range values {
			if len(out) == count {
				return out
			}
			out = append(out, fmt.Sprintf("%s-%06d", value, len(out)))
		}
	}
	return out
}
