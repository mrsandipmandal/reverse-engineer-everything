package canonical

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRFC8785Example(t *testing.T) {
	t.Parallel()

	input, err := os.ReadFile("testdata/rfc8785-input.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/rfc8785-canonical.json")
	if err != nil {
		t.Fatal(err)
	}
	want = bytes.TrimRight(want, "\n")

	got, err := Bytes(input)
	if err != nil {
		t.Fatalf("Bytes() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Bytes() = %q, want %q", got, want)
	}
}

func TestBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "sorts members",
			input: `{"b":2,"a":1}`,
			want:  `{"a":1,"b":2}`,
		},
		{
			name:  "removes insignificant whitespace",
			input: "{\n  \"a\" : [ 1, 2 ]\n}",
			want:  `{"a":[1,2]}`,
		},
		{
			name:  "sorts by utf16 code units",
			input: `{"\uE000":1,"\uD83D\uDE00":2}`,
			want:  "{\"\U0001F600\":2,\"\uE000\":1}",
		},
		{
			name:  "decodes surrogate pairs",
			input: `{"a":"\ud83d\ude00"}`,
			want:  `{"a":"😀"}`,
		},
		{
			name:  "normalizes numbers",
			input: `[-0,0.0,4.50,1E30,2e-3,1e-27]`,
			want:  `[0,0,4.5,1e+30,0.002,1e-27]`,
		},
		{
			name:  "sorts nested members",
			input: `{"b":{"d":4,"c":3},"a":1}`,
			want:  `{"a":1,"b":{"c":3,"d":4}}`,
		},
		{
			name:  "keeps array order",
			input: `[3,1,2]`,
			want:  `[3,1,2]`,
		},
		{
			name:  "escapes control characters",
			input: `"a\u0001b"`,
			want:  `"a\u0001b"`,
		},
		{
			name:  "keeps top-level scalar",
			input: "  true\n",
			want:  `true`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Bytes([]byte(tt.input))
			if err != nil {
				t.Fatalf("Bytes() error = %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("Bytes() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBytesRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   []byte
		wantErr error
	}{
		{name: "empty", input: nil, wantErr: ErrEmpty},
		{name: "duplicate members", input: []byte(`{"a":1,"a":2}`), wantErr: ErrInvalid},
		{name: "duplicate escaped members", input: []byte(`{"a":1,"\u0061":2}`), wantErr: ErrInvalid},
		{name: "lone high surrogate", input: []byte(`{"a":"\ud800"}`), wantErr: ErrInvalid},
		{name: "lone low surrogate", input: []byte(`{"a":"\udc00"}`), wantErr: ErrInvalid},
		{name: "nan literal", input: []byte(`[NaN]`), wantErr: ErrInvalid},
		{name: "infinity literal", input: []byte(`[Infinity]`), wantErr: ErrInvalid},
		{name: "trailing data", input: []byte(`{} {}`), wantErr: ErrInvalid},
		{name: "invalid utf8", input: []byte{'"', 0xff, '"'}, wantErr: ErrInvalid},
		{name: "unquoted member", input: []byte(`{a:1}`), wantErr: ErrInvalid},
		{name: "truncated", input: []byte(`{"a":`), wantErr: ErrInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := Bytes(tt.input)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Bytes() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestLimits(t *testing.T) {
	t.Parallel()

	deep := []byte(strings.Repeat("[", DefaultMaxDepth+1) + strings.Repeat("]", DefaultMaxDepth+1))
	if _, err := Bytes(deep); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("Bytes(deep) error = %v, want %v", err, ErrTooDeep)
	}
	if _, err := WithOptions(deep, Options{MaxDepth: DefaultMaxDepth + 10}); err != nil {
		t.Fatalf("WithOptions(deep, larger depth) error = %v", err)
	}

	large := []byte(`{"a":"` + strings.Repeat("x", 32) + `"}`)
	if _, err := WithOptions(large, Options{MaxBytes: 16}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("WithOptions(large) error = %v, want %v", err, ErrTooLarge)
	}

	// Brackets inside strings must not count toward the depth limit.
	if _, err := Bytes([]byte(`{"a":"[[[[[["}`)); err != nil {
		t.Fatalf("Bytes(brackets in string) error = %v", err)
	}

	// Zero options select the defaults.
	if _, err := WithOptions([]byte(`{"a":1}`), Options{}); err != nil {
		t.Fatalf("WithOptions(zero) error = %v", err)
	}
}

func TestIdempotent(t *testing.T) {
	t.Parallel()

	inputs := [][]byte{
		[]byte(`{"b":2,"a":1}`),
		[]byte(`[1e30,-0,4.50]`),
		[]byte(`{"a":"\u20ac\ud83d\ude00"}`),
		[]byte(`null`),
	}
	for _, input := range inputs {
		once, err := Bytes(input)
		if err != nil {
			t.Fatalf("Bytes(%q) error = %v", input, err)
		}
		twice, err := Bytes(once)
		if err != nil {
			t.Fatalf("Bytes(canonical) error = %v", err)
		}
		if !bytes.Equal(once, twice) {
			t.Fatalf("canonicalization is not idempotent: %q then %q", once, twice)
		}
	}
}

func TestSHA256(t *testing.T) {
	t.Parallel()

	if got, want := SHA256(nil), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; got != want {
		t.Fatalf("SHA256(nil) = %q, want %q", got, want)
	}
	canonical := []byte(`{"a":1}`)
	if got := SHA256(canonical); len(got) != 64 || strings.ToLower(got) != got {
		t.Fatalf("SHA256(canonical) = %q, want 64 lowercase hex characters", got)
	}
}

func FuzzBytes(f *testing.F) {
	seeds := [][]byte{
		[]byte(`{}`),
		[]byte(`[]`),
		[]byte(`null`),
		[]byte(`"x"`),
		[]byte(`{"b":1,"a":2}`),
		[]byte(`{"a":1,"a":2}`),
		[]byte(`[1e30,-0,4.50]`),
		[]byte(`{"a":"\ud83d\ude00"}`),
		{'"', 0xff, '"'},
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		out, err := Bytes(input)
		if err != nil {
			return
		}
		if !utf8.Valid(out) {
			t.Fatalf("canonical output is not valid UTF-8: %q", out)
		}
		again, err := Bytes(out)
		if err != nil {
			t.Fatalf("canonical output was rejected: %v", err)
		}
		if !bytes.Equal(out, again) {
			t.Fatalf("canonicalization is not idempotent: %q then %q", out, again)
		}
	})
}
