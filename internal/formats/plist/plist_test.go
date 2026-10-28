package plist

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
)

func TestParseBinaryInventory(t *testing.T) {
	data := buildBinary(t, [][]byte{
		bdict(1, 3, 5, 2, 4, 6),
		bstr("name"),
		bstr("demo"),
		bstr("version"),
		bint(7),
		bstr("enabled"),
		{0x09},
	})
	parsed := parseBytes(t, data)

	if parsed.Format != FormatBinary || parsed.Version != "00" {
		t.Fatalf("format = %v/%q", parsed.Format, parsed.Version)
	}
	if parsed.Truncated || len(parsed.Limitations) != 0 {
		t.Fatalf("truncated=%v limitations=%v", parsed.Truncated, parsed.Limitations)
	}
	if parsed.TopObject != 0 || len(parsed.Objects) != 7 {
		t.Fatalf("top=%d objects=%d", parsed.TopObject, len(parsed.Objects))
	}
	root := parsed.Objects[0]
	if root.Type != TypeDictionary || len(root.Keys) != 3 || len(root.Values) != 3 {
		t.Fatalf("root = %#v", root)
	}
	if !root.Reachable || root.Depth != 0 {
		t.Fatalf("root reachability = %v depth = %d", root.Reachable, root.Depth)
	}
	if root.Keys[0] != 1 || root.Values[0] != 2 {
		t.Fatalf("first pair = %d/%d", root.Keys[0], root.Values[0])
	}
	if got := parsed.Objects[2]; got.Type != TypeString || !got.TextAvailable || got.Text != "demo" {
		t.Fatalf("value = %#v", got)
	}
	if got := parsed.Objects[2].Depth; got != 1 {
		t.Fatalf("string depth = %d", got)
	}
	if got := parsed.Objects[4]; got.Type != TypeInteger || got.Integer != "7" {
		t.Fatalf("integer = %#v", got)
	}
	if got := parsed.Objects[6]; got.Type != TypeBoolean || !got.Boolean {
		t.Fatalf("boolean = %#v", got)
	}
	for index, object := range parsed.Objects {
		if object.Index != index {
			t.Fatalf("object %d index = %d", index, object.Index)
		}
	}
}

func TestParseBinaryScalars(t *testing.T) {
	data := buildBinary(t, [][]byte{
		barray(1, 2, 3, 4, 5, 6, 7, 8, 9),
		{0x00},
		{0x08},
		breal(1.5),
		bdate(1_700_000_000),
		bdata(3),
		buid(300, 2),
		butf16("héllo"),
		blong(5, 0),
		blong(9, 1),
	})
	parsed := parseBytes(t, data)

	if got := parsed.Objects[1]; got.Type != TypeNull {
		t.Fatalf("null = %#v", got)
	}
	if got := parsed.Objects[2]; got.Type != TypeBoolean || got.Boolean {
		t.Fatalf("false = %#v", got)
	}
	if got := parsed.Objects[3]; got.Type != TypeReal || got.Real != 1.5 {
		t.Fatalf("real = %#v", got)
	}
	if got := parsed.Objects[4]; got.Type != TypeDate || got.DateUnix != 1_700_000_000 {
		t.Fatalf("date = %#v", got)
	}
	if got := parsed.Objects[5]; got.Type != TypeData || got.DataBytes != 3 {
		t.Fatalf("data = %#v", got)
	}
	if got := parsed.Objects[6]; got.Type != TypeUID || got.UID != 300 {
		t.Fatalf("uid = %#v", got)
	}
	if got := parsed.Objects[7]; got.Type != TypeString || !got.TextAvailable || got.Text != "héllo" {
		t.Fatalf("utf16 = %#v", got)
	}
	if got := parsed.Objects[8]; got.Integer != "5" || len(got.Limitations) != 0 {
		t.Fatalf("wide integer = %#v", got)
	}
	if got := parsed.Objects[9]; got.Integer != "9" || len(got.Limitations) != 1 {
		t.Fatalf("over-wide integer = %#v", got)
	}
	if got := parsed.Objects[0]; got.Type != TypeArray || len(got.Refs) != 9 {
		t.Fatalf("array = %#v", got)
	}
}

func TestParseBinaryUnreachable(t *testing.T) {
	data := buildBinary(t, [][]byte{
		bdict(1, 2),
		bstr("only"),
		bstr("reachable"),
		bstr("dead"),
	})
	parsed := parseBytes(t, data)
	if parsed.Objects[3].Reachable {
		t.Fatal("dead object is reachable")
	}
	if len(parsed.Objects[3].Limitations) != 0 {
		t.Fatalf("dead object limitations = %v", parsed.Objects[3].Limitations)
	}
	found := false
	for _, limitation := range parsed.Limitations {
		if strings.Contains(limitation, "not reachable") {
			found = true
		}
	}
	if !found {
		t.Fatalf("limitations = %v", parsed.Limitations)
	}
	if parsed.Truncated {
		t.Fatal("unreachable objects truncate the inventory")
	}
}

func TestParseBinaryDepthLimit(t *testing.T) {
	data := buildBinary(t, [][]byte{
		barray(1),
		barray(2),
		barray(3),
		barray(),
	})
	parsed, err := parseWith(t, data, Limits{Depth: 1})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !parsed.Truncated {
		t.Fatal("depth limit did not truncate")
	}
	if len(parsed.Objects[1].Refs) != 0 {
		t.Fatalf("object 1 refs = %v", parsed.Objects[1].Refs)
	}
	if len(parsed.Objects[1].Limitations) == 0 {
		t.Fatal("object 1 has no limitation")
	}
	if parsed.Objects[1].Depth != 1 || parsed.Objects[0].Depth != 0 {
		t.Fatalf("depths = %d/%d", parsed.Objects[0].Depth, parsed.Objects[1].Depth)
	}
}

func TestParseBinaryStringLimit(t *testing.T) {
	data := buildBinary(t, [][]byte{bstrLong(strings.Repeat("x", 20))})
	parsed, err := parseWith(t, data, Limits{StringBytes: 8})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	object := parsed.Objects[0]
	if object.TextAvailable || len(object.TextBytes) != 8 {
		t.Fatalf("object = %#v", object)
	}
	if len(object.Limitations) != 1 || object.Limitations[0] != "string exceeds 8 bytes" {
		t.Fatalf("limitations = %v", object.Limitations)
	}
}

func TestParseBinaryObjectLimit(t *testing.T) {
	data := buildBinary(t, [][]byte{bstr("a"), bstr("b"), bstr("c")})
	if _, err := parseWith(t, data, Limits{Objects: 2}); !errors.Is(err, ErrLimit) {
		t.Fatalf("error = %v, want ErrLimit", err)
	}
}

func TestParseBinaryErrors(t *testing.T) {
	valid := buildBinary(t, [][]byte{bdict(1, 2), bstr("k"), bstr("v")})
	trailer := len(valid) - binaryTrailerBytes
	table := 8 + 1 + 2 + 2 + 1 + 2 + 2

	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"magic", patch(valid, 0, []byte("Xplist00")), ErrInvalid},
		{"version", patch(valid, 6, []byte("99")), ErrInvalid},
		{"offset int size", patch(valid, trailer+6, []byte{0}), ErrInvalid},
		{"object ref size", patch(valid, trailer+7, []byte{0}), ErrInvalid},
		{"no objects", patch(valid, trailer+8, make([]byte, 8)), ErrInvalid},
		{"top object", patch(valid, trailer+16, []byte{0, 0, 0, 0, 0, 0, 0, 99}), ErrInvalid},
		{"table before header", patch(valid, trailer+24, make([]byte, 8)), ErrInvalid},
		{"table past area", patch(valid, trailer+24, []byte{0, 0, 0, 0, 0, 0, 1, 0}), ErrInvalid},
		{"table bytes", patch(valid, trailer+8, []byte{0, 0, 0, 0, 0, 0, 0x4e, 0x20}), ErrTruncated},
		{"object offset", patch(valid, table, []byte{0, 2}), ErrInvalid},
		{"short artifact", valid[:20], ErrTruncated},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := Parse(bytes.NewReader(test.data), int64(len(test.data)))
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if parsed != nil {
				t.Fatal("plist returned with an error")
			}
		})
	}
}

func TestParseBinaryObjectErrors(t *testing.T) {
	tests := []struct {
		name   string
		object []byte
		want   error
	}{
		{"unsupported marker", []byte{0xF0}, ErrInvalid},
		{"integer width", []byte{0x15}, ErrInvalid},
		{"real width", []byte{0x21, 0, 0}, ErrInvalid},
		{"count extension", []byte{0x5F, 0x50}, ErrInvalid},
		{"count extension width", []byte{0x5F, 0x15}, ErrInvalid},
		{"data too large", []byte{0x4F, 0x13, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, ErrTruncated},
		{"string too large", []byte{0x5F, 0x13, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, ErrTruncated},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := buildBinary(t, [][]byte{test.object})
			if _, err := Parse(bytes.NewReader(data), int64(len(data))); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestParseBinaryReferenceOutside(t *testing.T) {
	data := buildBinary(t, [][]byte{barray(9), bstr("a")})
	if _, err := Parse(bytes.NewReader(data), int64(len(data))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
}

func TestParseBinaryInvalidUTF16(t *testing.T) {
	data := buildBinary(t, [][]byte{{0x61, 0xD8, 0x00}})
	parsed := parseBytes(t, data)
	object := parsed.Objects[0]
	if object.TextAvailable {
		t.Fatalf("object = %#v", object)
	}
	if len(object.Limitations) != 1 || object.Limitations[0] != "string is not valid UTF-16" {
		t.Fatalf("limitations = %v", object.Limitations)
	}
}

func TestParseBinaryNonFiniteDate(t *testing.T) {
	data := buildBinary(t, [][]byte{brealWithMarker(0x33, 0)})
	parsed := parseBytes(t, data)
	object := parsed.Objects[0]
	if object.DateUnix != binaryDateEpoch {
		t.Fatalf("date = %d", object.DateUnix)
	}
	if len(object.Limitations) != 0 {
		t.Fatalf("limitations = %v", object.Limitations)
	}
	notANumber := buildBinary(t, [][]byte{brealWithMarker(0x33, math.NaN())})
	parsed = parseBytes(t, notANumber)
	if len(parsed.Objects[0].Limitations) != 1 {
		t.Fatalf("limitations = %v", parsed.Objects[0].Limitations)
	}
}

func TestParseBinaryUTF8AndASCII(t *testing.T) {
	data := buildBinary(t, [][]byte{
		append([]byte{0x70 | 2}, []byte("ok")...),
		append([]byte{0x52}, 0xFF, 0xFE),
	})
	parsed := parseBytes(t, data)
	if got := parsed.Objects[0]; got.Text != "ok" || !got.TextAvailable {
		t.Fatalf("utf8 = %#v", got)
	}
	if got := parsed.Objects[1]; got.TextAvailable || len(got.Limitations) != 1 {
		t.Fatalf("invalid ascii = %#v", got)
	}
}

func TestParseBinaryUIDWidth(t *testing.T) {
	data := buildBinary(t, [][]byte{buid(1, 9)})
	parsed := parseBytes(t, data)
	object := parsed.Objects[0]
	if object.UID != 1 || len(object.Limitations) != 1 {
		t.Fatalf("object = %#v", object)
	}
}

func TestParseXMLInventory(t *testing.T) {
	document := xmlDocument(`<dict>
	<key>name</key><string>demo</string>
	<key>count</key><integer>7</integer>
	<key>ratio</key><real>1.5</real>
	<key>enabled</key><true/>
	<key>disabled</key><false/>
	<key>when</key><date>2020-01-02T03:04:05Z</date>
	<key>blob</key><data>AAAA</data>
	<key>uid</key><uid>42</uid>
	<key>list</key><array><string>a</string><string>b</string></array>
</dict>`)
	parsed := parseBytes(t, []byte(document))

	if parsed.Format != FormatXML || parsed.Version != "" {
		t.Fatalf("format = %v/%q", parsed.Format, parsed.Version)
	}
	if parsed.Truncated || len(parsed.Limitations) != 0 {
		t.Fatalf("truncated=%v limitations=%v", parsed.Truncated, parsed.Limitations)
	}
	root, err := parsed.ObjectAt(parsed.TopObject)
	if err != nil {
		t.Fatalf("ObjectAt: %v", err)
	}
	if root.Type != TypeDictionary || len(root.Keys) != 9 {
		t.Fatalf("root = %#v", root)
	}
	byKey := map[string]Object{}
	for i, key := range root.Keys {
		name := parsed.Objects[key].Text
		byKey[name] = parsed.Objects[root.Values[i]]
	}
	if got := byKey["name"]; got.Type != TypeString || got.Text != "demo" {
		t.Fatalf("name = %#v", got)
	}
	if got := byKey["count"]; got.Type != TypeInteger || got.Integer != "7" {
		t.Fatalf("count = %#v", got)
	}
	if got := byKey["ratio"]; got.Type != TypeReal || got.Real != 1.5 {
		t.Fatalf("ratio = %#v", got)
	}
	if got := byKey["enabled"]; got.Type != TypeBoolean || !got.Boolean {
		t.Fatalf("enabled = %#v", got)
	}
	if got := byKey["disabled"]; got.Type != TypeBoolean || got.Boolean {
		t.Fatalf("disabled = %#v", got)
	}
	if got := byKey["when"]; got.Type != TypeDate || got.DateUnix != 1_577_934_245 {
		t.Fatalf("when = %#v", got)
	}
	if got := byKey["blob"]; got.Type != TypeData || got.DataBytes != 3 {
		t.Fatalf("blob = %#v", got)
	}
	if got := byKey["uid"]; got.Type != TypeUID || got.UID != 42 {
		t.Fatalf("uid = %#v", got)
	}
	if got := byKey["list"]; got.Type != TypeArray || len(got.Refs) != 2 {
		t.Fatalf("list = %#v", got)
	}
}

func TestParseXMLDepthLimit(t *testing.T) {
	document := xmlDocument(`<array><array><array><string>deep</string></array></array></array>`)
	parsed, err := parseWith(t, []byte(document), Limits{Depth: 1})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !parsed.Truncated {
		t.Fatal("depth limit did not truncate")
	}
	if len(parsed.Objects) != 2 {
		t.Fatalf("objects = %d", len(parsed.Objects))
	}
	if len(parsed.Objects[1].Refs) != 0 {
		t.Fatalf("object 1 refs = %v", parsed.Objects[1].Refs)
	}
}

func TestParseXMLObjectLimit(t *testing.T) {
	document := xmlDocument(`<dict><key>a</key><string>b</string></dict>`)
	parsed, err := parseWith(t, []byte(document), Limits{Objects: 2})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !parsed.Truncated || len(parsed.Objects) != 2 {
		t.Fatalf("truncated=%v objects=%d", parsed.Truncated, len(parsed.Objects))
	}
}

func TestParseXMLScalarLimitations(t *testing.T) {
	document := xmlDocument(`<array>
	<integer>twelve</integer>
	<real>many</real>
	<date>yesterday</date>
	<data>abc</data>
	<uid>zero</uid>
	<widget/>
</array>`)
	parsed := parseBytes(t, []byte(document))
	wants := []string{
		"integer is not a decimal number",
		"real is not a number",
		"date is not an RFC 3339 timestamp",
		"data is not valid base64",
		"uid is not a decimal number",
		`unsupported element "widget"`,
	}
	for i, want := range wants {
		object := parsed.Objects[i+1]
		if len(object.Limitations) != 1 || object.Limitations[0] != want {
			t.Fatalf("object %d limitations = %v, want %q", i+1, object.Limitations, want)
		}
	}
}

func TestParseXMLStringLimit(t *testing.T) {
	document := xmlDocument(`<string>` + strings.Repeat("x", 20) + `</string>`)
	parsed, err := parseWith(t, []byte(document), Limits{StringBytes: 8})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	object := parsed.Objects[0]
	if object.TextAvailable || len(object.TextBytes) != 8 {
		t.Fatalf("object = %#v", object)
	}
	if !parsed.Truncated {
		t.Fatal("string limit did not truncate")
	}
}

func TestParseXMLErrors(t *testing.T) {
	tests := []struct {
		name     string
		document string
		want     error
	}{
		{"root", `<dict/>`, ErrInvalid},
		{"empty", ``, ErrTruncated},
		{"no value", `<plist version="1.0"></plist>`, ErrInvalid},
		{"two values", `<plist><string>a</string><string>b</string></plist>`, ErrInvalid},
		{"key without value", `<plist><dict><key>a</key></dict></plist>`, ErrInvalid},
		{"non-key member", `<plist><dict><string>a</string></dict></plist>`, ErrInvalid},
		{"trailing text", `<plist><string>a</string></plist>tail`, ErrInvalid},
		{"unclosed", `<plist><string>a</string>`, ErrTruncated},
		{"text before root", `hello<plist><string>a</string></plist>`, ErrInvalid},
		{"mismatched", `<plist><dict></array></plist>`, ErrInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse(bytes.NewReader([]byte(test.document)), int64(len(test.document)))
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestParseXMLEmptyCollections(t *testing.T) {
	parsed := parseBytes(t, []byte(xmlDocument(`<dict/>`)))
	if root := parsed.Objects[0]; root.Type != TypeDictionary || len(root.Keys) != 0 {
		t.Fatalf("root = %#v", root)
	}
	parsed = parseBytes(t, []byte(xmlDocument(`<array/>`)))
	if root := parsed.Objects[0]; root.Type != TypeArray || len(root.Refs) != 0 {
		t.Fatalf("root = %#v", root)
	}
}

func TestDetect(t *testing.T) {
	tests := []struct {
		prefix []byte
		want   Format
	}{
		{[]byte("bplist00"), FormatBinary},
		{[]byte("bplist15"), FormatBinary},
		{[]byte("  <?xml version=\"1.0\"?>"), FormatXML},
		{[]byte("<plist>"), FormatXML},
		{[]byte("not a plist"), FormatUnknown},
		{nil, FormatUnknown},
	}
	for _, test := range tests {
		if got := Detect(test.prefix); got != test.want {
			t.Fatalf("Detect(%q) = %v, want %v", test.prefix, got, test.want)
		}
	}
}

func TestParseNotAPlist(t *testing.T) {
	data := []byte("not a plist at all")
	if _, err := Parse(bytes.NewReader(data), int64(len(data))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
}

func TestLimitsDefaultsAndClamping(t *testing.T) {
	defaults := DefaultLimits()
	if defaults.ArtifactBytes != MaxArtifactBytes || defaults.Objects != MaxObjects ||
		defaults.Depth != MaxDepth || defaults.StringBytes != MaxStringBytes {
		t.Fatalf("defaults = %#v", defaults)
	}
	clamped := Limits{
		ArtifactBytes: MaxArtifactBytes + 1,
		Objects:       MaxObjects + 1,
		Depth:         MaxDepth + 1,
		StringBytes:   MaxStringBytes + 1,
	}.withDefaults()
	if clamped != defaults {
		t.Fatalf("clamped = %#v", clamped)
	}
	if zero := (Limits{}).withDefaults(); zero != defaults {
		t.Fatalf("zero = %#v", zero)
	}
}

func TestParseArtifactLimit(t *testing.T) {
	data := buildBinary(t, [][]byte{{0x00}})
	if _, err := parseWith(t, data, Limits{ArtifactBytes: 4}); !errors.Is(err, ErrLimit) {
		t.Fatalf("error = %v, want ErrLimit", err)
	}
}

func TestParseNilAndNegative(t *testing.T) {
	if _, err := Parse(nil, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil error = %v", err)
	}
	if _, err := Parse(bytes.NewReader(nil), -1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("negative error = %v", err)
	}
	if _, err := Parse(bytes.NewReader(nil), 0); !errors.Is(err, ErrTruncated) {
		t.Fatalf("empty error = %v", err)
	}
}

func TestObjectAccess(t *testing.T) {
	parsed := parseBytes(t, []byte(xmlDocument(`<string>a</string>`)))
	if parsed.Size() != int64(len(xmlDocument(`<string>a</string>`))) {
		t.Fatal("Size does not report the artifact size")
	}
	for _, index := range []int{-1, 1, 9} {
		if _, err := parsed.ObjectAt(index); !errors.Is(err, ErrOutOfRange) {
			t.Fatalf("ObjectAt(%d) error = %v", index, err)
		}
	}
	var nilPlist *Plist
	if _, err := nilPlist.ObjectAt(0); !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("nil ObjectAt error = %v", err)
	}
	if nilPlist.Size() != 0 {
		t.Fatal("nil Size is not zero")
	}
}

func TestStringers(t *testing.T) {
	formats := map[Format]string{
		FormatBinary:  "binary",
		FormatXML:     "xml",
		FormatUnknown: "unknown",
	}
	for format, want := range formats {
		if got := format.String(); got != want {
			t.Fatalf("Format(%d) = %q, want %q", format, got, want)
		}
	}
	types := map[Type]string{
		TypeDictionary: "dictionary",
		TypeArray:      "array",
		TypeSet:        "set",
		TypeString:     "string",
		TypeInteger:    "integer",
		TypeReal:       "real",
		TypeBoolean:    "boolean",
		TypeDate:       "date",
		TypeData:       "data",
		TypeUID:        "uid",
		TypeNull:       "null",
		TypeUnknown:    "unknown",
	}
	for kind, want := range types {
		if got := kind.String(); got != want {
			t.Fatalf("Type(%d) = %q, want %q", kind, got, want)
		}
	}
}

// failingReader always fails.
type failingReader struct{}

func (failingReader) ReadAt([]byte, int64) (int, error) {
	return 0, io.ErrClosedPipe
}

// shortReader withholds the last byte of its data.
type shortReader struct{ data []byte }

func (r shortReader) ReadAt(p []byte, off int64) (int, error) {
	limit := int64(len(r.data) - 1)
	if off >= limit {
		return 0, io.EOF
	}
	return copy(p, r.data[off:limit]), nil
}

func TestReaderFailures(t *testing.T) {
	data := buildBinary(t, [][]byte{{0x00}})
	if _, err := Parse(failingReader{}, int64(len(data))); !errors.Is(err, ErrRead) {
		t.Fatalf("failing reader error = %v", err)
	}
	if _, err := Parse(shortReader{data: data}, int64(len(data))); !errors.Is(err, ErrRead) {
		t.Fatalf("short reader error = %v", err)
	}
	if _, err := readBytes(bytes.NewReader(data), int64(len(data)), 4, int64(len(data))); !errors.Is(err, ErrTruncated) {
		t.Fatalf("out-of-range read error = %v", err)
	}
	if _, err := readBytes(bytes.NewReader(data), -1, 4, int64(len(data))); !errors.Is(err, ErrTruncated) {
		t.Fatalf("negative offset read error = %v", err)
	}
	if _, err := readBytes(bytes.NewReader(data), 0, -1, int64(len(data))); !errors.Is(err, ErrTruncated) {
		t.Fatalf("negative length read error = %v", err)
	}
	if got, err := readPrefix(bytes.NewReader(data), 0, 4); err != nil || len(got) != 0 {
		t.Fatalf("empty prefix = %q, %v", got, err)
	}
}

func TestBase64Length(t *testing.T) {
	tests := []struct {
		text string
		want uint64
		ok   bool
	}{
		{"", 0, true},
		{"AAAA", 3, true},
		{"AAA=", 2, true},
		{"AA==", 1, true},
		{"AA\nAA", 3, true},
		{"abc", 0, false},
		{"A===", 0, false},
	}
	for _, test := range tests {
		got, ok := base64Length(test.text)
		if got != test.want || ok != test.ok {
			t.Fatalf("base64Length(%q) = %d, %v", test.text, got, ok)
		}
	}
}

func TestValidInteger(t *testing.T) {
	for _, text := range []string{"0", "7", "-1", "18446744073709551615"} {
		if !validInteger(text) {
			t.Fatalf("validInteger(%q) = false", text)
		}
	}
	for _, text := range []string{"", "x", "1.5", "18446744073709551616"} {
		if validInteger(text) {
			t.Fatalf("validInteger(%q) = true", text)
		}
	}
}

func TestClipText(t *testing.T) {
	if got := clipText([]byte("short")); got != "short" {
		t.Fatalf("clipText = %q", got)
	}
	if got := clipText([]byte(strings.Repeat("x", 40))); len(got) != 35 {
		t.Fatalf("clipText length = %d", len(got))
	}
}

func TestTrailerByteLayout(t *testing.T) {
	data := buildBinary(t, [][]byte{{0x00}})
	trailer := data[len(data)-binaryTrailerBytes:]
	if trailer[6] != 2 || trailer[7] != 1 {
		t.Fatalf("sizes = %d/%d", trailer[6], trailer[7])
	}
	if got := binary.BigEndian.Uint64(trailer[8:]); got != 1 {
		t.Fatalf("objects = %d", got)
	}
}

func TestParseBinarySetsAndOrdered(t *testing.T) {
	data := buildBinary(t, [][]byte{
		barray(1, 2, 3),
		append([]byte{0xB1}, 4),
		append([]byte{0xC1}, 5),
		{0xA0},
		bstr("a"),
		bstr("b"),
	})
	parsed := parseBytes(t, data)
	if got := parsed.Objects[1]; got.Type != TypeSet || len(got.Refs) != 1 || got.Refs[0] != 4 {
		t.Fatalf("ordered set = %#v", got)
	}
	if got := parsed.Objects[2]; got.Type != TypeSet || len(got.Refs) != 1 || got.Refs[0] != 5 {
		t.Fatalf("set = %#v", got)
	}
	if got := parsed.Objects[3]; got.Type != TypeArray || len(got.Refs) != 0 {
		t.Fatalf("empty array = %#v", got)
	}
}

func TestParseBinaryFloat32AndLongData(t *testing.T) {
	object := []byte{0x22, 0x3F, 0xC0, 0x00, 0x00}
	data := buildBinary(t, [][]byte{barray(1, 2), object, bdata(20)})
	parsed := parseBytes(t, data)
	if got := parsed.Objects[1]; got.Type != TypeReal || got.Real != 1.5 {
		t.Fatalf("float32 = %#v", got)
	}
	if got := parsed.Objects[2]; got.Type != TypeData || got.DataBytes != 20 {
		t.Fatalf("data = %#v", got)
	}
}

func TestParseXMLCommentsAndWhitespace(t *testing.T) {
	document := xmlDocument("\n<!-- before --><dict>\n<!-- inside --><key>a</key>\n<string>b</string></dict><!-- after -->")
	parsed := parseBytes(t, []byte(document))
	if root := parsed.Objects[0]; root.Type != TypeDictionary || len(root.Keys) != 1 {
		t.Fatalf("root = %#v", root)
	}
}

func TestParseXMLKeyStringLimit(t *testing.T) {
	document := xmlDocument(`<dict><key>` + strings.Repeat("k", 20) + `</key><string>v</string></dict>`)
	parsed, err := parseWith(t, []byte(document), Limits{StringBytes: 8})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	key := parsed.Objects[1]
	if key.TextAvailable || len(key.TextBytes) != 8 || len(key.Limitations) != 1 {
		t.Fatalf("key = %#v", key)
	}
}
