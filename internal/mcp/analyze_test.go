package mcp

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/canonical"
	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	"github.com/mrsandipmandal/reverse-engineer-everything/internal/usecase/analyze"
	"github.com/mrsandipmandal/reverse-engineer-everything/internal/version"
)

func TestAnalyzeToolELF(t *testing.T) {
	t.Parallel()

	data := minimalAnalyzeELF64()
	path := writeAnalyzeFixture(t, "sample.elf", data)
	session := connect(t, NewServer(version.Get()))

	result := callAnalyze(t, session, map[string]any{"path": path})
	report := decodeStructured[analyzeReport](t, result)
	summary := report.Summary

	if summary.Format != analyze.FormatELF {
		t.Fatalf("format = %q, want %q", summary.Format, analyze.FormatELF)
	}
	if summary.ProviderID != "builtin.elf" || summary.Profile != "default" {
		t.Fatalf("provider = %q/%q, want builtin.elf/default", summary.ProviderID, summary.Profile)
	}
	if summary.Version != version.Get().Version {
		t.Fatalf("version = %q, want %q", summary.Version, version.Get().Version)
	}
	if summary.Size != int64(len(data)) {
		t.Fatalf("size = %d, want %d", summary.Size, len(data))
	}
	sum := sha256.Sum256(data)
	if summary.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("subject digest = %q, want the fixture digest", summary.SHA256)
	}
	if len(summary.RecordSHA256) != 64 || !canonical.ValidSHA256Hex(summary.RecordSHA256) {
		t.Fatalf("record digest = %q, want lowercase hex", summary.RecordSHA256)
	}
	if summary.Coverage != string(evidence.CoverageComplete) {
		t.Fatalf("coverage = %q, want complete", summary.Coverage)
	}
	if summary.Limitations == nil || summary.Unknowns == nil {
		t.Fatalf("limitations = %v, unknowns = %v; want non-nil empty slices", summary.Limitations, summary.Unknowns)
	}
	if summary.Counts != (analyze.Counts{}) {
		t.Fatalf("counts = %+v, want zero", summary.Counts)
	}
	if report.Record != nil {
		t.Fatal("record is present although include_record was not set")
	}
	if report.RecordOmitted != "" {
		t.Fatalf("record_omitted = %q, want empty", report.RecordOmitted)
	}
}

func TestAnalyzeToolZIP(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	member, err := writer.CreateHeader(&zip.FileHeader{Name: "hello.txt", Method: zip.Store})
	if err != nil {
		t.Fatalf("create member: %v", err)
	}
	if _, err := member.Write([]byte("hi")); err != nil {
		t.Fatalf("write member: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}
	path := writeAnalyzeFixture(t, "bundle.zip", buffer.Bytes())
	session := connect(t, NewServer(version.Get()))

	result := callAnalyze(t, session, map[string]any{"path": path})
	summary := decodeStructured[analyzeReport](t, result).Summary

	if summary.Format != analyze.FormatZIP {
		t.Fatalf("format = %q, want %q", summary.Format, analyze.FormatZIP)
	}
	if summary.ProviderID != "builtin.archive" || summary.Profile != "default" {
		t.Fatalf("provider = %q/%q, want builtin.archive/default", summary.ProviderID, summary.Profile)
	}
	if summary.Coverage != string(evidence.CoverageComplete) {
		t.Fatalf("coverage = %q, want complete", summary.Coverage)
	}
	if summary.Counts.Entries != 1 {
		t.Fatalf("entry count = %d, want 1", summary.Counts.Entries)
	}
}

func TestAnalyzeToolPE(t *testing.T) {
	t.Parallel()

	data := minimalAnalyzePE32()
	path := writeAnalyzeFixture(t, "sample.exe", data)
	session := connect(t, NewServer(version.Get()))

	result := callAnalyze(t, session, map[string]any{"path": path, "format": "pe"})
	summary := decodeStructured[analyzeReport](t, result).Summary

	if summary.Format != analyze.FormatPE {
		t.Fatalf("format = %q, want %q", summary.Format, analyze.FormatPE)
	}
	if summary.ProviderID != "builtin.pe" {
		t.Fatalf("provider = %q, want builtin.pe", summary.ProviderID)
	}
	if summary.Size != int64(len(data)) {
		t.Fatalf("size = %d, want %d", summary.Size, len(data))
	}
	if summary.Counts != (analyze.Counts{}) {
		t.Fatalf("counts = %+v, want zero", summary.Counts)
	}
}

func TestAnalyzeToolIncludeRecord(t *testing.T) {
	t.Parallel()

	path := writeAnalyzeFixture(t, "sample.elf", minimalAnalyzeELF64())
	session := connect(t, NewServer(version.Get()))

	result := callAnalyze(t, session, map[string]any{"path": path, "include_record": true})
	report := decodeStructured[analyzeReport](t, result)
	if report.Record == nil {
		t.Fatalf("record is absent; record_omitted = %q", report.RecordOmitted)
	}

	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	var wrapper struct {
		Summary analyze.Summary `json:"summary"`
		Record  json.RawMessage `json:"record"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		t.Fatalf("unmarshal structured content: %v", err)
	}
	sealed, err := canonical.Bytes(wrapper.Record)
	if err != nil {
		t.Fatalf("canonicalize record: %v", err)
	}
	rec, err := evidence.Decode(sealed)
	if err != nil {
		t.Fatalf("decode record: %v", err)
	}
	digest, err := rec.Digest()
	if err != nil {
		t.Fatalf("digest record: %v", err)
	}
	if digest != wrapper.Summary.RecordSHA256 {
		t.Fatalf("record digest = %q, want %q", digest, wrapper.Summary.RecordSHA256)
	}
	if rec.Subject.SHA256 != wrapper.Summary.SHA256 {
		t.Fatalf("record subject = %q, want %q", rec.Subject.SHA256, wrapper.Summary.SHA256)
	}
	if rec.Provider.Version != version.Get().Version {
		t.Fatalf("record provider version = %q, want %q", rec.Provider.Version, version.Get().Version)
	}
}

func TestAnalyzeReportRecordLimit(t *testing.T) {
	t.Parallel()

	small := analyzeResult([]byte(`{"schema":"ree.evidence/1"}`))

	report := analyzeReportFor(small, true)
	if report.Record == nil {
		t.Fatal("small record was omitted")
	}
	if report.RecordOmitted != "" {
		t.Fatalf("record_omitted = %q, want empty", report.RecordOmitted)
	}

	report = analyzeReportFor(small, false)
	if report.Record != nil || report.RecordOmitted != "" {
		t.Fatalf("record = %v, record_omitted = %q; want neither", report.Record, report.RecordOmitted)
	}

	large := analyzeResult(make([]byte, MaxRecordToolBytes+1))
	report = analyzeReportFor(large, true)
	if report.Record != nil {
		t.Fatal("oversized record was included")
	}
	if !strings.Contains(report.RecordOmitted, "tool limit") {
		t.Fatalf("record_omitted = %q, want the tool limit", report.RecordOmitted)
	}
	if !strings.Contains(report.RecordOmitted, "ree analyze --out") {
		t.Fatalf("record_omitted = %q, want the export hint", report.RecordOmitted)
	}
}

func TestAnalyzeToolErrors(t *testing.T) {
	t.Parallel()

	elfPath := writeAnalyzeFixture(t, "sample.elf", minimalAnalyzeELF64())
	pePath := writeAnalyzeFixture(t, "sample.exe", minimalAnalyzePE32())
	textPath := writeAnalyzeFixture(t, "notes.txt", []byte("not an artifact\n"))
	dirPath := t.TempDir()
	missing := filepath.Join(t.TempDir(), "missing.bin")

	tests := []struct {
		name string
		args map[string]any
		want string
	}{
		{name: "missing artifact", args: map[string]any{"path": missing}, want: "artifact not found"},
		{name: "unsupported bytes", args: map[string]any{"path": textPath}, want: "unsupported format"},
		{name: "directory", args: map[string]any{"path": dirPath}, want: "not a regular file"},
		{name: "size limit", args: map[string]any{"path": elfPath, "max_bytes": 32}, want: "size limit"},
		{name: "unknown format", args: map[string]any{"path": elfPath, "format": "coff"}, want: "invalid arguments"},
		{name: "macho mismatch", args: map[string]any{"path": elfPath, "format": "macho"}, want: "parse"},
		{name: "format mismatch", args: map[string]any{"path": pePath, "format": "elf"}, want: "parse"},
		{name: "missing path", args: map[string]any{}, want: "required"},
		{name: "blank path", args: map[string]any{"path": "  "}, want: "path is required"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			session := connect(t, NewServer(version.Get()))
			result, err := session.CallTool(context.Background(), &sdk.CallToolParams{
				Name:      AnalyzeToolName,
				Arguments: test.args,
			})
			if err != nil {
				t.Fatalf("CallTool() error = %v", err)
			}
			if !result.IsError {
				t.Fatalf("CallTool() IsError = false; structured content = %v", result.StructuredContent)
			}
			text := resultText(t, result)
			if !strings.Contains(text, test.want) {
				t.Fatalf("error text = %q, want %q", text, test.want)
			}
		})
	}
}

func TestAnalyzeToolDoesNotLeakPath(t *testing.T) {
	t.Parallel()

	path := writeAnalyzeFixture(t, "secret-name.elf", minimalAnalyzeELF64())
	session := connect(t, NewServer(version.Get()))

	result := callAnalyze(t, session, map[string]any{"path": path, "include_record": true})
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	for _, part := range []string{filepath.Dir(path), filepath.Base(path)} {
		if strings.Contains(string(data), part) {
			t.Fatalf("structured content contains %q: %s", part, data)
		}
	}
}

func TestAnalyzeToolDeterministic(t *testing.T) {
	t.Parallel()

	path := writeAnalyzeFixture(t, "sample.elf", minimalAnalyzeELF64())
	session := connect(t, NewServer(version.Get()))

	first := callAnalyze(t, session, map[string]any{"path": path, "include_record": true})
	second := callAnalyze(t, session, map[string]any{"path": path, "include_record": true})
	firstBytes, err := json.Marshal(first.StructuredContent)
	if err != nil {
		t.Fatalf("marshal first result: %v", err)
	}
	secondBytes, err := json.Marshal(second.StructuredContent)
	if err != nil {
		t.Fatalf("marshal second result: %v", err)
	}
	if string(firstBytes) != string(secondBytes) {
		t.Fatalf("results differ:\n%s\n%s", firstBytes, secondBytes)
	}
}

func TestAnalyzeToolCanceledContext(t *testing.T) {
	t.Parallel()

	path := writeAnalyzeFixture(t, "sample.elf", minimalAnalyzeELF64())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := analyzeArtifact(ctx, analyzeInput{Path: path}, version.Get().Version)
	if err == nil {
		t.Fatal("analyzeArtifact() error = nil, want a cancellation error")
	}
	if !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("error = %v, want context canceled", err)
	}
}

func callAnalyze(t *testing.T, session *sdk.ClientSession, args map[string]any) *sdk.CallToolResult {
	t.Helper()

	result, err := session.CallTool(context.Background(), &sdk.CallToolParams{
		Name:      AnalyzeToolName,
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("CallTool() IsError = true; content = %s", resultText(t, result))
	}
	if result.StructuredContent == nil {
		t.Fatal("StructuredContent is nil")
	}
	return result
}

func resultText(t *testing.T, result *sdk.CallToolResult) string {
	t.Helper()

	var texts []string
	for _, content := range result.Content {
		if text, ok := content.(*sdk.TextContent); ok {
			texts = append(texts, text.Text)
		}
	}
	return strings.Join(texts, "\n")
}

func analyzeResult(data []byte) analyze.Result {
	return analyze.Result{
		Summary: analyze.Summary{Format: analyze.FormatELF},
		Bytes:   data,
	}
}

func minimalAnalyzeELF64() []byte {
	data := make([]byte, 64)
	copy(data[0:4], "\x7fELF")
	data[4] = 2
	data[5] = 1
	data[6] = 1
	binary.LittleEndian.PutUint16(data[16:], 2)
	binary.LittleEndian.PutUint16(data[18:], 0x3e)
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint16(data[52:], 64)
	return data
}

func minimalAnalyzePE32() []byte {
	const (
		peOffset  = 0x80
		coffSize  = 20
		optOffset = peOffset + 4 + coffSize
	)
	data := make([]byte, 512)
	binary.LittleEndian.PutUint16(data[0:], 0x5a4d)
	binary.LittleEndian.PutUint32(data[0x3c:], peOffset)

	copy(data[peOffset:], "PE\x00\x00")
	coff := data[peOffset+4:]
	binary.LittleEndian.PutUint16(coff[0:], 0x14c)
	binary.LittleEndian.PutUint16(coff[2:], 0)
	binary.LittleEndian.PutUint16(coff[16:], 96)
	binary.LittleEndian.PutUint16(coff[18:], 0x0102)

	opt := data[optOffset:]
	binary.LittleEndian.PutUint16(opt[0:], 0x10b)
	binary.LittleEndian.PutUint32(opt[28:], 0x400000)
	binary.LittleEndian.PutUint32(opt[32:], 0x1000)
	binary.LittleEndian.PutUint32(opt[36:], 0x200)
	binary.LittleEndian.PutUint32(opt[56:], 0x1000)
	binary.LittleEndian.PutUint32(opt[60:], 0x200)
	binary.LittleEndian.PutUint16(opt[68:], 3)
	binary.LittleEndian.PutUint32(opt[92:], 0)
	return data
}

func writeAnalyzeFixture(t testing.TB, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture %q: %v", name, err)
	}
	return path
}

func TestAnalyzeToolSchema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	session := connect(t, NewServer(version.Get()))
	result, err := session.ListTools(ctx, &sdk.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}

	var schema map[string]any
	for _, tool := range result.Tools {
		if tool.Name != AnalyzeToolName {
			continue
		}
		data, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatalf("marshal input schema: %v", err)
		}
		if err := json.Unmarshal(data, &schema); err != nil {
			t.Fatalf("unmarshal input schema: %v", err)
		}
	}

	if schema == nil {
		t.Fatalf("tool %q is missing", AnalyzeToolName)
	}
	required, ok := schema["required"].([]any)
	if !ok || len(required) != 1 || required[0] != "path" {
		t.Fatalf("required = %v, want [path]", schema["required"])
	}
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties = %v, want an object", schema["properties"])
	}
	for _, name := range []string{"path", "format", "max_bytes", "include_record"} {
		if _, ok := properties[name]; !ok {
			t.Fatalf("properties missing %q: %v", name, properties)
		}
	}
}
