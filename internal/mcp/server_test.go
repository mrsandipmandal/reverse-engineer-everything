package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/setup"
	"github.com/mrsandipmandal/reverse-engineer-everything/internal/version"
)

func TestInitialize(t *testing.T) {
	t.Parallel()

	info := version.Info{
		Name:      version.Name,
		Version:   "1.2.3",
		Commit:    "abcdef123456",
		Built:     "2026-10-26T00:00:00Z",
		GoVersion: "go1.26.10",
		OS:        "linux",
		Arch:      "amd64",
	}
	session := connect(t, NewServer(info))

	result := session.InitializeResult()
	if result == nil {
		t.Fatal("InitializeResult() = nil")
	}
	latest := sdk.SupportedProtocolVersions()[0]
	if result.ProtocolVersion != latest {
		t.Fatalf("protocol version = %q, want latest %q", result.ProtocolVersion, latest)
	}
	if result.ServerInfo == nil {
		t.Fatal("server info is nil")
	}
	if result.ServerInfo.Name != ServerName {
		t.Fatalf("server name = %q, want %q", result.ServerInfo.Name, ServerName)
	}
	if result.ServerInfo.Version != info.Version {
		t.Fatalf("server version = %q, want %q", result.ServerInfo.Version, info.Version)
	}
	if !strings.Contains(result.Instructions, SurfaceVersion) {
		t.Fatalf("instructions = %q, want surface version %q", result.Instructions, SurfaceVersion)
	}
}

func TestLegacyProtocol(t *testing.T) {
	t.Parallel()

	session := connectWith(t, NewServer(version.Get()), &sdk.ClientSessionOptions{ProtocolVersion: "2025-11-25"})
	result := session.InitializeResult()
	if result == nil {
		t.Fatal("InitializeResult() = nil")
	}
	if result.ProtocolVersion != "2025-11-25" {
		t.Fatalf("protocol version = %q, want %q", result.ProtocolVersion, "2025-11-25")
	}
	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	if len(tools.Tools) != 3 {
		t.Fatalf("tools = %d, want 3", len(tools.Tools))
	}
}

func TestListTools(t *testing.T) {
	t.Parallel()

	session := connect(t, NewServer(version.Get()))
	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	if result.NextCursor != "" {
		t.Fatalf("next cursor = %q, want empty", result.NextCursor)
	}
	if len(result.Tools) != 3 {
		t.Fatalf("tools = %d, want 3", len(result.Tools))
	}

	want := map[string]bool{
		VersionToolName: false,
		DoctorToolName:  false,
		AnalyzeToolName: false,
	}
	for _, tool := range result.Tools {
		if _, ok := want[tool.Name]; !ok {
			t.Fatalf("unexpected tool %q", tool.Name)
		}
		want[tool.Name] = true

		if tool.Description == "" {
			t.Fatalf("%q has no description", tool.Name)
		}
		if tool.InputSchema == nil {
			t.Fatalf("%q has no input schema", tool.Name)
		}
		if tool.OutputSchema == nil {
			t.Fatalf("%q has no output schema", tool.Name)
		}
		if tool.Annotations == nil {
			t.Fatalf("%q has no annotations", tool.Name)
		}
		if !tool.Annotations.ReadOnlyHint {
			t.Fatalf("%q is not marked read-only", tool.Name)
		}
		if !tool.Annotations.IdempotentHint {
			t.Fatalf("%q is not marked idempotent", tool.Name)
		}
		if tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
			t.Fatalf("%q is not marked closed-world", tool.Name)
		}
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("missing tool %q", name)
		}
	}
}

func TestVersionTool(t *testing.T) {
	t.Parallel()

	info := version.Info{
		Name:      version.Name,
		Version:   "1.2.3",
		Commit:    "abcdef123456",
		Built:     "2026-10-26T00:00:00Z",
		GoVersion: "go1.26.10",
		OS:        "linux",
		Arch:      "amd64",
	}
	session := connect(t, NewServer(info))

	result, err := session.CallTool(context.Background(), &sdk.CallToolParams{Name: VersionToolName})
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("CallTool() IsError = true; content=%v", result.Content)
	}
	if result.StructuredContent == nil {
		t.Fatal("StructuredContent is nil")
	}

	got := decodeStructured[version.Info](t, result)
	if got != info {
		t.Fatalf("version = %+v, want %+v", got, info)
	}
}

func TestDoctorTool(t *testing.T) {
	t.Parallel()

	want := setup.Report{
		SchemaVersion: setup.SchemaVersion,
		OK:            false,
		Platform: setup.Platform{
			OS:        "linux",
			Arch:      "amd64",
			GoVersion: "go1.26.10",
		},
		Tools: []setup.Tool{{
			Name:     "go",
			Required: true,
			Status:   setup.StatusMissing,
			Error:    "not found",
		}},
	}
	called := false
	server := newServer(version.Get(), func(context.Context) setup.Report {
		called = true
		return want
	})
	session := connect(t, server)

	result, err := session.CallTool(context.Background(), &sdk.CallToolParams{Name: DoctorToolName})
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("CallTool() IsError = true; content=%v", result.Content)
	}
	if !called {
		t.Fatal("doctor function was not called")
	}
	got := decodeStructured[setup.Report](t, result)
	if got.SchemaVersion != want.SchemaVersion {
		t.Fatalf("schema version = %q, want %q", got.SchemaVersion, want.SchemaVersion)
	}
	if got.OK != want.OK {
		t.Fatalf("ok = %t, want %t", got.OK, want.OK)
	}
	if len(got.Tools) != 1 || got.Tools[0].Name != "go" || got.Tools[0].Status != setup.StatusMissing {
		t.Fatalf("tools = %+v, want the injected report", got.Tools)
	}
}

func connect(t *testing.T, server *sdk.Server) *sdk.ClientSession {
	t.Helper()
	return connectWith(t, server, nil)
}

func connectWith(t *testing.T, server *sdk.Server, opts *sdk.ClientSessionOptions) *sdk.ClientSession {
	t.Helper()

	serverTransport, clientTransport := sdk.NewInMemoryTransports()
	serverSession, err := server.Connect(context.Background(), serverTransport, nil)
	if err != nil {
		t.Fatalf("server.Connect() error = %v", err)
	}

	client := sdk.NewClient(&sdk.Implementation{Name: "ree-test", Version: "1.0.0"}, nil)
	clientSession, err := client.Connect(context.Background(), clientTransport, opts)
	if err != nil {
		_ = serverSession.Close()
		t.Fatalf("client.Connect() error = %v", err)
	}

	t.Cleanup(func() {
		_ = clientSession.Close()
		_ = serverSession.Wait()
	})
	return clientSession
}

func decodeStructured[T any](t *testing.T, result *sdk.CallToolResult) T {
	t.Helper()

	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal structured content: %v", err)
	}
	return out
}
