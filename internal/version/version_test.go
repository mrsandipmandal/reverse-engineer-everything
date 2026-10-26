package version

import (
	"runtime"
	"testing"
)

func TestGet(t *testing.T) {
	t.Parallel()

	info := Get()
	if info.Name != Name {
		t.Fatalf("Name = %q, want %q", info.Name, Name)
	}
	if info.Version == "" {
		t.Fatal("Version is empty")
	}
	if info.Commit == "" {
		t.Fatal("Commit is empty")
	}
	if info.Built == "" {
		t.Fatal("Built is empty")
	}
	if info.GoVersion != runtime.Version() {
		t.Fatalf("GoVersion = %q, want %q", info.GoVersion, runtime.Version())
	}
	if info.OS != runtime.GOOS {
		t.Fatalf("OS = %q, want %q", info.OS, runtime.GOOS)
	}
	if info.Arch != runtime.GOARCH {
		t.Fatalf("Arch = %q, want %q", info.Arch, runtime.GOARCH)
	}
}
