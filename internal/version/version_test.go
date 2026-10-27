package version

import (
	"runtime"
	"runtime/debug"
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

func TestResolveIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		version     string
		commit      string
		built       string
		buildInfo   *debug.BuildInfo
		wantVersion string
		wantCommit  string
		wantBuilt   string
	}{
		{
			name:        "module version loses the tag prefix",
			version:     "dev",
			commit:      "unknown",
			built:       "unknown",
			buildInfo:   &debug.BuildInfo{Main: debug.Module{Version: "v0.0.2"}},
			wantVersion: "0.0.2",
			wantCommit:  "unknown",
			wantBuilt:   "unknown",
		},
		{
			name:        "module version without prefix is unchanged",
			version:     "dev",
			commit:      "unknown",
			built:       "unknown",
			buildInfo:   &debug.BuildInfo{Main: debug.Module{Version: "0.0.2"}},
			wantVersion: "0.0.2",
			wantCommit:  "unknown",
			wantBuilt:   "unknown",
		},
		{
			name:        "pseudo version loses the tag prefix",
			version:     "dev",
			commit:      "unknown",
			built:       "unknown",
			buildInfo:   &debug.BuildInfo{Main: debug.Module{Version: "v0.0.0-20261027000000-abcdef123456"}},
			wantVersion: "0.0.0-20261027000000-abcdef123456",
			wantCommit:  "unknown",
			wantBuilt:   "unknown",
		},
		{
			name:        "development module version keeps the default",
			version:     "dev",
			commit:      "unknown",
			built:       "unknown",
			buildInfo:   &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}},
			wantVersion: "dev",
			wantCommit:  "unknown",
			wantBuilt:   "unknown",
		},
		{
			name:        "empty module version keeps the default",
			version:     "dev",
			commit:      "unknown",
			built:       "unknown",
			buildInfo:   &debug.BuildInfo{},
			wantVersion: "dev",
			wantCommit:  "unknown",
			wantBuilt:   "unknown",
		},
		{
			name:        "missing build info keeps linker values",
			version:     "dev",
			commit:      "unknown",
			built:       "unknown",
			buildInfo:   nil,
			wantVersion: "dev",
			wantCommit:  "unknown",
			wantBuilt:   "unknown",
		},
		{
			name:        "linker version wins over module version",
			version:     "0.0.2",
			commit:      "abcdef1234567890",
			built:       "2026-10-27T00:00:00Z",
			buildInfo:   &debug.BuildInfo{Main: debug.Module{Version: "v9.9.9"}},
			wantVersion: "0.0.2",
			wantCommit:  "abcdef123456",
			wantBuilt:   "2026-10-27T00:00:00Z",
		},
		{
			name:        "vcs settings fill unknown values",
			version:     "dev",
			commit:      "unknown",
			built:       "unknown",
			buildInfo:   &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abcdef1234567890"}, {Key: "vcs.time", Value: "2026-10-27T00:00:00Z"}}},
			wantVersion: "dev",
			wantCommit:  "abcdef123456",
			wantBuilt:   "2026-10-27T00:00:00Z",
		},
		{
			name:        "linker commit and build time win over vcs settings",
			version:     "0.0.2",
			commit:      "1111111111111",
			built:       "2026-01-01T00:00:00Z",
			buildInfo:   &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "2222222222222"}, {Key: "vcs.time", Value: "2026-02-02T00:00:00Z"}}},
			wantVersion: "0.0.2",
			wantCommit:  "111111111111",
			wantBuilt:   "2026-01-01T00:00:00Z",
		},
		{
			name:        "short commit is unchanged",
			version:     "dev",
			commit:      "unknown",
			built:       "unknown",
			buildInfo:   &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abc"}}},
			wantVersion: "dev",
			wantCommit:  "abc",
			wantBuilt:   "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			info := resolveIdentity(tt.version, tt.commit, tt.built, tt.buildInfo, "linux", "amd64", "go1.26.10")
			if info.Version != tt.wantVersion {
				t.Fatalf("Version = %q, want %q", info.Version, tt.wantVersion)
			}
			if info.Commit != tt.wantCommit {
				t.Fatalf("Commit = %q, want %q", info.Commit, tt.wantCommit)
			}
			if info.Built != tt.wantBuilt {
				t.Fatalf("Built = %q, want %q", info.Built, tt.wantBuilt)
			}
			if info.Name != Name {
				t.Fatalf("Name = %q, want %q", info.Name, Name)
			}
			if info.OS != "linux" || info.Arch != "amd64" || info.GoVersion != "go1.26.10" {
				t.Fatalf("platform = %s/%s %s, want linux/amd64 go1.26.10", info.OS, info.Arch, info.GoVersion)
			}
		})
	}
}
