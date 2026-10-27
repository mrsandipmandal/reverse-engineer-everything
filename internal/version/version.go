// Package version reports build and platform identity for REE.
package version

import (
	"runtime"
	"runtime/debug"
	"strings"
)

const (
	// Name is the machine-readable project name.
	Name = "reverse-engineer-everything"
	// DisplayName is the human-readable project name.
	DisplayName = "Reverse Engineer Everything"
)

var (
	// Version is set at build time with -ldflags.
	Version = "dev"
	// Commit is set at build time with -ldflags.
	Commit = "unknown"
	// Built is set at build time with -ldflags.
	Built = "unknown"
)

// Info describes the running build.
type Info struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Built     string `json:"built"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// Get returns the current build identity.
func Get() Info {
	bi, _ := debug.ReadBuildInfo()
	return resolveIdentity(Version, Commit, Built, bi, runtime.GOOS, runtime.GOARCH, runtime.Version())
}

// resolveIdentity merges linker-injected values with Go module build metadata.
// It is separate from Get so every fallback can be tested deterministically.
//
// Linker-injected values take precedence. A module version replaces the "dev"
// default, with the leading "v" removed so release archives and module builds
// report the same version form. Module builds do not carry VCS metadata, so
// Commit and Built stay "unknown" unless the linker set them.
func resolveIdentity(v, c, b string, bi *debug.BuildInfo, goos, goarch, goVersion string) Info {
	if bi != nil {
		if v == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			v = strings.TrimPrefix(bi.Main.Version, "v")
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if c == "unknown" {
					c = s.Value
				}
			case "vcs.time":
				if b == "unknown" {
					b = s.Value
				}
			}
		}
	}
	if len(c) > 12 {
		c = c[:12]
	}
	return Info{
		Name:      Name,
		Version:   v,
		Commit:    c,
		Built:     b,
		GoVersion: goVersion,
		OS:        goos,
		Arch:      goarch,
	}
}
