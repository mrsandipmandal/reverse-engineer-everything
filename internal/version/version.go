// Package version reports build and platform identity for REE.
package version

import (
	"runtime"
	"runtime/debug"
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
	v, c, b := Version, Commit, Built
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			v = bi.Main.Version
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
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}
