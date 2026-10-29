// Package analyze selects a built-in provider for a local artifact and returns
// sealed ree.evidence/1 evidence with a deterministic summary.
//
// Analyze inspects only the artifact bytes. It detects ELF, PE, Mach-O,
// universal binaries, ZIP, tar, gzip, Android packages, Electron ASAR archives,
// and Apple property lists by magic, delegates the read to the matching
// provider, and never executes, maps, decompresses, or writes artifact content.
// The artifact path is used for file system access only and never enters the
// evidence record or the summary.
package analyze

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/canonical"
	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	reapk "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/apk"
	rearchive "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/archive"
	replist "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/plist"
	apkprovider "github.com/mrsandipmandal/reverse-engineer-everything/internal/providers/apk"
	archiveprovider "github.com/mrsandipmandal/reverse-engineer-everything/internal/providers/archive"
	asarprovider "github.com/mrsandipmandal/reverse-engineer-everything/internal/providers/asar"
	elfprovider "github.com/mrsandipmandal/reverse-engineer-everything/internal/providers/elf"
	machoprovider "github.com/mrsandipmandal/reverse-engineer-everything/internal/providers/macho"
	peprovider "github.com/mrsandipmandal/reverse-engineer-everything/internal/providers/pe"
	plistprovider "github.com/mrsandipmandal/reverse-engineer-everything/internal/providers/plist"
)

const (
	// FormatAuto selects the provider from the artifact magic.
	FormatAuto = "auto"
	// FormatELF selects the built-in ELF provider.
	FormatELF = "elf"
	// FormatPE selects the built-in PE provider.
	FormatPE = "pe"
	// FormatMachO selects the built-in Mach-O provider. One provider reads
	// both thin images and universal binaries.
	FormatMachO = "macho"
	// FormatZIP selects the built-in archive provider for a ZIP container.
	FormatZIP = "zip"
	// FormatTar selects the built-in archive provider for a tar container.
	FormatTar = "tar"
	// FormatGZip selects the built-in archive provider for a gzip container.
	FormatGZip = "gzip"
	// FormatAPK selects the built-in Android package provider, which reads the
	// ZIP container and requires a root AndroidManifest.xml.
	FormatAPK = "apk"
	// FormatASAR selects the built-in Electron ASAR provider.
	FormatASAR = "asar"
	// FormatPlist selects the built-in Apple property list provider, which
	// reads both the binary and XML representations.
	FormatPlist = "plist"

	// MaxArtifactBytes is the largest artifact the built-in readers accept.
	MaxArtifactBytes int64 = 2 << 30

	// detectionBytes is the longest magic prefix a detector needs. Tar stores
	// its `ustar` magic at offset 257.
	detectionBytes = 512
)

// Sentinel errors. Errors returned by Analyze wrap one of these values unless a
// file system or provider error already explains the failure.
var (
	// ErrOptions reports an invalid analysis configuration.
	ErrOptions = errors.New("analyze: invalid options")
	// ErrUnsupportedFormat reports artifact bytes that match no built-in
	// provider.
	ErrUnsupportedFormat = errors.New("analyze: unsupported format")
	// ErrTooLarge reports an artifact above the configured byte limit.
	ErrTooLarge = errors.New("analyze: artifact exceeds the size limit")
	// ErrNotRegular reports a path that is not a regular file.
	ErrNotRegular = errors.New("analyze: path is not a regular file")
)

// Options configure Analyze.
type Options struct {
	// Format is FormatAuto, FormatELF, FormatPE, or FormatMachO. The empty
	// string selects FormatAuto.
	Format string
	// ProviderVersion is recorded in provider.version. It is required.
	ProviderVersion string
	// MaxBytes bounds the artifact size. Zero selects MaxArtifactBytes;
	// larger values are clamped to it.
	MaxBytes int64
}

func (o Options) withDefaults() (Options, error) {
	o.Format = strings.ToLower(strings.TrimSpace(o.Format))
	if o.Format == "" {
		o.Format = FormatAuto
	}
	switch o.Format {
	case FormatAuto, FormatELF, FormatPE, FormatMachO,
		FormatZIP, FormatTar, FormatGZip, FormatAPK, FormatASAR, FormatPlist:
	default:
		return Options{}, fmt.Errorf("%w: unknown format %q", ErrOptions, o.Format)
	}
	if o.ProviderVersion == "" {
		return Options{}, fmt.Errorf("%w: provider version is required", ErrOptions)
	}
	if o.MaxBytes < 0 {
		return Options{}, fmt.Errorf("%w: max bytes is negative", ErrOptions)
	}
	if o.MaxBytes == 0 || o.MaxBytes > MaxArtifactBytes {
		o.MaxBytes = MaxArtifactBytes
	}
	return o, nil
}

// Counts summarize the observed tables.
//
// Import counts name import modules, not thunks. Counts that do not apply to a
// format are zero, so the summary shape stays stable across formats.
type Counts struct {
	Sections     int `json:"sections"`
	Segments     int `json:"segments"`
	Symbols      int `json:"symbols"`
	Imports      int `json:"imports"`
	Exports      int `json:"exports"`
	Resources    int `json:"resources"`
	Certificates int `json:"certificates"`

	// Entries counts container entries: archive members, ASAR entries, or APK
	// entries, including members of nested containers.
	Entries int `json:"entries,omitempty"`
	// Objects counts property list objects.
	Objects int `json:"objects,omitempty"`
	// DEX counts Android DEX files.
	DEX int `json:"dex,omitempty"`
	// NativeLibraries counts Android native libraries.
	NativeLibraries int `json:"native_libraries,omitempty"`
	// SigningPairs counts APK Signing Block pairs.
	SigningPairs int `json:"signing_pairs,omitempty"`
}

// Summary is the deterministic, path-free description of one analysis.
type Summary struct {
	Format       string   `json:"format"`
	ProviderID   string   `json:"provider_id"`
	Profile      string   `json:"profile"`
	Version      string   `json:"version"`
	Size         int64    `json:"size"`
	SHA256       string   `json:"sha256"`
	RecordSHA256 string   `json:"record_sha256"`
	Coverage     string   `json:"coverage"`
	Limitations  []string `json:"limitations"`
	Unknowns     []string `json:"unknowns"`
	Counts       Counts   `json:"counts"`
}

// Result is one analysis: the summary, the decoded record, and its canonical
// sealed bytes.
type Result struct {
	Summary Summary
	Record  evidence.Evidence
	Bytes   []byte
}

// Analyze reads the regular file at path and returns sealed evidence for it.
//
// The returned bytes are canonical ree.evidence/1 JSON, already accepted by
// evidence.Encode. Two analyses of identical bytes with the same provider
// version produce identical record bytes. The path is used for file system
// access only: it never enters the record or the summary, so evidence can be
// shared without disclosing the host layout. Operational errors may still name
// the path, as a local command-line tool is expected to.
func Analyze(ctx context.Context, path string, opts Options) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	opts, err := opts.withDefaults()
	if err != nil {
		return Result{}, err
	}

	info, err := os.Stat(path)
	if err != nil {
		return Result{}, fmt.Errorf("analyze: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Result{}, fmt.Errorf("%w: %s", ErrNotRegular, path)
	}
	size := info.Size()
	if size > opts.MaxBytes {
		return Result{}, fmt.Errorf("%w: %d bytes exceeds %d", ErrTooLarge, size, opts.MaxBytes)
	}

	file, err := os.Open(path)
	if err != nil {
		return Result{}, fmt.Errorf("analyze: %w", err)
	}
	defer func() { _ = file.Close() }()

	format := opts.Format
	if format == FormatAuto {
		format, err = detect(file, size)
		if err != nil {
			return Result{}, err
		}
	}

	record, err := observe(file, size, format, opts.ProviderVersion)
	if err != nil {
		return Result{}, fmt.Errorf("analyze: %s: %w", format, err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	encoded, err := evidence.Encode(record)
	if err != nil {
		return Result{}, fmt.Errorf("analyze: encode: %w", err)
	}
	counts, err := countPayload(format, record.Payload)
	if err != nil {
		return Result{}, fmt.Errorf("analyze: payload counts: %w", err)
	}

	summary := Summary{
		Format:       format,
		ProviderID:   record.Provider.ID,
		Profile:      record.Provider.Profile,
		Version:      record.Provider.Version,
		Size:         record.Subject.Size,
		SHA256:       record.Subject.SHA256,
		RecordSHA256: canonical.SHA256(encoded),
		Coverage:     string(record.Coverage),
		Limitations:  append([]string{}, record.Limitations...),
		Unknowns:     append([]string{}, record.Unknowns...),
		Counts:       counts,
	}
	return Result{Summary: summary, Record: record, Bytes: encoded}, nil
}

func observe(r io.ReaderAt, size int64, format, version string) (evidence.Evidence, error) {
	switch format {
	case FormatELF:
		return elfprovider.Observe(r, size, elfprovider.Options{ProviderVersion: version})
	case FormatPE:
		return peprovider.Observe(r, size, peprovider.Options{ProviderVersion: version})
	case FormatMachO:
		return machoprovider.Observe(r, size, machoprovider.Options{ProviderVersion: version})
	case FormatZIP, FormatTar, FormatGZip:
		return archiveprovider.Observe(r, size, archiveprovider.Options{
			ProviderVersion: version,
			Container:       format,
		})
	case FormatAPK:
		return apkprovider.Observe(r, size, apkprovider.Options{ProviderVersion: version})
	case FormatASAR:
		return asarprovider.Observe(r, size, asarprovider.Options{ProviderVersion: version})
	case FormatPlist:
		return plistprovider.Observe(r, size, plistprovider.Options{ProviderVersion: version})
	default:
		return evidence.Evidence{}, fmt.Errorf("%w: %q", ErrUnsupportedFormat, format)
	}
}

// machoMagics lists the four-byte prefixes the Mach-O reader accepts: thin
// 32-bit and 64-bit images in both byte orders, and universal headers in the
// standard and byte-swapped forms.
//
// 0xcafebabe is also the Java class-file magic. Detection cannot tell them
// apart from four bytes, so a class file is reported as a Mach-O artifact whose
// universal header does not parse rather than as an unknown format.
var machoMagics = [...][4]byte{
	{0xfe, 0xed, 0xfa, 0xce}, // 32-bit, big-endian
	{0xfe, 0xed, 0xfa, 0xcf}, // 64-bit, big-endian
	{0xce, 0xfa, 0xed, 0xfe}, // 32-bit, little-endian
	{0xcf, 0xfa, 0xed, 0xfe}, // 64-bit, little-endian
	{0xca, 0xfe, 0xba, 0xbe}, // universal
	{0xca, 0xfe, 0xba, 0xbf}, // 64-bit universal
	{0xbe, 0xba, 0xfe, 0xca}, // universal, byte-swapped
	{0xbf, 0xba, 0xfe, 0xca}, // 64-bit universal, byte-swapped
}

// isMachOMagic reports whether the first four bytes name a Mach-O artifact.
func isMachOMagic(magic [4]byte) bool {
	for _, candidate := range machoMagics {
		if magic == candidate {
			return true
		}
	}
	return false
}

// detect reads the artifact prefix and returns the matching format.
//
// The prefix is read once and reused by every detector. A ZIP is probed for a
// root AndroidManifest.xml through the bounded APK reader so a package is
// labelled `apk`; a ZIP without one, or one the APK reader rejects, stays a
// ZIP and is explained by the archive provider.
func detect(r io.ReaderAt, size int64) (string, error) {
	prefix := make([]byte, detectionBytes)
	n, err := r.ReadAt(prefix, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("analyze: read artifact magic: %w", err)
	}
	prefix = prefix[:n]

	if n >= 4 && prefix[0] == 0x7f && prefix[1] == 'E' && prefix[2] == 'L' && prefix[3] == 'F' {
		return FormatELF, nil
	}
	if n >= 2 && prefix[0] == 'M' && prefix[1] == 'Z' {
		return FormatPE, nil
	}
	if n >= 4 {
		var magic [4]byte
		copy(magic[:], prefix[:4])
		if isMachOMagic(magic) {
			return FormatMachO, nil
		}
	}
	if isASARHeader(prefix) {
		return FormatASAR, nil
	}
	switch rearchive.Detect(prefix) {
	case rearchive.ContainerZIP:
		if _, err := reapk.Parse(r, size); err == nil {
			return FormatAPK, nil
		}
		return FormatZIP, nil
	case rearchive.ContainerTar:
		return FormatTar, nil
	case rearchive.ContainerGZIP:
		return FormatGZip, nil
	}
	if format := replist.Detect(prefix); format != replist.FormatUnknown {
		// plist.Detect only looks for a leading `<`. Requiring the `plist`
		// token keeps an unrelated XML document out of the plist provider.
		if format == replist.FormatBinary || bytes.Contains(prefix, []byte("plist")) {
			return FormatPlist, nil
		}
	}
	return "", ErrUnsupportedFormat
}

// isASARHeader reports whether prefix looks like a Chromium Pickle header: a
// four-byte payload size of 4 followed by a plausible header size.
func isASARHeader(prefix []byte) bool {
	const asarMaxHeaderBytes = 64 << 20
	if len(prefix) < 8 {
		return false
	}
	if binary.LittleEndian.Uint32(prefix[0:4]) != 4 {
		return false
	}
	header := binary.LittleEndian.Uint32(prefix[4:8])
	return header >= 8 && header <= asarMaxHeaderBytes
}
