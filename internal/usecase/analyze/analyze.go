// Package analyze selects a built-in provider for a local artifact and returns
// sealed ree.evidence/1 evidence with a deterministic summary.
//
// Analyze inspects only the artifact bytes. It detects ELF, PE, or Mach-O and
// universal binaries by magic, delegates the read to the matching provider, and
// never executes, maps, decompresses, or writes artifact content. The artifact
// path is used for file system access only and never enters the evidence record
// or the summary.
package analyze

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/canonical"
	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	elfprovider "github.com/mrsandipmandal/reverse-engineer-everything/internal/providers/elf"
	machoprovider "github.com/mrsandipmandal/reverse-engineer-everything/internal/providers/macho"
	peprovider "github.com/mrsandipmandal/reverse-engineer-everything/internal/providers/pe"
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

	// MaxArtifactBytes is the largest artifact the built-in readers accept.
	MaxArtifactBytes int64 = 2 << 30
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
	case FormatAuto, FormatELF, FormatPE, FormatMachO:
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
		format, err = detect(file)
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

// detect reads the artifact magic and returns the matching format.
func detect(r io.ReaderAt) (string, error) {
	var magic [4]byte
	n, err := r.ReadAt(magic[:], 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("analyze: read artifact magic: %w", err)
	}
	switch {
	case n >= 4 && magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F':
		return FormatELF, nil
	case n >= 2 && magic[0] == 'M' && magic[1] == 'Z':
		return FormatPE, nil
	case n >= 4 && isMachOMagic(magic):
		return FormatMachO, nil
	default:
		return "", ErrUnsupportedFormat
	}
}
