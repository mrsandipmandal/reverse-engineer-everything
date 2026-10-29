// Package apk reads Android application packages without extracting them.
//
// An APK is a ZIP archive with a fixed set of well-known members. Parse reuses
// the bounded ZIP reader in internal/formats/archive, classifies every entry
// against the Android layout, and detects the APK Signing Block that sits
// immediately before the central directory. The binary AndroidManifest.xml,
// the DEX files, and resources.arsc are inventoried as declared bytes: their
// content is hashed but never decoded, and nothing claims a signature is valid.
//
// Input is untrusted. An artifact without a ZIP end record fails with a
// sentinel error, and so does a package without a root AndroidManifest.xml
// entry. Signing block sizes are validated against the central directory; a
// block that contradicts itself is invalid rather than partially trusted. A
// signing pair or entry count above a configured limit is reported through
// Truncated and a limitation.
//
// The package never writes, extracts, links, maps, or executes content.
package apk

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/archive"
)

// Package limits. Callers may lower them through Limits but cannot raise them
// above these values.
const (
	// MaxArtifactBytes bounds the artifact size accepted by Parse.
	MaxArtifactBytes int64 = archive.MaxArtifactBytes
	// MaxEntries bounds the ZIP entries loaded from one package.
	MaxEntries = archive.MaxEntries
	// MaxSigningBytes bounds the APK Signing Block pair area read.
	MaxSigningBytes int64 = 16 << 20
	// MaxSigningPairs bounds the signing block pairs decoded.
	MaxSigningPairs = 64
	// MaxDigestBytes bounds one hashed member.
	MaxDigestBytes int64 = 64 << 20
	// MaxTotalDigestBytes bounds every member hash in one package.
	MaxTotalDigestBytes int64 = 256 << 20
)

// Sentinel errors. Errors returned by this package wrap exactly one of these
// values unless the ZIP reader itself fails, in which case the archived
// sentinel is preserved as well.
var (
	// ErrInvalid reports a structurally invalid APK: no ZIP end record, no
	// ZIP container, or a signing block that contradicts itself.
	ErrInvalid = errors.New("apk: invalid artifact")
	// ErrNotPackage reports a valid ZIP archive without a root
	// AndroidManifest.xml, so the artifact is an archive and not a package.
	ErrNotPackage = errors.New("apk: root AndroidManifest.xml is missing")
	// ErrTruncated reports that a declared structure extends beyond the
	// artifact end.
	ErrTruncated = errors.New("apk: truncated artifact")
	// ErrLimit reports an artifact size above the configured limit.
	ErrLimit = errors.New("apk: limit exceeded")
	// ErrRead reports a failure or short read from the underlying reader.
	ErrRead = errors.New("apk: read failed")
)

// Kind is the Android role of one ZIP entry.
type Kind uint8

// Entry kinds reported by this package.
const (
	// KindOther is an entry outside the well-known Android layout.
	KindOther Kind = 0
	// KindManifest is the root AndroidManifest.xml, a binary XML document.
	KindManifest Kind = 1
	// KindDEX is a root classes*.dex bytecode file.
	KindDEX Kind = 2
	// KindResources is the root resources.arsc resource table.
	KindResources Kind = 3
	// KindNativeLibrary is a lib/<abi>/*.so native library.
	KindNativeLibrary Kind = 4
	// KindResource is a res/* packaged resource.
	KindResource Kind = 5
	// KindAsset is an assets/* packaged asset.
	KindAsset Kind = 6
	// KindSignature is a META-INF signature block file.
	KindSignature Kind = 7
)

// String returns the kind name used in evidence.
func (k Kind) String() string {
	switch k {
	case KindManifest:
		return "manifest"
	case KindDEX:
		return "dex"
	case KindResources:
		return "resources"
	case KindNativeLibrary:
		return "native_library"
	case KindResource:
		return "resource"
	case KindAsset:
		return "asset"
	case KindSignature:
		return "signature"
	default:
		return "other"
	}
}

// Entry is the Android classification of one ZIP entry.
//
// The ZIP header fields and the content stay in ZIP, which has an entry at the
// same index. Entry only states the Android role, the digest computed for a
// well-known member, and why the view is incomplete.
type Entry struct {
	// Kind is the Android role of the entry.
	Kind Kind
	// ABI is the native library ABI for KindNativeLibrary, empty otherwise.
	ABI string
	// Digest is the lowercase SHA-256 of the member content, empty when
	// DigestAvailable is false.
	Digest string
	// DigestAvailable reports that the content was read and hashed in full.
	DigestAvailable bool
	// Limitations states, in deterministic order, why this entry's view is
	// incomplete.
	Limitations []string
}

// Pair is one identification pair in the APK Signing Block.
type Pair struct {
	// ID is the pair identifier from the block.
	ID uint32
	// Scheme names a known signing scheme, empty for an unrecognized ID.
	Scheme string
	// ValueBytes is the declared value length.
	ValueBytes uint64
	// Digest is the lowercase SHA-256 of the value, empty when unavailable.
	Digest string
	// DigestAvailable reports that the value was hashed in full.
	DigestAvailable bool
}

// SigningBlock is the APK Signing Block found before the central directory.
type SigningBlock struct {
	// Present reports that the block magic was found.
	Present bool
	// Offset is the absolute artifact offset of the block, zero when absent.
	Offset int64
	// Size is the total block size including both size fields, zero when
	// absent.
	Size uint64
	// Pairs are the identification pairs in block order.
	Pairs []Pair
	// Truncated reports that the pair limit or byte limit stopped the scan.
	Truncated bool
	// Limitations states, in deterministic order, why the block view is
	// incomplete.
	Limitations []string
}

// APK is one parsed Android package.
type APK struct {
	// ZIP is the underlying bounded ZIP inventory.
	ZIP *archive.Archive
	// Entries is the Android classification of every ZIP entry, in the same
	// order and of the same length.
	Entries []Entry
	// Signing is the APK Signing Block, zero when the artifact is not signed
	// with scheme v2 or later.
	Signing SigningBlock
	// Truncated reports that the entry or signing block inventory is
	// incomplete.
	Truncated bool
	// Limitations states, in deterministic order, why the loaded inventory is
	// incomplete.
	Limitations []string

	size   int64
	limits Limits
}

// Size returns the artifact size supplied to Parse.
func (a *APK) Size() int64 {
	if a == nil {
		return 0
	}
	return a.size
}

// Limits bounds parsing work. A zero or negative field selects the package
// default. Values above the package maximum are clamped to that maximum.
type Limits struct {
	// ArtifactBytes bounds the artifact size accepted by Parse.
	ArtifactBytes int64
	// Entries bounds the ZIP entries loaded.
	Entries int
	// SigningBytes bounds the signing block pair area read.
	SigningBytes int64
	// SigningPairs bounds the signing block pairs decoded.
	SigningPairs int
	// DigestBytes bounds one hashed member.
	DigestBytes int64
	// TotalDigestBytes bounds every member hash in one package.
	TotalDigestBytes int64
}

// DefaultLimits returns the package limits.
func DefaultLimits() Limits {
	return Limits{
		ArtifactBytes:    MaxArtifactBytes,
		Entries:          MaxEntries,
		SigningBytes:     MaxSigningBytes,
		SigningPairs:     MaxSigningPairs,
		DigestBytes:      MaxDigestBytes,
		TotalDigestBytes: MaxTotalDigestBytes,
	}
}

func clamp(value, maximum int64) int64 {
	if value <= 0 {
		return maximum
	}
	if value > maximum {
		return maximum
	}
	return value
}

func (l Limits) withDefaults() Limits {
	defaults := DefaultLimits()
	l.ArtifactBytes = clamp(l.ArtifactBytes, defaults.ArtifactBytes)
	l.SigningBytes = clamp(l.SigningBytes, defaults.SigningBytes)
	l.DigestBytes = clamp(l.DigestBytes, defaults.DigestBytes)
	l.TotalDigestBytes = clamp(l.TotalDigestBytes, defaults.TotalDigestBytes)
	l.Entries = int(clamp(int64(l.Entries), int64(defaults.Entries)))
	l.SigningPairs = int(clamp(int64(l.SigningPairs), int64(defaults.SigningPairs)))
	return l
}

// Parse reads an Android package with the package limits.
func Parse(r io.ReaderAt, size int64) (*APK, error) {
	return ParseWithLimits(r, size, Limits{})
}

// ParseWithLimits reads an Android package using limits.
//
// A ZIP archive without a root AndroidManifest.xml entry returns a nil APK and
// an error wrapping ErrInvalid, because the artifact is a ZIP and not an APK. A
// ZIP directory or entry count cut short by a limit yields a non-nil APK with
// Truncated set and a nil error.
func ParseWithLimits(r io.ReaderAt, size int64, limits Limits) (*APK, error) {
	limits = limits.withDefaults()
	if r == nil {
		return nil, fmt.Errorf("%w: nil reader", ErrInvalid)
	}
	if size < 0 {
		return nil, fmt.Errorf("%w: negative artifact size", ErrInvalid)
	}
	if size > limits.ArtifactBytes {
		return nil, fmt.Errorf("%w: artifact size %d exceeds limit %d",
			ErrLimit, size, limits.ArtifactBytes)
	}

	zip, err := archive.ParseWithLimits(r, size, archive.Limits{
		ArtifactBytes:  limits.ArtifactBytes,
		Entries:        limits.Entries,
		EntryDataBytes: limits.DigestBytes,
	})
	if err != nil {
		return nil, mapArchiveError(err)
	}
	if zip.Container != archive.ContainerZIP {
		return nil, fmt.Errorf("%w: container is %s, want ZIP", ErrInvalid, zip.Container)
	}

	manifest := false
	for _, entry := range zip.Entries {
		if entry.NameAvailable && entry.Name == "AndroidManifest.xml" &&
			entry.Type == archive.EntryFile {
			manifest = true
			break
		}
	}
	if !manifest {
		return nil, ErrNotPackage
	}

	out := &APK{
		ZIP:         zip,
		Entries:     make([]Entry, len(zip.Entries)),
		Truncated:   zip.Truncated,
		Limitations: append([]string(nil), zip.Limitations...),
		size:        size,
		limits:      limits,
	}
	manifests := 0
	for index := range zip.Entries {
		entry := &zip.Entries[index]
		out.Entries[index] = classify(entry)
		if out.Entries[index].Kind == KindManifest {
			manifests++
		}
	}
	if manifests > 1 {
		out.note("%d AndroidManifest.xml entries; the first is reported", manifests)
	}
	out.digest(limits)

	cdOffset, ok := centralDirectoryOffset(r, size)
	if !ok {
		out.note("central directory offset is unavailable; the signing block was not inspected")
	} else {
		signing, err := parseSigningBlock(r, size, cdOffset, limits)
		if err != nil {
			return nil, err
		}
		out.Signing = signing
		if signing.Truncated {
			out.Truncated = true
		}
		for _, limitation := range signing.Limitations {
			out.note("%s", limitation)
		}
	}
	return out, nil
}

// note appends a limitation once, in first-seen order.
func (a *APK) note(format string, args ...any) {
	reason := fmt.Sprintf(format, args...)
	for _, existing := range a.Limitations {
		if existing == reason {
			return
		}
	}
	a.Limitations = append(a.Limitations, reason)
}

// mapArchiveError translates a ZIP sentinel into the APK sentinel while keeping
// the original error for diagnosis.
func mapArchiveError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, archive.ErrInvalid):
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	case errors.Is(err, archive.ErrTruncated):
		return fmt.Errorf("%w: %w", ErrTruncated, err)
	case errors.Is(err, archive.ErrLimit):
		return fmt.Errorf("%w: %w", ErrLimit, err)
	case errors.Is(err, archive.ErrRead):
		return fmt.Errorf("%w: %w", ErrRead, err)
	default:
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
}

// digest hashes the well-known members that carry executable or resource
// meaning: the manifest, every root DEX file, and the resource table.
func (a *APK) digest(limits Limits) {
	spent := int64(0)
	for index := range a.Entries {
		entry := &a.Entries[index]
		if entry.Kind != KindManifest && entry.Kind != KindDEX && entry.Kind != KindResources {
			continue
		}
		zipEntry := &a.ZIP.Entries[index]
		if spent >= limits.TotalDigestBytes {
			entry.Limitations = append(entry.Limitations,
				fmt.Sprintf("content digest skipped: %d-byte aggregate limit reached",
					limits.TotalDigestBytes))
			a.note("content digest limit %d reached", limits.TotalDigestBytes)
			continue
		}
		if zipEntry.UncompressedSizeKnown && zipEntry.UncompressedSize > uint64(limits.DigestBytes) {
			entry.Limitations = append(entry.Limitations,
				fmt.Sprintf("content digest skipped: declared size exceeds %d bytes",
					limits.DigestBytes))
			a.note("content digest is unavailable for %q", zipEntry.Name)
			continue
		}
		data, err := a.ZIP.EntryData(index)
		if err != nil {
			entry.Limitations = append(entry.Limitations,
				"content digest unavailable: "+reason(err))
			a.note("content digest is unavailable for %q", zipEntry.Name)
			continue
		}
		spent += int64(len(data))
		sum := sha256.Sum256(data)
		entry.Digest = hex.EncodeToString(sum[:])
		entry.DigestAvailable = true
	}
}

// reason returns the short sentinel text of an archive error.
func reason(err error) string {
	switch {
	case errors.Is(err, archive.ErrUnavailable):
		return "content is unavailable"
	case errors.Is(err, archive.ErrLimit):
		return "content exceeds the limit"
	case errors.Is(err, archive.ErrTruncated):
		return "declared range is outside the artifact"
	case errors.Is(err, archive.ErrRead):
		return "read failed"
	default:
		return "content could not be decoded"
	}
}

// classify assigns the Android role of one ZIP entry.
func classify(entry *archive.Entry) Entry {
	if !entry.NameAvailable {
		return Entry{Kind: KindOther}
	}
	out := Entry{Kind: kindOf(entry.Name)}
	if out.Kind == KindNativeLibrary {
		out.ABI = abiOf(entry.Name)
	}
	return out
}

func kindOf(name string) Kind {
	switch name {
	case "AndroidManifest.xml":
		return KindManifest
	case "resources.arsc":
		return KindResources
	}
	if isDEXName(name) {
		return KindDEX
	}
	switch {
	case hasPrefixSegment(name, "lib/") && hasSuffix(name, ".so"):
		return KindNativeLibrary
	case hasPrefixSegment(name, "res/"):
		return KindResource
	case hasPrefixSegment(name, "assets/"):
		return KindAsset
	case hasPrefixSegment(name, "META-INF/") && isSignatureFile(name):
		return KindSignature
	default:
		return KindOther
	}
}

// isDEXName reports a root classes*.dex name.
func isDEXName(name string) bool {
	if len(name) < len("classes.dex") || !hasSuffix(name, ".dex") {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] == '/' {
			return false
		}
	}
	return len(name) >= len("classes") && name[:len("classes")] == "classes"
}

// isSignatureFile reports a META-INF scheme v1 signature block file such as
// CERT.RSA or CERT.SF.
func isSignatureFile(name string) bool {
	base := name
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '/' {
			base = name[i+1:]
			break
		}
	}
	for _, suffix := range []string{".SF", ".RSA", ".DSA", ".EC"} {
		if len(base) > len(suffix) && hasSuffixFold(base, suffix) {
			return true
		}
	}
	return false
}

func hasPrefixSegment(name, prefix string) bool {
	return len(name) >= len(prefix) && name[:len(prefix)] == prefix
}

func hasSuffix(name, suffix string) bool {
	return len(name) >= len(suffix) && name[len(name)-len(suffix):] == suffix
}

func hasSuffixFold(name, suffix string) bool {
	offset := len(name) - len(suffix)
	for i := 0; i < len(suffix); i++ {
		got := name[offset+i]
		want := suffix[i]
		if got >= 'a' && got <= 'z' {
			got -= 'a' - 'A'
		}
		if got != want {
			return false
		}
	}
	return true
}

// abiOf extracts the ABI segment of a lib/<abi>/*.so name.
func abiOf(name string) string {
	if !hasPrefixSegment(name, "lib/") {
		return ""
	}
	rest := name[len("lib/"):]
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' {
			return rest[:i]
		}
	}
	return ""
}

// centralDirectoryOffset locates the ZIP central directory, following the
// ZIP64 end record when the classic fields are saturated.
func centralDirectoryOffset(r io.ReaderAt, size int64) (int64, bool) {
	record, ok := findEndRecord(r, size)
	if !ok {
		return 0, false
	}
	if record.cdOffset != 0xFFFFFFFF && record.cdSize != 0xFFFFFFFF {
		return record.cdOffset, true
	}
	return zip64CentralDirectoryOffset(r, size, record)
}

// endRecord is the classic ZIP end record.
type endRecord struct {
	offset   int64
	cdOffset int64
	cdSize   int64
}

// findEndRecord scans the trailing comment window for the end record.
func findEndRecord(r io.ReaderAt, size int64) (endRecord, bool) {
	const (
		recordBytes  = 22
		commentBytes = 0xFFFF
	)
	window := int64(recordBytes + commentBytes)
	if size < recordBytes {
		return endRecord{}, false
	}
	if window > size {
		window = size
	}
	tail, err := readAt(r, size-window, int(window), size)
	if err != nil {
		return endRecord{}, false
	}
	for i := len(tail) - recordBytes; i >= 0; i-- {
		if tail[i] != 'P' || tail[i+1] != 'K' || tail[i+2] != 0x05 || tail[i+3] != 0x06 {
			continue
		}
		comment := int64(binary.LittleEndian.Uint16(tail[i+20:]))
		if int64(i)+recordBytes+comment != int64(len(tail)) {
			continue
		}
		return endRecord{
			offset:   size - window + int64(i),
			cdOffset: int64(binary.LittleEndian.Uint32(tail[i+16:])),
			cdSize:   int64(binary.LittleEndian.Uint32(tail[i+12:])),
		}, true
	}
	return endRecord{}, false
}

// zip64CentralDirectoryOffset follows the ZIP64 locator and end record.
func zip64CentralDirectoryOffset(r io.ReaderAt, size int64, record endRecord) (int64, bool) {
	const (
		locatorBytes = 20
		endBytes     = 56
	)
	if record.offset < locatorBytes+endBytes {
		return 0, false
	}
	locator, err := readAt(r, record.offset-locatorBytes, locatorBytes, size)
	if err != nil {
		return 0, false
	}
	if string(locator[:4]) != "PK\x06\x07" {
		return 0, false
	}
	offset64 := binary.LittleEndian.Uint64(locator[8:])
	if offset64 > uint64(size) || offset64 > uint64(size-endBytes) {
		return 0, false
	}
	end, err := readAt(r, int64(offset64), endBytes, size)
	if err != nil {
		return 0, false
	}
	if string(end[:4]) != "PK\x06\x06" {
		return 0, false
	}
	cdSize := binary.LittleEndian.Uint64(end[40:])
	cdOffset := binary.LittleEndian.Uint64(end[48:])
	if cdOffset > uint64(size) || cdSize > uint64(size)-cdOffset {
		return 0, false
	}
	return int64(cdOffset), true
}

// readAt reads exactly n bytes, bounded by the artifact size.
func readAt(r io.ReaderAt, offset int64, n int, size int64) ([]byte, error) {
	if offset < 0 || n < 0 || offset > size || int64(n) > size-offset {
		return nil, fmt.Errorf("%w: %d bytes at offset %d extend beyond artifact size %d",
			ErrTruncated, n, offset, size)
	}
	buf := make([]byte, n)
	if n == 0 {
		return buf, nil
	}
	read, err := r.ReadAt(buf, offset)
	if read == n {
		return buf, nil
	}
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("%w: %w", ErrRead, err)
	}
	return nil, fmt.Errorf("%w: short read of %d bytes at offset %d", ErrRead, n-read, offset)
}
