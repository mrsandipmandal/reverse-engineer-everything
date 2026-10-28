package asar

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// headerFixedBytes is the size of the four leading pickle integers.
const headerFixedBytes = 16

// header is the validated ASAR header.
type header struct {
	headerBytes int64
	jsonBytes   int64
	dataOffset  int64
	root        json.RawMessage
}

// rawNode is one parsed directory node. Fields that can be absent are kept as
// raw messages so an absent value is distinct from a zero value.
type rawNode struct {
	Files      map[string]json.RawMessage `json:"files"`
	Size       json.RawMessage            `json:"size"`
	Offset     json.RawMessage            `json:"offset"`
	Link       *string                    `json:"link"`
	Executable bool                       `json:"executable"`
	Unpacked   bool                       `json:"unpacked"`
	Integrity  json.RawMessage            `json:"integrity"`
}

// walkState carries the stop condition across siblings.
type walkState struct {
	stopped bool
}

// readHeader validates the Pickle sizes and loads the JSON directory.
func readHeader(r io.ReaderAt, size int64, limits Limits) (header, error) {
	fixed := make([]byte, headerFixedBytes)
	if err := readAt(r, 0, fixed, size); err != nil {
		return header{}, err
	}
	order := binary.LittleEndian
	if order.Uint32(fixed[0:]) != 4 {
		return header{}, fmt.Errorf("%w: first pickle size is %d, want 4", ErrInvalid, order.Uint32(fixed[0:]))
	}
	headerBytes := int64(order.Uint32(fixed[4:]))
	jsonBytes := int64(order.Uint32(fixed[8:]))
	jsonLen := int64(order.Uint32(fixed[12:]))

	if headerBytes < 8 {
		return header{}, fmt.Errorf("%w: header size %d is too small", ErrInvalid, headerBytes)
	}
	if headerBytes > limits.HeaderBytes {
		return header{}, fmt.Errorf("%w: header size %d exceeds limit %d",
			ErrLimit, headerBytes, limits.HeaderBytes)
	}
	if headerBytes > size-8 {
		return header{}, fmt.Errorf("%w: header size %d extends beyond artifact size %d",
			ErrTruncated, headerBytes, size)
	}
	if jsonLen > jsonBytes || jsonBytes > headerBytes-8 {
		return header{}, fmt.Errorf("%w: JSON sizes (%d, %d) contradict header size %d",
			ErrInvalid, jsonLen, jsonBytes, headerBytes)
	}
	if jsonLen == 0 {
		return header{}, fmt.Errorf("%w: JSON directory is empty", ErrInvalid)
	}
	rootBytes := make([]byte, jsonLen)
	if err := readAt(r, headerFixedBytes, rootBytes, size); err != nil {
		return header{}, err
	}
	trimmed := bytes.TrimSpace(rootBytes)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return header{}, fmt.Errorf("%w: JSON directory is not an object", ErrInvalid)
	}
	return header{
		headerBytes: headerBytes,
		jsonBytes:   jsonBytes,
		dataOffset:  8 + headerBytes,
		root:        rootBytes,
	}, nil
}

// walk inventories one node and, for a directory, its sorted children.
func (a *Archive) walk(raw json.RawMessage, path string, depth int, root bool, state *walkState) error {
	var node rawNode
	if err := json.Unmarshal(raw, &node); err != nil {
		return fmt.Errorf("%w: node %q is not a JSON object: %w", ErrInvalid, displayPath(path), err)
	}
	if root && node.Files == nil {
		return fmt.Errorf("%w: header has no files object", ErrInvalid)
	}
	if node.Files == nil {
		if len(a.Entries) >= a.limits.Entries {
			a.stopAtEntryLimit(path, state)
			return nil
		}
		entry, err := a.buildEntry(node, path)
		if err != nil {
			return err
		}
		a.Entries = append(a.Entries, entry)
		return nil
	}
	if len(node.Size) > 0 || node.Link != nil {
		return fmt.Errorf("%w: node %q declares both files and non-directory fields",
			ErrInvalid, displayPath(path))
	}
	if !root {
		if len(a.Entries) >= a.limits.Entries {
			a.stopAtEntryLimit(path, state)
			return nil
		}
		name, available, unsafe, stored := decodePath(path, a.limits.PathBytes)
		a.Entries = append(a.Entries, Entry{
			Index:         len(a.Entries),
			Path:          name,
			PathAvailable: available,
			PathBytes:     stored,
			PathUnsafe:    unsafe,
			Type:          EntryDirectory,
		})
	}
	if depth+1 > a.limits.Depth {
		a.Truncated = true
		a.note("directory depth limit %d reached at %q", a.limits.Depth, displayPath(path))
		state.stopped = true
		return nil
	}

	keys := make([]string, 0, len(node.Files))
	for key := range node.Files {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if state.stopped {
			break
		}
		if err := a.walk(node.Files[key], joinPath(path, key), depth+1, false, state); err != nil {
			return err
		}
	}
	return nil
}

// stopAtEntryLimit records that the entry limit stopped the walk.
func (a *Archive) stopAtEntryLimit(path string, state *walkState) {
	a.Truncated = true
	a.note("entry limit %d reached at %q", a.limits.Entries, displayPath(path))
	state.stopped = true
}

// buildEntry converts one leaf node into an inventory entry.
func (a *Archive) buildEntry(node rawNode, path string) (Entry, error) {
	name, available, unsafe, stored := decodePath(path, a.limits.PathBytes)
	entry := Entry{
		Index:         len(a.Entries),
		Path:          name,
		PathAvailable: available,
		PathBytes:     stored,
		PathUnsafe:    unsafe,
		Executable:    node.Executable,
		Unpacked:      node.Unpacked,
	}
	switch {
	case node.Link != nil:
		entry.Type = EntryLink
		entry.LinkTarget, entry.LinkTargetAvailable, _ = decodeText([]byte(*node.Link), a.limits.PathBytes)
		if len(node.Size) > 0 || len(node.Offset) > 0 {
			entry.Limitations = append(entry.Limitations, "link also declares file data")
		}
	case len(node.Size) > 0:
		entry.Type = EntryFile
	default:
		entry.Type = EntryOther
		entry.Limitations = append(entry.Limitations, "node declares no type")
	}

	if entry.Type == EntryFile {
		size, sizeOK, err := parseUintField(node.Size)
		if err != nil {
			return Entry{}, fmt.Errorf("%w: file %q has an invalid size", ErrInvalid, displayPath(path))
		}
		offset, offsetOK, err := parseUintField(node.Offset)
		if err != nil {
			return Entry{}, fmt.Errorf("%w: file %q has an invalid offset", ErrInvalid, displayPath(path))
		}
		entry.Size, entry.SizeKnown = size, sizeOK
		entry.Offset, entry.OffsetKnown = offset, offsetOK
		switch {
		case !sizeOK:
			entry.Limitations = append(entry.Limitations, "file size is missing")
		case !offsetOK:
			entry.Limitations = append(entry.Limitations, "file offset is missing")
		case entry.Unpacked:
			entry.Limitations = append(entry.Limitations, "file content is unpacked")
		default:
			a.locate(&entry)
		}
	}

	if len(node.Integrity) > 0 && string(node.Integrity) != "null" {
		integrity, malformed := parseIntegrity(node.Integrity)
		if malformed {
			entry.Limitations = append(entry.Limitations, "integrity metadata is malformed")
		}
		entry.Integrity = &integrity
	}
	return entry, nil
}

// locate resolves an entry's declared range against the artifact.
func (a *Archive) locate(entry *Entry) {
	// Both bounds are checked before the conversion: the artifact size is
	// never negative, and the explicit MaxInt64 comparison keeps the
	// conversion provably in range.
	if a.size < 0 || entry.Offset > uint64(a.size) || entry.Offset > math.MaxInt64 {
		entry.RangeOutside = true
		entry.Limitations = append(entry.Limitations, "content range is outside the artifact")
		return
	}
	absolute := a.DataOffset + int64(entry.Offset)
	if absolute > a.size || entry.Size > uint64(a.size-absolute) {
		entry.RangeOutside = true
		entry.Limitations = append(entry.Limitations, "content range is outside the artifact")
		return
	}
	entry.DataOffset = absolute
	entry.DataKnown = true
}

// parseUintField decodes a non-negative integer stored as a JSON number or a
// decimal string. It reports whether the field was present.
func parseUintField(raw json.RawMessage) (uint64, bool, error) {
	text := strings.TrimSpace(string(raw))
	if text == "" || text == "null" {
		return 0, false, nil
	}
	if text[0] == '"' {
		var decoded string
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return 0, false, err
		}
		text = decoded
	}
	if text == "" || len(text) > 20 {
		return 0, false, fmt.Errorf("not a valid integer")
	}
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return 0, false, fmt.Errorf("not a decimal integer")
		}
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, false, err
	}
	return value, true, nil
}

// rawIntegrity is the declared integrity object.
type rawIntegrity struct {
	Algorithm string            `json:"algorithm"`
	Hash      string            `json:"hash"`
	Blocks    []json.RawMessage `json:"blocks"`
}

// parseIntegrity decodes integrity metadata and reports malformed input.
func parseIntegrity(raw json.RawMessage) (Integrity, bool) {
	var decoded rawIntegrity
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return Integrity{}, true
	}
	out := Integrity{
		Algorithm:          decoded.Algorithm,
		AlgorithmAvailable: decoded.Algorithm != "",
		Hash:               strings.ToLower(decoded.Hash),
		HashAvailable:      decoded.Hash != "",
		BlockCount:         len(decoded.Blocks),
	}
	return out, false
}

// decodePath decodes one archive path and checks it against the path rules. The
// path is never repaired: an empty, over-limit, invalid, or NUL-bearing path is
// reported as unavailable with the raw bytes preserved up to the limit.
func decodePath(path string, limit int) (decoded string, available bool, unsafe string, stored []byte) {
	raw := []byte(path)
	stored = append([]byte(nil), raw...)
	if len(stored) > limit {
		stored = stored[:limit]
	}
	switch {
	case len(raw) == 0:
		return "", false, "empty name", stored
	case len(raw) > limit:
		return "", false, fmt.Sprintf("path exceeds %d bytes", limit), stored
	case !utf8.Valid(raw):
		return "", false, "path is not valid UTF-8", stored
	}
	text := string(raw)
	if strings.IndexByte(text, 0) >= 0 {
		return "", false, "path contains a NUL byte", stored
	}
	if reason := unsafePath(text); reason != "" {
		return text, true, reason, stored
	}
	return text, true, "", stored
}

// decodeText decodes a metadata field such as a link target. It is not an
// archive path, so only encoding and NUL bytes are checked.
func decodeText(raw []byte, limit int) (string, bool, []byte) {
	stored := append([]byte(nil), raw...)
	if len(stored) > limit {
		stored = stored[:limit]
	}
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) || strings.IndexByte(string(raw), 0) >= 0 {
		return "", false, stored
	}
	return string(raw), true, stored
}

// unsafePath reports why a decoded path cannot be used as a relative archive
// path, and returns an empty string when the path stays inside the root.
func unsafePath(name string) string {
	if name == "" {
		return "empty name"
	}
	if name[0] == '/' {
		return "absolute path"
	}
	if hasDrivePrefix(name) {
		return "drive-letter path"
	}
	if strings.IndexByte(name, '\\') >= 0 {
		return "backslash separator"
	}
	trimmed := strings.TrimSuffix(name, "/")
	if trimmed == "" || trimmed == "." {
		return "name resolves to the archive root"
	}
	for _, segment := range strings.Split(trimmed, "/") {
		if segment == ".." {
			return "parent-directory segment"
		}
	}
	return ""
}

// hasDrivePrefix reports a Windows drive-letter prefix such as C: or c:.
func hasDrivePrefix(name string) bool {
	if len(name) < 2 || name[1] != ':' {
		return false
	}
	first := name[0]
	return (first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z')
}

// joinPath appends a directory key to its parent path.
func joinPath(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + "/" + name
}

// displayPath quotes a path for an error or limitation message.
func displayPath(path string) string {
	if path == "" {
		return "<root>"
	}
	return path
}
