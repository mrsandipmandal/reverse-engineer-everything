package archive

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// decodeEntryName decodes one stored name field and checks it against the path
// rules. The returned bytes are a copy capped at limit, so the caller may keep
// them after the artifact buffer is reused.
//
// The name is never repaired: a name that is empty, longer than the limit, not
// valid UTF-8, or contains a NUL byte is reported as unavailable. CP437 names
// are not transcoded.
func decodeEntryName(raw []byte, limit int) (name string, available bool, unsafe string, stored []byte) {
	stored = append([]byte(nil), raw...)
	if len(stored) > limit {
		stored = stored[:limit]
	}
	switch {
	case len(raw) == 0:
		return "", false, "empty name", stored
	case len(raw) > limit:
		return "", false, fmt.Sprintf("name exceeds %d bytes", limit), stored
	case !utf8.Valid(raw):
		return "", false, "name is not valid UTF-8", stored
	}
	text := string(raw)
	if strings.IndexByte(text, 0) >= 0 {
		return "", false, "name contains a NUL byte", stored
	}
	if reason := unsafePath(text); reason != "" {
		return text, true, reason, stored
	}
	return text, true, "", stored
}

// decodeText decodes a metadata field such as a gzip name or comment or a tar
// link target. It is not an archive path, so only encoding and NUL bytes are
// checked.
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

// unsafePath reports why a decoded name cannot be used as a relative archive
// path, and returns an empty string when the name stays inside the root.
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
