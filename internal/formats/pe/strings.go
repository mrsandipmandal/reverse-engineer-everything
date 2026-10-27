package pe

import (
	"bytes"
	"errors"
	"fmt"
	"unicode/utf8"
)

// fileRange resolves an RVA to a file offset and the number of contiguous
// file-backed bytes that follow it inside the same headers region or section.
func (f *File) fileRange(rva uint32) (uint64, int64, error) {
	if uint64(rva) < uint64(f.Header.Optional.SizeOfHeaders) {
		offset := uint64(rva)
		if offset >= uint64(f.size) {
			return 0, 0, fmt.Errorf("%w: RVA %#x is beyond the artifact", ErrUnavailable, rva)
		}
		maximum := uint64(f.Header.Optional.SizeOfHeaders) - offset
		if available := uint64(f.size) - offset; available < maximum {
			maximum = available
		}
		return offset, int64(maximum), nil
	}

	mapping := f.MapRVA(rva)
	if mapping.SectionIndex < 0 || !mapping.FileBacked {
		return 0, 0, fmt.Errorf("%w: RVA %#x has no file bytes", ErrUnavailable, rva)
	}
	section := f.Sections[mapping.SectionIndex]
	delta := uint64(rva) - uint64(section.VirtualAddress)
	maximum := uint64(section.SizeOfRawData) - delta
	if mapping.Offset >= uint64(f.size) {
		return 0, 0, fmt.Errorf("%w: RVA %#x maps beyond the artifact", ErrUnavailable, rva)
	}
	if available := uint64(f.size) - mapping.Offset; available < maximum {
		maximum = available
	}
	return mapping.Offset, int64(maximum), nil
}

// readRVA returns length file-backed bytes at rva. The range must lie within
// one headers region or section.
func (f *File) readRVA(rva uint32, length int) ([]byte, error) {
	if length < 0 {
		return nil, fmt.Errorf("%w: negative read length %d", ErrInvalid, length)
	}
	offset, maximum, err := f.fileRange(rva)
	if err != nil {
		return nil, err
	}
	if int64(length) > maximum {
		return nil, fmt.Errorf("%w: %d bytes at RVA %#x exceed the %d file-backed bytes",
			ErrUnavailable, length, rva, maximum)
	}
	buf := make([]byte, length)
	if err := readAt(f.reader, int64(offset), buf, f.size); err != nil {
		return nil, err
	}
	return buf, nil
}

// readString reads a NUL-terminated UTF-8 string at rva.
//
// budget is reduced by the bytes read, including the terminator. The read is
// bounded by the section or headers region, the per-string limit, and the
// remaining string budget. Invalid UTF-8 is reported as ErrInvalid rather than
// normalized.
func (f *File) readString(rva uint32, budget *int64) (string, error) {
	if *budget <= 0 {
		return "", fmt.Errorf("%w: string budget is exhausted", ErrLimit)
	}
	offset, maximum, err := f.fileRange(rva)
	if err != nil {
		return "", err
	}
	if maximum == 0 {
		return "", fmt.Errorf("%w: no string bytes at RVA %#x", ErrUnavailable, rva)
	}

	limit := int64(f.limits.StringBytes)
	if maximum < limit {
		limit = maximum
	}
	if *budget < limit {
		limit = *budget
	}
	if limit <= 0 {
		return "", fmt.Errorf("%w: string budget is exhausted", ErrLimit)
	}

	buf := make([]byte, 0, 64)
	var read int64
	for read < limit {
		chunk := int64(256)
		if limit-read < chunk {
			chunk = limit - read
		}
		part := make([]byte, chunk)
		if err := readAt(f.reader, int64(offset+uint64(read)), part, f.size); err != nil {
			*budget -= read
			return "", err
		}
		read += chunk
		if nul := bytes.IndexByte(part, 0); nul >= 0 {
			buf = append(buf, part[:nul]...)
			*budget -= int64(len(buf)) + 1
			if !utf8.Valid(buf) {
				return "", fmt.Errorf("%w: string at RVA %#x is not valid UTF-8", ErrInvalid, rva)
			}
			return string(buf), nil
		}
		buf = append(buf, part...)
	}

	*budget -= read
	if limit == maximum {
		return "", fmt.Errorf("%w: string at RVA %#x is not NUL-terminated", ErrUnavailable, rva)
	}
	return "", fmt.Errorf("%w: string at RVA %#x exceeds the %d-byte limit",
		ErrLimit, rva, f.limits.StringBytes)
}

// stringIssue classifies a failed string read for aggregate limitations.
type stringIssue int

const (
	stringOK stringIssue = iota
	stringUnavailable
	stringInvalidUTF8
	stringLimit
)

func classifyStringError(err error) stringIssue {
	switch {
	case err == nil:
		return stringOK
	case errors.Is(err, ErrInvalid):
		return stringInvalidUTF8
	case errors.Is(err, ErrLimit):
		return stringLimit
	default:
		return stringUnavailable
	}
}
