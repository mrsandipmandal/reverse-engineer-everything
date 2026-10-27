package pe

import (
	"encoding/binary"
	"fmt"
)

const (
	certificateHeaderSize = 8
	certificateAlignment  = 8
)

// Certificate is one WIN_CERTIFICATE header from the attribute certificate
// table.
//
// The certificate blob is not decoded, verified, or trusted. Revision and Type
// are the raw header values.
type Certificate struct {
	// Index is the position in the certificate table.
	Index int
	// Offset is the file offset of the WIN_CERTIFICATE header.
	Offset uint64
	// Length is dwLength, including the eight header bytes and any padding
	// declared inside the record.
	Length uint32
	// Revision and Type are wRevision and wCertificateType.
	Revision uint16
	Type     uint16
	// DataOffset and DataSize describe the certificate blob that follows the
	// header.
	DataOffset uint64
	DataSize   uint32
}

// CertificateTable is the decoded attribute certificate table.
type CertificateTable struct {
	// Offset is the security directory file offset. The security directory
	// stores a file offset, not an RVA.
	Offset uint64
	// Size is the declared security directory size.
	Size uint32

	Certificates []Certificate

	// Truncated reports that more certificate records exist than were loaded.
	Truncated bool
	// Limitations states, in deterministic order, why the table is
	// incomplete.
	Limitations []string
}

func (t *CertificateTable) limit(format string, args ...any) {
	t.Limitations = append(t.Limitations, fmt.Sprintf(format, args...))
}

// Certificates reads the attribute certificate table.
//
// An absent security directory returns ErrNotFound. An inconsistent offset and
// size pair returns ErrInvalid. A table outside the artifact returns
// ErrUnavailable, and a table above the configured size returns ErrLimit. A
// record that contradicts the table bounds returns ErrInvalid. A count limit
// yields a partial table with Truncated set.
//
// The table describes signature records; it makes no claim about signature
// validity, chain, or trust. Certificate bytes are read only by
// CertificateData.
func (f *File) Certificates() (*CertificateTable, error) {
	directory, err := f.metadataDirectory(4, "security")
	if err != nil {
		return nil, err
	}
	start := uint64(directory.VirtualAddress)
	size := uint64(directory.Size)
	if size > uint64(f.limits.CertificateBytes) {
		return nil, fmt.Errorf("%w: certificate table size %d exceeds limit %d",
			ErrLimit, size, f.limits.CertificateBytes)
	}
	if start > uint64(f.size) || size > uint64(f.size)-start {
		return nil, fmt.Errorf("%w: certificate table range is outside the artifact", ErrUnavailable)
	}

	table := &CertificateTable{Offset: start, Size: directory.Size}
	position := uint64(0)
	for position+certificateHeaderSize <= size {
		header, err := f.readFileRange(start+position, certificateHeaderSize)
		if err != nil {
			return nil, err
		}
		length := binary.LittleEndian.Uint32(header[0:])
		if length < certificateHeaderSize {
			return nil, fmt.Errorf("%w: certificate %d length %d",
				ErrInvalid, len(table.Certificates), length)
		}
		if uint64(length) > size-position {
			return nil, fmt.Errorf("%w: certificate %d length %d exceeds the %d-byte table",
				ErrInvalid, len(table.Certificates), length, size)
		}
		if len(table.Certificates) >= f.limits.Certificates {
			if !allZero(header) {
				table.Truncated = true
				table.limit("certificate count exceeds limit %d", f.limits.Certificates)
				position = size
			}
			break
		}
		table.Certificates = append(table.Certificates, Certificate{
			Index:      len(table.Certificates),
			Offset:     start + position,
			Length:     length,
			Revision:   binary.LittleEndian.Uint16(header[4:]),
			Type:       binary.LittleEndian.Uint16(header[6:]),
			DataOffset: start + position + certificateHeaderSize,
			DataSize:   length - certificateHeaderSize,
		})
		advance := (uint64(length) + certificateAlignment - 1) &^ (certificateAlignment - 1)
		if advance > size-position {
			// The last record is not padded inside the declared table.
			position = size
			continue
		}
		position += advance
	}

	if position < size {
		trailing, err := f.readFileRange(start+position, size-position)
		if err != nil {
			return nil, err
		}
		if !allZero(trailing) {
			table.Truncated = true
			table.limit("%d trailing bytes after the last certificate", size-position)
		}
	}
	return table, nil
}

// CertificateData returns a copy of the certificate blob at index.
//
// The blob is bounded by the certificate table size limit and is not decoded or
// verified.
func (f *File) CertificateData(index int) ([]byte, error) {
	table, err := f.Certificates()
	if err != nil {
		return nil, err
	}
	if index < 0 || index >= len(table.Certificates) {
		return nil, fmt.Errorf("%w: certificate %d", ErrOutOfRange, index)
	}
	certificate := table.Certificates[index]
	return f.readFileRange(certificate.DataOffset, uint64(certificate.DataSize))
}

func allZero(raw []byte) bool {
	for _, value := range raw {
		if value != 0 {
			return false
		}
	}
	return true
}
