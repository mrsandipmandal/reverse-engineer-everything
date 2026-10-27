package pe_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	repe "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/pe"
)

func TestCertificates(t *testing.T) {
	t.Parallel()

	for _, magic := range []uint16{repe.MagicPE32, repe.MagicPE32P} {
		magic := magic
		t.Run(magicName(t, magic), func(t *testing.T) {
			t.Parallel()

			image := newMetadataImage(magic)
			data := image.build(t)
			first := certificateRecord(0x0200, 0x0002, []byte("signed-data"))
			second := certificateRecord(0x0100, 0x0001, []byte("x509"))
			data, offset, size := appendCertificateTable(data, first, second)
			setSecurityDirectory(data, magic, offset, size)

			file := parseImageData(t, data)
			table, err := file.Certificates()
			if err != nil {
				t.Fatalf("Certificates() error = %v", err)
			}
			if table.Truncated || len(table.Limitations) != 0 {
				t.Fatalf("truncated = %t, limitations = %v", table.Truncated, table.Limitations)
			}
			if len(table.Certificates) != 2 {
				t.Fatalf("certificate count = %d", len(table.Certificates))
			}
			if table.Offset != offset || table.Size != size {
				t.Fatalf("table = %#x/%d, want %#x/%d", table.Offset, table.Size, offset, size)
			}

			firstCertificate := table.Certificates[0]
			if firstCertificate.Index != 0 || firstCertificate.Revision != 0x0200 ||
				firstCertificate.Type != 0x0002 || firstCertificate.Length != 8+uint32(len("signed-data")) {
				t.Fatalf("certificate 0 = %+v", firstCertificate)
			}
			secondCertificate := table.Certificates[1]
			if secondCertificate.Index != 1 || secondCertificate.Revision != 0x0100 ||
				secondCertificate.Type != 0x0001 {
				t.Fatalf("certificate 1 = %+v", secondCertificate)
			}

			blob, err := file.CertificateData(0)
			if err != nil {
				t.Fatalf("CertificateData(0) error = %v", err)
			}
			if string(blob) != "signed-data" || len(blob) != int(firstCertificate.DataSize) {
				t.Fatalf("blob = %q", blob)
			}
			if _, err := file.CertificateData(2); !errors.Is(err, repe.ErrOutOfRange) {
				t.Fatalf("CertificateData(2) error = %v, want ErrOutOfRange", err)
			}
		})
	}
}

func TestCertificatesErrors(t *testing.T) {
	t.Parallel()

	t.Run("absent", func(t *testing.T) {
		t.Parallel()

		file := parseImage(t, newMetadataImage(repe.MagicPE32))
		if _, err := file.Certificates(); !errors.Is(err, repe.ErrNotFound) {
			t.Fatalf("Certificates() error = %v, want ErrNotFound", err)
		}
	})

	t.Run("contradictory directory", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.directories[4] = [2]uint32{0, 16}
		file := parseImage(t, image)
		if _, err := file.Certificates(); !errors.Is(err, repe.ErrInvalid) {
			t.Fatalf("Certificates() error = %v, want ErrInvalid", err)
		}
	})

	t.Run("outside artifact", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.directories[4] = [2]uint32{0x9000, 16}
		file := parseImage(t, image)
		if _, err := file.Certificates(); !errors.Is(err, repe.ErrUnavailable) {
			t.Fatalf("Certificates() error = %v, want ErrUnavailable", err)
		}
	})

	t.Run("table size limit", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		limits := repe.DefaultLimits()
		limits.CertificateBytes = 8
		data := image.build(t)
		data, offset, size := appendCertificateTable(data, certificateRecord(0x0200, 0x0002, []byte("payload")))
		setSecurityDirectory(data, repe.MagicPE32, offset, size)
		file, err := repe.ParseWithLimits(bytes.NewReader(data), int64(len(data)), limits)
		if err != nil {
			t.Fatalf("ParseWithLimits() error = %v", err)
		}
		if _, err := file.Certificates(); !errors.Is(err, repe.ErrLimit) {
			t.Fatalf("Certificates() error = %v, want ErrLimit", err)
		}
	})

	t.Run("short record", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		data := image.build(t)
		record := make([]byte, 8)
		binary.LittleEndian.PutUint32(record, 4)
		data, offset, size := appendCertificateTable(data, record)
		setSecurityDirectory(data, repe.MagicPE32, offset, size)
		file := parseImageData(t, data)
		if _, err := file.Certificates(); !errors.Is(err, repe.ErrInvalid) {
			t.Fatalf("Certificates() error = %v, want ErrInvalid", err)
		}
	})

	t.Run("record beyond table", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		data := image.build(t)
		data, offset, _ := appendCertificateTable(data, certificateRecord(0x0200, 0x0002, []byte("payload")))
		setSecurityDirectory(data, repe.MagicPE32, offset, 8)
		file := parseImageData(t, data)
		if _, err := file.Certificates(); !errors.Is(err, repe.ErrInvalid) {
			t.Fatalf("Certificates() error = %v, want ErrInvalid", err)
		}
	})

	t.Run("count limit", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		limits := repe.DefaultLimits()
		limits.Certificates = 1
		data := image.build(t)
		data, offset, size := appendCertificateTable(data,
			certificateRecord(0x0200, 0x0002, []byte("one")),
			certificateRecord(0x0200, 0x0002, []byte("two")),
		)
		setSecurityDirectory(data, repe.MagicPE32, offset, size)
		file, err := repe.ParseWithLimits(bytes.NewReader(data), int64(len(data)), limits)
		if err != nil {
			t.Fatalf("ParseWithLimits() error = %v", err)
		}
		table, err := file.Certificates()
		if err != nil {
			t.Fatalf("Certificates() error = %v", err)
		}
		if len(table.Certificates) != 1 || !table.Truncated {
			t.Fatalf("certificates = %d, truncated = %t", len(table.Certificates), table.Truncated)
		}
		if !hasLimitation(table.Limitations, "certificate count exceeds limit 1") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("unpadded last record", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		data := image.build(t)
		data, offset, _ := appendCertificateTable(data, certificateRecord(0x0200, 0x0002, []byte("abcd")))
		setSecurityDirectory(data, repe.MagicPE32, offset, 12)

		file := parseImageData(t, data)
		table, err := file.Certificates()
		if err != nil {
			t.Fatalf("Certificates() error = %v", err)
		}
		if len(table.Certificates) != 1 || table.Truncated || len(table.Limitations) != 0 {
			t.Fatalf("table = %+v", table)
		}
	})

	t.Run("zero padding", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		data := image.build(t)
		data, offset, size := appendCertificateTable(data, certificateRecord(0x0200, 0x0002, []byte("one")))
		data = append(data, 0, 0, 0, 0)
		size += 4
		setSecurityDirectory(data, repe.MagicPE32, offset, size)

		file := parseImageData(t, data)
		table, err := file.Certificates()
		if err != nil {
			t.Fatalf("Certificates() error = %v", err)
		}
		if table.Truncated || len(table.Limitations) != 0 {
			t.Fatalf("truncated = %t, limitations = %v", table.Truncated, table.Limitations)
		}
	})

	t.Run("trailing bytes", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		data := image.build(t)
		data, offset, size := appendCertificateTable(data, certificateRecord(0x0200, 0x0002, []byte("one")))
		data = append(data, 1, 2, 3, 4)
		size += 4
		setSecurityDirectory(data, repe.MagicPE32, offset, size)

		file := parseImageData(t, data)
		table, err := file.Certificates()
		if err != nil {
			t.Fatalf("Certificates() error = %v", err)
		}
		if !table.Truncated {
			t.Fatal("trailing bytes did not set Truncated")
		}
		if !hasLimitation(table.Limitations, "4 trailing bytes after the last certificate") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})
}

func TestCertificatesReaderFailure(t *testing.T) {
	t.Parallel()

	image := newMetadataImage(repe.MagicPE32)
	data := image.build(t)
	data, offset, size := appendCertificateTable(data, certificateRecord(0x0200, 0x0002, []byte("payload")))
	setSecurityDirectory(data, repe.MagicPE32, offset, size)

	reader := failingReader{data: data, off: int64(offset)}
	file, err := repe.Parse(reader, int64(len(data)))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if _, err := file.Certificates(); !errors.Is(err, repe.ErrRead) {
		t.Fatalf("Certificates() error = %v, want ErrRead", err)
	}
}
