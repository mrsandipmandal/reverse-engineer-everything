package pe

import (
	"bytes"
	"testing"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	repe "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/pe"
)

// FuzzObserve checks that no artifact can make the adapter panic or return a
// record that the evidence encoder rejects.
func FuzzObserve(f *testing.F) {
	fixture := newPEFixture(f, fixtureOptions{certificates: 2, overlayBytes: 4})
	f.Add(fixture.data)
	f.Add([]byte("MZ"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		record, err := Observe(bytes.NewReader(data), int64(len(data)), Options{
			ProviderVersion: "fuzz",
			Limits: repe.Limits{
				ArtifactBytes:       1 << 20,
				Sections:            16,
				DataDirectories:     16,
				SectionDataBytes:    4 << 10,
				ImportModules:       8,
				ImportThunks:        64,
				Exports:             64,
				StringBytes:         256,
				ImportStringBytes:   1 << 10,
				ExportStringBytes:   1 << 10,
				ResourceDepth:       4,
				ResourceEntries:     64,
				ResourceStringBytes: 1 << 10,
				Certificates:        8,
				CertificateBytes:    4 << 10,
			},
			PayloadBytes: MinPayloadBytes,
			ContentBytes: 4 << 10,
		})
		if err != nil {
			return
		}
		if _, err := evidence.Encode(record); err != nil {
			t.Fatalf("Observe returned an unencodable record: %v", err)
		}
	})
}
