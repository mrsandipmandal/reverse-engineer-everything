package elf

import (
	"bytes"
	"testing"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
	reeelf "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/elf"
)

// FuzzObserve checks that no artifact can make the adapter panic or return a
// record that the evidence encoder rejects.
func FuzzObserve(f *testing.F) {
	fixture := newELFFixture(f, fixtureOptions{})
	f.Add(fixture.data)
	f.Add([]byte("\x7fELF"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		record, err := Observe(bytes.NewReader(data), int64(len(data)), Options{
			ProviderVersion: "fuzz",
			Limits: reeelf.Limits{
				SectionHeaders:     16,
				ProgramHeaders:     16,
				SectionDataBytes:   4 << 10,
				SegmentDataBytes:   4 << 10,
				StringTableBytes:   1 << 10,
				NameBytes:          64,
				Notes:              8,
				NoteDataBytes:      4 << 10,
				BuildIDBytes:       64,
				CommentStrings:     8,
				SymbolTables:       4,
				Symbols:            64,
				SymbolStringBytes:  1 << 10,
				RelocationSections: 4,
				Relocations:        64,
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
