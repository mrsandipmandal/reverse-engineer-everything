package analyze

import (
	"encoding/json"
	"fmt"

	elfprovider "github.com/mrsandipmandal/reverse-engineer-everything/internal/providers/elf"
	peprovider "github.com/mrsandipmandal/reverse-engineer-everything/internal/providers/pe"
)

// countPayload derives the summary counts from a sealed payload.
//
// The extractors decode only the array members they count, so the summary does
// not depend on the full provider payload types and a schema change that keeps
// those arrays costs no code here. Counts are the lengths actually present,
// which may be a prefix of the artifact's tables after payload trimming; the
// record's limitations describe that gap.
func countPayload(format string, payload []byte) (Counts, error) {
	switch format {
	case FormatELF:
		return countELF(payload)
	case FormatPE:
		return countPE(payload)
	default:
		return Counts{}, fmt.Errorf("%w: %q", ErrUnsupportedFormat, format)
	}
}

// elfCountPayload is the counted subset of ree.payload.elf/1.
type elfCountPayload struct {
	Schema   string            `json:"schema"`
	Sections []json.RawMessage `json:"sections"`
	Segments []json.RawMessage `json:"segments"`
	Symbols  []json.RawMessage `json:"symbols"`
}

func countELF(payload []byte) (Counts, error) {
	var raw elfCountPayload
	if err := json.Unmarshal(payload, &raw); err != nil {
		return Counts{}, fmt.Errorf("decode %s payload: %w", elfprovider.PayloadSchema, err)
	}
	if raw.Schema != elfprovider.PayloadSchema {
		return Counts{}, fmt.Errorf("decode %s payload: schema is %q", elfprovider.PayloadSchema, raw.Schema)
	}
	return Counts{
		Sections: len(raw.Sections),
		Segments: len(raw.Segments),
		Symbols:  len(raw.Symbols),
	}, nil
}

// peCountPayload is the counted subset of ree.payload.pe/1.
//
// A directory member is null when the directory is absent or unusable, so a
// nil pointer counts zero. The limitation text, not the count, separates the
// two cases.
type peCountPayload struct {
	Schema       string            `json:"schema"`
	Sections     []json.RawMessage `json:"sections"`
	Imports      *peImportCounts   `json:"imports"`
	Exports      *peExportCounts   `json:"exports"`
	Resources    *peTableCount     `json:"resources"`
	Certificates *peTableCount     `json:"certificates"`
}

type peImportCounts struct {
	Modules []json.RawMessage `json:"modules"`
}

type peExportCounts struct {
	Exports []json.RawMessage `json:"exports"`
}

type peTableCount struct {
	Resources    []json.RawMessage `json:"resources"`
	Certificates []json.RawMessage `json:"certificates"`
}

func countPE(payload []byte) (Counts, error) {
	var raw peCountPayload
	if err := json.Unmarshal(payload, &raw); err != nil {
		return Counts{}, fmt.Errorf("decode %s payload: %w", peprovider.PayloadSchema, err)
	}
	if raw.Schema != peprovider.PayloadSchema {
		return Counts{}, fmt.Errorf("decode %s payload: schema is %q", peprovider.PayloadSchema, raw.Schema)
	}
	counts := Counts{Sections: len(raw.Sections)}
	if raw.Imports != nil {
		counts.Imports = len(raw.Imports.Modules)
	}
	if raw.Exports != nil {
		counts.Exports = len(raw.Exports.Exports)
	}
	if raw.Resources != nil {
		counts.Resources = len(raw.Resources.Resources)
	}
	if raw.Certificates != nil {
		counts.Certificates = len(raw.Certificates.Certificates)
	}
	return counts, nil
}
