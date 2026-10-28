package analyze

import (
	"encoding/json"
	"fmt"

	elfprovider "github.com/mrsandipmandal/reverse-engineer-everything/internal/providers/elf"
	machoprovider "github.com/mrsandipmandal/reverse-engineer-everything/internal/providers/macho"
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
	case FormatMachO:
		return countMachO(payload)
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

// machoCountPayload is the counted subset of ree.payload.macho/1.
//
// One artifact carries one slice per architecture, so every count sums the
// slices. A table member is null when the image does not declare that command,
// which counts zero.
type machoCountPayload struct {
	Schema string            `json:"schema"`
	Slices []machoCountSlice `json:"slices"`
}

type machoCountSlice struct {
	Segments []json.RawMessage `json:"segments"`
	Sections []json.RawMessage `json:"sections"`
	Dylibs   *machoDylibTable  `json:"dylibs"`
	Symbols  *machoSymbolTable `json:"symbols"`
}

type machoDylibTable struct {
	Dylibs []machoDylib `json:"dylibs"`
}

// machoDylib keeps only the command, so the count does not depend on the
// presentation fields of a dylib entry.
type machoDylib struct {
	Command uint32 `json:"command"`
}

type machoSymbolTable struct {
	Symbols []json.RawMessage `json:"symbols"`
}

// machoCommandDylibID is LC_ID_DYLIB. It names the image itself, so it is an
// install name rather than a dependency and is not counted as an import.
const machoCommandDylibID uint32 = 0xd

func countMachO(payload []byte) (Counts, error) {
	var raw machoCountPayload
	if err := json.Unmarshal(payload, &raw); err != nil {
		return Counts{}, fmt.Errorf("decode %s payload: %w", machoprovider.PayloadSchema, err)
	}
	if raw.Schema != machoprovider.PayloadSchema {
		return Counts{}, fmt.Errorf("decode %s payload: schema is %q", machoprovider.PayloadSchema, raw.Schema)
	}
	var counts Counts
	for _, slice := range raw.Slices {
		counts.Segments += len(slice.Segments)
		counts.Sections += len(slice.Sections)
		if slice.Dylibs != nil {
			for _, dylib := range slice.Dylibs.Dylibs {
				if dylib.Command != machoCommandDylibID {
					counts.Imports++
				}
			}
		}
		if slice.Symbols != nil {
			counts.Symbols += len(slice.Symbols.Symbols)
		}
	}
	return counts, nil
}
