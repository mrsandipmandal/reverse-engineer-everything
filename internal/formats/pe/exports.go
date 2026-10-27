package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const exportDirectorySize = 40

// Export is one exported function slot.
type Export struct {
	// Index is the position in the export address table.
	Index int
	// Ordinal is Base plus Index.
	Ordinal uint32
	// RVA is the exported address. It is zero for an unused slot.
	RVA uint32
	// Name is the export name. It is empty when NameAvailable is false. An
	// export may legitimately have no name.
	Name string
	// NameAvailable reports that Name was read and is valid UTF-8.
	NameAvailable bool
	// NameRVA is the RVA of the name string. It is zero when no name applies.
	NameRVA uint32
	// Forwarder is the forwarder target, such as "KERNEL32.Sleep". It is empty
	// when ForwarderAvailable is false.
	Forwarder string
	// ForwarderAvailable reports that RVA points inside the export directory
	// and its forwarder string was read.
	ForwarderAvailable bool
}

// ExportTable is the decoded export directory.
type ExportTable struct {
	// Name is the DLL name. It is empty when NameAvailable is false.
	Name string
	// NameAvailable reports that Name was read and is valid UTF-8.
	NameAvailable bool
	NameRVA       uint32

	TimeDateStamp uint32
	MajorVersion  uint16
	MinorVersion  uint16
	// Base is the ordinal of the first exported function.
	Base uint32
	// NumberOfFunctions and NumberOfNames are the declared counts. They may
	// exceed the number of entries loaded.
	NumberOfFunctions uint32
	NumberOfNames     uint32

	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32

	Exports []Export

	// Truncated reports that the function or name list is incomplete because
	// of a configured limit, a short or missing array, or an exhausted string
	// budget.
	Truncated bool
	// Limitations states, in deterministic order, why the table is
	// incomplete or which names could not be decoded.
	Limitations []string
}

func (t *ExportTable) limit(format string, args ...any) {
	t.Limitations = append(t.Limitations, fmt.Sprintf(format, args...))
}

// Exports reads the export directory, its function addresses, names, ordinals,
// and forwarder strings.
//
// An absent directory returns ErrNotFound. An inconsistent directory address
// or size, or an unreadable export directory structure, returns ErrInvalid or
// ErrUnavailable. A function or name list that is cut short by the artifact or
// a configured limit returns a partial table with Truncated set and a
// deterministic limitation. Reader failures return ErrRead.
func (f *File) Exports() (*ExportTable, error) {
	directory, err := f.metadataDirectory(0, "export")
	if err != nil {
		return nil, err
	}
	raw, err := f.readRVA(directory.VirtualAddress, exportDirectorySize)
	if err != nil {
		return nil, err
	}

	table := &ExportTable{
		NameRVA:               binary.LittleEndian.Uint32(raw[12:]),
		Base:                  binary.LittleEndian.Uint32(raw[16:]),
		NumberOfFunctions:     binary.LittleEndian.Uint32(raw[20:]),
		NumberOfNames:         binary.LittleEndian.Uint32(raw[24:]),
		AddressOfFunctions:    binary.LittleEndian.Uint32(raw[28:]),
		AddressOfNames:        binary.LittleEndian.Uint32(raw[32:]),
		AddressOfNameOrdinals: binary.LittleEndian.Uint32(raw[36:]),
		TimeDateStamp:         binary.LittleEndian.Uint32(raw[4:]),
		MajorVersion:          binary.LittleEndian.Uint16(raw[8:]),
		MinorVersion:          binary.LittleEndian.Uint16(raw[10:]),
	}
	budget := f.limits.ExportStringBytes

	var (
		dllNameUnavailable int
		dllNameInvalid     int
		dllNameLimited     int
		exportNameUnavail  int
		exportNameInvalid  int
		exportNameLimited  int
		badOrdinals        int
		duplicateNames     int
		forwardUnavail     int
		forwardInvalid     int
		forwardLimited     int
		budgetHit          bool
	)

	if table.NameRVA == 0 {
		dllNameUnavailable++
	} else if name, err := f.readString(table.NameRVA, &budget); err != nil {
		if errors.Is(err, ErrRead) {
			return nil, err
		}
		switch classifyStringError(err) {
		case stringInvalidUTF8:
			dllNameInvalid++
		case stringLimit:
			dllNameLimited++
			budgetHit = budget <= 0
		default:
			dllNameUnavailable++
		}
	} else {
		table.Name = name
		table.NameAvailable = true
	}

	functionCount := f.exportCount(table, table.NumberOfFunctions, "function")
	nameCount := f.exportCount(table, table.NumberOfNames, "name")

	if functionCount > 0 {
		if table.AddressOfFunctions == 0 {
			table.Truncated = true
			table.limit("export function array address is zero")
		} else {
			functions, err := f.readRVA(table.AddressOfFunctions, functionCount*4)
			if err != nil {
				if errors.Is(err, ErrRead) {
					return nil, err
				}
				table.Truncated = true
				table.limit("export function array is unavailable")
			} else {
				table.Exports = make([]Export, 0, functionCount)
				for i := 0; i < functionCount; i++ {
					table.Exports = append(table.Exports, Export{
						Index:   i,
						Ordinal: table.Base + uint32(i),
						RVA:     binary.LittleEndian.Uint32(functions[i*4:]),
					})
				}
			}
		}
	}

	if nameCount > 0 {
		switch {
		case table.AddressOfNames == 0 || table.AddressOfNameOrdinals == 0:
			table.Truncated = true
			table.limit("export name arrays are missing")
		default:
			names, namesErr := f.readRVA(table.AddressOfNames, nameCount*4)
			if namesErr != nil && errors.Is(namesErr, ErrRead) {
				return nil, namesErr
			}
			ordinals, ordinalsErr := f.readRVA(table.AddressOfNameOrdinals, nameCount*2)
			if ordinalsErr != nil && errors.Is(ordinalsErr, ErrRead) {
				return nil, ordinalsErr
			}
			if namesErr != nil || ordinalsErr != nil {
				table.Truncated = true
				table.limit("export name arrays are unavailable")
				break
			}
			for i := 0; i < nameCount; i++ {
				nameIndex := int(binary.LittleEndian.Uint16(ordinals[i*2:]))
				if nameIndex >= len(table.Exports) {
					badOrdinals++
					continue
				}
				entry := &table.Exports[nameIndex]
				if entry.NameAvailable {
					duplicateNames++
					continue
				}
				entry.NameRVA = binary.LittleEndian.Uint32(names[i*4:])
				if entry.NameRVA == 0 {
					exportNameUnavail++
					continue
				}
				name, err := f.readString(entry.NameRVA, &budget)
				if err != nil {
					if errors.Is(err, ErrRead) {
						return nil, err
					}
					switch classifyStringError(err) {
					case stringInvalidUTF8:
						exportNameInvalid++
					case stringLimit:
						exportNameLimited++
						if budget <= 0 {
							budgetHit = true
						}
					default:
						exportNameUnavail++
					}
					continue
				}
				entry.Name = name
				entry.NameAvailable = true
			}
		}
	}

	exportStart := uint64(directory.VirtualAddress)
	exportEnd := exportStart + uint64(directory.Size)
	for i := range table.Exports {
		entry := &table.Exports[i]
		if entry.RVA == 0 {
			continue
		}
		if uint64(entry.RVA) < exportStart || uint64(entry.RVA) >= exportEnd {
			continue
		}
		forwarderRVA, err := f.readRVA(entry.RVA, 4)
		if err != nil {
			if errors.Is(err, ErrRead) {
				return nil, err
			}
			forwardUnavail++
			continue
		}
		target := binary.LittleEndian.Uint32(forwarderRVA)
		if target == 0 {
			forwardUnavail++
			continue
		}
		forwarder, err := f.readString(target, &budget)
		if err != nil {
			if errors.Is(err, ErrRead) {
				return nil, err
			}
			switch classifyStringError(err) {
			case stringInvalidUTF8:
				forwardInvalid++
			case stringLimit:
				forwardLimited++
				if budget <= 0 {
					budgetHit = true
				}
			default:
				forwardUnavail++
			}
			continue
		}
		entry.Forwarder = forwarder
		entry.ForwarderAvailable = true
	}

	if budgetHit {
		table.Truncated = true
		table.limit("export string budget exhausted; later names are unavailable")
	}
	if dllNameUnavailable > 0 {
		table.limit("%d export DLL names are unavailable", dllNameUnavailable)
	}
	if dllNameInvalid > 0 {
		table.limit("%d export DLL names are not valid UTF-8", dllNameInvalid)
	}
	if dllNameLimited > 0 {
		table.limit("%d export DLL names exceed the string limit", dllNameLimited)
	}
	if exportNameUnavail > 0 {
		table.limit("%d export function names are unavailable", exportNameUnavail)
	}
	if exportNameInvalid > 0 {
		table.limit("%d export function names are not valid UTF-8", exportNameInvalid)
	}
	if exportNameLimited > 0 {
		table.limit("%d export function names exceed the string limit", exportNameLimited)
	}
	if badOrdinals > 0 {
		table.limit("%d export name ordinals are outside the function table", badOrdinals)
	}
	if duplicateNames > 0 {
		table.limit("%d export functions have more than one name; the first was kept", duplicateNames)
	}
	if forwardUnavail > 0 {
		table.limit("%d export forwarder strings are unavailable", forwardUnavail)
	}
	if forwardInvalid > 0 {
		table.limit("%d export forwarder strings are not valid UTF-8", forwardInvalid)
	}
	if forwardLimited > 0 {
		table.limit("%d export forwarder strings exceed the string limit", forwardLimited)
	}
	return table, nil
}

// exportCount clamps a declared export count to the configured limit and
// records the truncation. The uint64 comparison keeps a count near 2^32 from
// overflowing int on a 32-bit build.
func (f *File) exportCount(table *ExportTable, declared uint32, kind string) int {
	if uint64(declared) > uint64(f.limits.Exports) {
		table.Truncated = true
		table.limit("export %s count %d exceeds limit %d", kind, declared, f.limits.Exports)
		return f.limits.Exports
	}
	return int(declared)
}
