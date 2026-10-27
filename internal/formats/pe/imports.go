package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

const importDescriptorSize = 20

// ThunkSource identifies which array supplied an import module's thunks.
type ThunkSource string

const (
	// ThunkSourceOriginal is the OriginalFirstThunk array.
	ThunkSourceOriginal ThunkSource = "original_first_thunk"
	// ThunkSourceIAT is the FirstThunk array, used when OriginalFirstThunk is
	// zero.
	ThunkSourceIAT ThunkSource = "first_thunk"
)

// ImportThunk is one import name or ordinal entry.
type ImportThunk struct {
	// Index is the position in the module's thunk array.
	Index int
	// ByOrdinal reports that the entry imports by ordinal. Ordinal is only
	// meaningful when this is true.
	ByOrdinal bool
	Ordinal   uint16
	// Hint is the import name hint. It is zero for an ordinal import or when
	// the name could not be read.
	Hint uint16
	// Name is the imported function name. It is empty when NameAvailable is
	// false.
	Name string
	// NameAvailable reports that Name was read and is valid UTF-8.
	NameAvailable bool
	// NameRVA is the RVA of the IMAGE_IMPORT_BY_NAME hint and name. It is zero
	// for an ordinal import.
	NameRVA uint32
}

// ImportModule is one import descriptor with its thunks.
type ImportModule struct {
	// Index is the descriptor position in the import directory.
	Index int
	// Name is the DLL name. It is empty when NameAvailable is false.
	Name string
	// NameAvailable reports that Name was read and is valid UTF-8.
	NameAvailable bool
	NameRVA       uint32

	TimeDateStamp      uint32
	ForwarderChain     uint32
	OriginalFirstThunk uint32
	FirstThunk         uint32

	// ThunkSource reports which thunk array was decoded. It is empty when both
	// thunk addresses are zero.
	ThunkSource ThunkSource
	Thunks      []ImportThunk

	// Truncated reports that the module was declared with more thunks than
	// were loaded or that its thunk array ended early.
	Truncated bool
}

// ImportTable is the decoded import directory.
type ImportTable struct {
	Modules []ImportModule

	// Truncated reports that the module or thunk list is incomplete because of
	// a configured limit, a short table, or an exhausted string budget.
	Truncated bool
	// Limitations states, in deterministic order, why the table is
	// incomplete or which names could not be decoded.
	Limitations []string
}

func (t *ImportTable) limit(format string, args ...any) {
	t.Limitations = append(t.Limitations, fmt.Sprintf(format, args...))
}

// Imports reads the import directory, its module names, and its thunks.
//
// An absent directory returns ErrNotFound. An inconsistent directory address
// or size returns ErrInvalid. A module or thunk list that is cut short by the
// artifact or a configured limit returns a partial table with Truncated set
// and a deterministic limitation. Reader failures return ErrRead.
func (f *File) Imports() (*ImportTable, error) {
	directory, err := f.metadataDirectory(1, "import")
	if err != nil {
		return nil, err
	}

	table := &ImportTable{}
	decoder := &importDecoder{
		file:   f,
		table:  table,
		budget: f.limits.ImportStringBytes,
	}

	for index := 0; ; index++ {
		rva64 := uint64(directory.VirtualAddress) + uint64(index)*importDescriptorSize
		if rva64 > math.MaxUint32 {
			table.Truncated = true
			table.limit("import descriptor array exceeds the 32-bit RVA space at module %d", index)
			break
		}
		raw, err := f.readRVA(uint32(rva64), importDescriptorSize)
		if err != nil {
			if errors.Is(err, ErrRead) {
				return nil, err
			}
			table.Truncated = true
			if index >= f.limits.ImportModules {
				table.limit("import module count exceeds limit %d", f.limits.ImportModules)
			} else {
				table.limit("import descriptor array ends at module %d without a zero terminator", index)
			}
			break
		}
		descriptor := decodeImportDescriptor(raw)
		if descriptor.isZero() {
			break
		}
		if index >= f.limits.ImportModules {
			table.Truncated = true
			table.limit("import module count exceeds limit %d", f.limits.ImportModules)
			break
		}
		module, err := decoder.decodeModule(index, descriptor)
		if err != nil {
			return nil, err
		}
		table.Modules = append(table.Modules, module)
		if decoder.stopped {
			break
		}
	}

	decoder.finish()
	return table, nil
}

type importDescriptor struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}

func decodeImportDescriptor(raw []byte) importDescriptor {
	order := binary.LittleEndian
	return importDescriptor{
		OriginalFirstThunk: order.Uint32(raw[0:]),
		TimeDateStamp:      order.Uint32(raw[4:]),
		ForwarderChain:     order.Uint32(raw[8:]),
		Name:               order.Uint32(raw[12:]),
		FirstThunk:         order.Uint32(raw[16:]),
	}
}

func (d importDescriptor) isZero() bool {
	return d == importDescriptor{}
}

type importDecoder struct {
	file   *File
	table  *ImportTable
	thunks int
	budget int64

	stopped   bool
	budgetHit bool

	moduleNamesUnavailable int
	moduleNamesInvalid     int
	moduleNamesLimited     int
	thunkNamesUnavailable  int
	thunkNamesInvalid      int
	thunkNamesLimited      int
	thunkArraysEnded       int
}

func (d *importDecoder) decodeModule(index int, descriptor importDescriptor) (ImportModule, error) {
	module := ImportModule{
		Index:              index,
		NameRVA:            descriptor.Name,
		TimeDateStamp:      descriptor.TimeDateStamp,
		ForwarderChain:     descriptor.ForwarderChain,
		OriginalFirstThunk: descriptor.OriginalFirstThunk,
		FirstThunk:         descriptor.FirstThunk,
	}

	if descriptor.Name == 0 {
		d.moduleNamesUnavailable++
	} else if name, err := d.file.readString(descriptor.Name, &d.budget); err != nil {
		if errors.Is(err, ErrRead) {
			return module, err
		}
		d.noteModuleName(err)
	} else {
		module.Name = name
		module.NameAvailable = true
	}

	thunkRVA := descriptor.OriginalFirstThunk
	module.ThunkSource = ThunkSourceOriginal
	if thunkRVA == 0 {
		thunkRVA = descriptor.FirstThunk
		module.ThunkSource = ThunkSourceIAT
	}
	if thunkRVA == 0 {
		module.ThunkSource = ""
		return module, nil
	}

	entrySize := 4
	if d.file.Header.Optional.Magic == MagicPE32P {
		entrySize = 8
	}
	for thunkIndex := 0; ; thunkIndex++ {
		rva64 := uint64(thunkRVA) + uint64(thunkIndex)*uint64(entrySize)
		if rva64 > math.MaxUint32 {
			module.Truncated = true
			d.table.Truncated = true
			d.thunkArraysEnded++
			break
		}
		raw, err := d.file.readRVA(uint32(rva64), entrySize)
		if err != nil {
			if errors.Is(err, ErrRead) {
				return module, err
			}
			module.Truncated = true
			d.table.Truncated = true
			d.thunkArraysEnded++
			break
		}
		value := uint64(binary.LittleEndian.Uint32(raw))
		if entrySize == 8 {
			value = binary.LittleEndian.Uint64(raw)
		}
		if value == 0 {
			break
		}
		if d.thunks >= d.file.limits.ImportThunks {
			module.Truncated = true
			d.table.Truncated = true
			d.table.limit("import thunk count exceeds limit %d in module %d",
				d.file.limits.ImportThunks, index)
			d.stopped = true
			break
		}

		thunk := decodeImportThunk(thunkIndex, value, entrySize == 8)
		if !thunk.ByOrdinal && thunk.NameRVA == 0 {
			d.thunkNamesUnavailable++
		} else if err := d.decodeThunkName(&thunk); err != nil {
			return module, err
		}
		module.Thunks = append(module.Thunks, thunk)
		d.thunks++
	}
	return module, nil
}

func decodeImportThunk(index int, value uint64, pe32plus bool) ImportThunk {
	thunk := ImportThunk{Index: index}
	ordinalFlag := uint64(0x80000000)
	if pe32plus {
		ordinalFlag = 0x8000000000000000
	}
	if value&ordinalFlag != 0 {
		thunk.ByOrdinal = true
		thunk.Ordinal = uint16(value)
		return thunk
	}
	if value > math.MaxUint32 {
		return thunk
	}
	thunk.NameRVA = uint32(value)
	return thunk
}

func (d *importDecoder) decodeThunkName(thunk *ImportThunk) error {
	if thunk.ByOrdinal || thunk.NameRVA == 0 {
		return nil
	}
	if d.budget <= 0 {
		d.budgetHit = true
		return nil
	}

	raw, err := d.file.readRVA(thunk.NameRVA, 2)
	if err != nil {
		if errors.Is(err, ErrRead) {
			return err
		}
		d.noteThunkName(err)
		return nil
	}
	thunk.Hint = binary.LittleEndian.Uint16(raw)

	nameRVA := thunk.NameRVA + 2
	if nameRVA < thunk.NameRVA {
		d.thunkNamesUnavailable++
		return nil
	}
	name, err := d.file.readString(nameRVA, &d.budget)
	if err != nil {
		if errors.Is(err, ErrRead) {
			return err
		}
		d.noteThunkName(err)
		return nil
	}
	thunk.Name = name
	thunk.NameAvailable = true
	return nil
}

func (d *importDecoder) noteModuleName(err error) {
	switch classifyStringError(err) {
	case stringInvalidUTF8:
		d.moduleNamesInvalid++
	case stringLimit:
		d.moduleNamesLimited++
		if d.budget <= 0 {
			d.budgetHit = true
		}
	default:
		d.moduleNamesUnavailable++
	}
}

func (d *importDecoder) noteThunkName(err error) {
	switch classifyStringError(err) {
	case stringInvalidUTF8:
		d.thunkNamesInvalid++
	case stringLimit:
		d.thunkNamesLimited++
		if d.budget <= 0 {
			d.budgetHit = true
		}
	default:
		d.thunkNamesUnavailable++
	}
}

func (d *importDecoder) finish() {
	table := d.table
	if d.thunkArraysEnded > 0 {
		table.limit("%d import thunk arrays end early", d.thunkArraysEnded)
	}
	if d.budgetHit {
		table.Truncated = true
		table.limit("import string budget exhausted; later names are unavailable")
	}
	if d.moduleNamesUnavailable > 0 {
		table.limit("%d import module names are unavailable", d.moduleNamesUnavailable)
	}
	if d.moduleNamesInvalid > 0 {
		table.limit("%d import module names are not valid UTF-8", d.moduleNamesInvalid)
	}
	if d.moduleNamesLimited > 0 {
		table.limit("%d import module names exceed the string limit", d.moduleNamesLimited)
	}
	if d.thunkNamesUnavailable > 0 {
		table.limit("%d import thunk names are unavailable", d.thunkNamesUnavailable)
	}
	if d.thunkNamesInvalid > 0 {
		table.limit("%d import thunk names are not valid UTF-8", d.thunkNamesInvalid)
	}
	if d.thunkNamesLimited > 0 {
		table.limit("%d import thunk names exceed the string limit", d.thunkNamesLimited)
	}
}
