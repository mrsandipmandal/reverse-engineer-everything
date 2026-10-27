package pe_test

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"testing"

	repe "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/pe"
)

func TestImports(t *testing.T) {
	t.Parallel()

	for _, magic := range []uint16{repe.MagicPE32, repe.MagicPE32P} {
		magic := magic
		t.Run(magicName(t, magic), func(t *testing.T) {
			t.Parallel()

			image := newMetadataImage(magic)
			image.addImports([]importSpec{
				{name: "KERNEL32.dll", thunks: []thunkSpec{
					{name: "CreateFileW", hint: 1},
					{byOrdinal: true, ordinal: 7},
				}},
				{name: "USER32.dll", iatOnly: true, thunks: []thunkSpec{
					{name: "MessageBoxA", hint: 2},
				}},
				{name: "EMPTY.dll"},
			})
			file := parseImage(t, image)

			table, err := file.Imports()
			if err != nil {
				t.Fatalf("Imports() error = %v", err)
			}
			if table.Truncated || len(table.Limitations) != 0 {
				t.Fatalf("Truncated = %t, limitations = %v", table.Truncated, table.Limitations)
			}
			if len(table.Modules) != 3 {
				t.Fatalf("module count = %d", len(table.Modules))
			}

			kernel := table.Modules[0]
			if kernel.Index != 0 || kernel.Name != "KERNEL32.dll" || !kernel.NameAvailable {
				t.Fatalf("module 0 = %+v", kernel)
			}
			if kernel.ThunkSource != repe.ThunkSourceOriginal {
				t.Fatalf("module 0 thunk source = %q", kernel.ThunkSource)
			}
			if len(kernel.Thunks) != 2 {
				t.Fatalf("module 0 thunk count = %d", len(kernel.Thunks))
			}
			if got := kernel.Thunks[0]; got.ByOrdinal || !got.NameAvailable ||
				got.Name != "CreateFileW" || got.Hint != 1 || got.Index != 0 {
				t.Fatalf("module 0 thunk 0 = %+v", got)
			}
			if got := kernel.Thunks[1]; !got.ByOrdinal || got.Ordinal != 7 ||
				got.NameAvailable || got.Name != "" || got.Index != 1 {
				t.Fatalf("module 0 thunk 1 = %+v", got)
			}

			user := table.Modules[1]
			if user.Name != "USER32.dll" || user.ThunkSource != repe.ThunkSourceIAT {
				t.Fatalf("module 1 = %+v", user)
			}
			if len(user.Thunks) != 1 || user.Thunks[0].Name != "MessageBoxA" || user.Thunks[0].Hint != 2 {
				t.Fatalf("module 1 thunks = %+v", user.Thunks)
			}

			empty := table.Modules[2]
			if empty.Name != "EMPTY.dll" || empty.ThunkSource != "" || len(empty.Thunks) != 0 {
				t.Fatalf("module 2 = %+v", empty)
			}
		})
	}
}

func TestImportsDirectoryErrors(t *testing.T) {
	t.Parallel()

	t.Run("absent", func(t *testing.T) {
		t.Parallel()

		file := parseImage(t, newMetadataImage(repe.MagicPE32))
		if _, err := file.Imports(); !errors.Is(err, repe.ErrNotFound) {
			t.Fatalf("Imports() error = %v, want ErrNotFound", err)
		}
	})

	t.Run("not declared", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.directoryCount = 1
		image.addImports([]importSpec{{name: "A.dll"}})
		file := parseImage(t, image)
		if _, err := file.Imports(); !errors.Is(err, repe.ErrNotFound) {
			t.Fatalf("Imports() error = %v, want ErrNotFound", err)
		}
	})

	t.Run("not loaded", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.addImports([]importSpec{{name: "A.dll"}})
		limits := repe.DefaultLimits()
		limits.DataDirectories = 1
		file := parseImageWithLimits(t, image, limits)
		if _, err := file.Imports(); !errors.Is(err, repe.ErrUnavailable) {
			t.Fatalf("Imports() error = %v, want ErrUnavailable", err)
		}
	})

	t.Run("zero address", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.directories[1] = [2]uint32{0, 8}
		file := parseImage(t, image)
		if _, err := file.Imports(); !errors.Is(err, repe.ErrInvalid) {
			t.Fatalf("Imports() error = %v, want ErrInvalid", err)
		}
	})

	t.Run("zero size", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.directories[1] = [2]uint32{metadataRVA, 0}
		file := parseImage(t, image)
		if _, err := file.Imports(); !errors.Is(err, repe.ErrInvalid) {
			t.Fatalf("Imports() error = %v, want ErrInvalid", err)
		}
	})
}

func TestImportsLimits(t *testing.T) {
	t.Parallel()

	t.Run("module limit", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.addImports([]importSpec{{name: "A.dll"}, {name: "B.dll"}, {name: "C.dll"}})
		limits := repe.DefaultLimits()
		limits.ImportModules = 2
		file := parseImageWithLimits(t, image, limits)

		table, err := file.Imports()
		if err != nil {
			t.Fatalf("Imports() error = %v", err)
		}
		if len(table.Modules) != 2 || !table.Truncated {
			t.Fatalf("modules = %d, truncated = %t", len(table.Modules), table.Truncated)
		}
		if !hasLimitation(table.Limitations, "import module count exceeds limit 2") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("thunk limit", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.addImports([]importSpec{{name: "A.dll", thunks: []thunkSpec{
			{name: "One"}, {name: "Two"}, {name: "Three"},
		}}})
		limits := repe.DefaultLimits()
		limits.ImportThunks = 2
		file := parseImageWithLimits(t, image, limits)

		table, err := file.Imports()
		if err != nil {
			t.Fatalf("Imports() error = %v", err)
		}
		if len(table.Modules) != 1 || !table.Truncated || !table.Modules[0].Truncated {
			t.Fatalf("modules = %d, truncated = %t, module = %+v",
				len(table.Modules), table.Truncated, table.Modules)
		}
		if len(table.Modules[0].Thunks) != 2 {
			t.Fatalf("thunk count = %d", len(table.Modules[0].Thunks))
		}
		if !hasLimitation(table.Limitations, "import thunk count exceeds limit 2 in module 0") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("exact thunk limit", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.addImports([]importSpec{{name: "A.dll", thunks: []thunkSpec{
			{name: "One"}, {name: "Two"},
		}}})
		limits := repe.DefaultLimits()
		limits.ImportThunks = 2
		file := parseImageWithLimits(t, image, limits)

		table, err := file.Imports()
		if err != nil {
			t.Fatalf("Imports() error = %v", err)
		}
		if table.Truncated || len(table.Limitations) != 0 || len(table.Modules[0].Thunks) != 2 {
			t.Fatalf("truncated = %t, limitations = %v, thunks = %d",
				table.Truncated, table.Limitations, len(table.Modules[0].Thunks))
		}
	})

	t.Run("string limit", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.addImports([]importSpec{{name: "K.dll", thunks: []thunkSpec{{name: "CreateFileW"}}}})
		limits := repe.DefaultLimits()
		limits.StringBytes = 8
		file := parseImageWithLimits(t, image, limits)

		table, err := file.Imports()
		if err != nil {
			t.Fatalf("Imports() error = %v", err)
		}
		if !table.Modules[0].NameAvailable || table.Modules[0].Name != "K.dll" {
			t.Fatalf("module name = %+v", table.Modules[0])
		}
		if table.Modules[0].Thunks[0].NameAvailable {
			t.Fatalf("long thunk name was accepted: %+v", table.Modules[0].Thunks[0])
		}
		if !hasLimitation(table.Limitations, "1 import thunk names exceed the string limit") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("string budget", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.addImports([]importSpec{{name: "KERNEL32.dll", thunks: []thunkSpec{{name: "Sleep"}}}})
		limits := repe.DefaultLimits()
		limits.ImportStringBytes = 4
		file := parseImageWithLimits(t, image, limits)

		table, err := file.Imports()
		if err != nil {
			t.Fatalf("Imports() error = %v", err)
		}
		if !table.Truncated {
			t.Fatal("string budget exhaustion did not set Truncated")
		}
		if table.Modules[0].NameAvailable {
			t.Fatalf("module name was accepted: %+v", table.Modules[0])
		}
		if table.Modules[0].Thunks[0].NameAvailable {
			t.Fatalf("thunk name was accepted: %+v", table.Modules[0].Thunks[0])
		}
		if !hasLimitation(table.Limitations, "import string budget exhausted") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})
}

func TestImportsMalformed(t *testing.T) {
	t.Parallel()

	t.Run("unterminated descriptor array", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		descriptorRVA := image.addImports([]importSpec{{name: "A.dll"}})
		data := image.build(t)
		cut := image.offset(descriptorRVA) + 20
		file := parseImageData(t, data[:cut])

		table, err := file.Imports()
		if err != nil {
			t.Fatalf("Imports() error = %v", err)
		}
		if len(table.Modules) != 1 || !table.Truncated {
			t.Fatalf("modules = %d, truncated = %t", len(table.Modules), table.Truncated)
		}
		if !hasLimitation(table.Limitations, "descriptor array ends at module 1") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("unavailable module name", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		descriptorRVA := image.addImports([]importSpec{{name: "A.dll"}})
		data := image.build(t)
		binary.LittleEndian.PutUint32(data[image.offset(descriptorRVA)+12:], 0x9000)
		file := parseImageData(t, data)

		table, err := file.Imports()
		if err != nil {
			t.Fatalf("Imports() error = %v", err)
		}
		if table.Modules[0].NameAvailable {
			t.Fatalf("module name = %+v", table.Modules[0])
		}
		if !hasLimitation(table.Limitations, "1 import module names are unavailable") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("invalid module name", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.addImports([]importSpec{{name: string([]byte{0xff, 0xfe})}})
		file := parseImage(t, image)

		table, err := file.Imports()
		if err != nil {
			t.Fatalf("Imports() error = %v", err)
		}
		if table.Modules[0].NameAvailable {
			t.Fatalf("module name = %+v", table.Modules[0])
		}
		if !hasLimitation(table.Limitations, "1 import module names are not valid UTF-8") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("invalid thunk name", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.addImports([]importSpec{{name: "A.dll", thunks: []thunkSpec{
			{name: string([]byte{0x80, 0x81})},
		}}})
		file := parseImage(t, image)

		table, err := file.Imports()
		if err != nil {
			t.Fatalf("Imports() error = %v", err)
		}
		if table.Modules[0].Thunks[0].NameAvailable {
			t.Fatalf("thunk name = %+v", table.Modules[0].Thunks[0])
		}
		if !hasLimitation(table.Limitations, "1 import thunk names are not valid UTF-8") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("unavailable thunk array", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		descriptorRVA := image.addImports([]importSpec{{name: "A.dll", thunks: []thunkSpec{{name: "Sleep"}}}})
		data := image.build(t)
		binary.LittleEndian.PutUint32(data[image.offset(descriptorRVA)+0:], 0x9000)
		binary.LittleEndian.PutUint32(data[image.offset(descriptorRVA)+16:], 0x9000)
		file := parseImageData(t, data)

		table, err := file.Imports()
		if err != nil {
			t.Fatalf("Imports() error = %v", err)
		}
		if len(table.Modules) != 1 || !table.Truncated || !table.Modules[0].Truncated {
			t.Fatalf("modules = %d, truncated = %t", len(table.Modules), table.Truncated)
		}
		if !hasLimitation(table.Limitations, "1 import thunk arrays end early") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})
}

func TestImportsReaderFailure(t *testing.T) {
	t.Parallel()

	image := newMetadataImage(repe.MagicPE32)
	image.addImports([]importSpec{{name: "A.dll", thunks: []thunkSpec{{name: "Sleep"}}}})
	data := image.build(t)

	reader := failingReader{data: data, off: metadataRawOffset}
	file, err := repe.Parse(reader, int64(len(data)))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if _, err := file.Imports(); !errors.Is(err, repe.ErrRead) {
		t.Fatalf("Imports() error = %v, want ErrRead", err)
	}
}

func TestImportsDifferentialAgainstDebugPE(t *testing.T) {
	t.Parallel()

	for _, magic := range []uint16{repe.MagicPE32, repe.MagicPE32P} {
		magic := magic
		t.Run(magicName(t, magic), func(t *testing.T) {
			t.Parallel()

			image := newMetadataImage(magic)
			image.addImports([]importSpec{{name: "KERNEL32.dll", thunks: []thunkSpec{
				{name: "Sleep", hint: 1},
				{name: "GetTickCount", hint: 2},
			}}})
			data := image.build(t)
			file := parseImageData(t, data)
			table, err := file.Imports()
			if err != nil {
				t.Fatalf("Imports() error = %v", err)
			}

			oracle, err := pe.NewFile(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("debug/pe.NewFile() error = %v", err)
			}
			t.Cleanup(func() { _ = oracle.Close() })
			symbols, err := oracle.ImportedSymbols()
			if err != nil {
				t.Fatalf("ImportedSymbols() error = %v", err)
			}
			var gotSymbols []string
			for _, module := range table.Modules {
				for _, thunk := range module.Thunks {
					if thunk.NameAvailable {
						gotSymbols = append(gotSymbols, thunk.Name+":"+module.Name)
					}
				}
			}
			if len(gotSymbols) != len(symbols) {
				t.Fatalf("symbols = %v, want %v", gotSymbols, symbols)
			}
			for i := range symbols {
				if gotSymbols[i] != symbols[i] {
					t.Fatalf("symbols = %v, want %v", gotSymbols, symbols)
				}
			}
		})
	}
}

func TestImportsInHeadersRegion(t *testing.T) {
	t.Parallel()

	image := newMetadataImage(repe.MagicPE32)
	image.directories[1] = [2]uint32{0x1a0, 20}
	data := image.build(t)

	descriptor := 0x1a0
	binary.LittleEndian.PutUint32(data[descriptor+12:], 0x1e0)
	copy(data[0x1e0:], "H.dll\x00")
	file := parseImageData(t, data)

	table, err := file.Imports()
	if err != nil {
		t.Fatalf("Imports() error = %v", err)
	}
	if len(table.Modules) != 1 {
		t.Fatalf("module count = %d", len(table.Modules))
	}
	if module := table.Modules[0]; module.Name != "H.dll" || !module.NameAvailable ||
		module.ThunkSource != "" || len(module.Thunks) != 0 {
		t.Fatalf("module = %+v", module)
	}
	if table.Truncated || len(table.Limitations) != 0 {
		t.Fatalf("truncated = %t, limitations = %v", table.Truncated, table.Limitations)
	}
}
