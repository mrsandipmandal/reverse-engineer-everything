package pe_test

import (
	"encoding/binary"
	"errors"
	"testing"

	repe "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/pe"
)

func TestExports(t *testing.T) {
	t.Parallel()

	for _, magic := range []uint16{repe.MagicPE32, repe.MagicPE32P} {
		magic := magic
		t.Run(magicName(t, magic), func(t *testing.T) {
			t.Parallel()

			image := newMetadataImage(magic)
			image.addExports("sample.dll", 5, []exportSpec{
				{name: "Alpha", rva: 0x5000},
				{name: "Forwarded", forwarder: "KERNEL32.Sleep"},
				{rva: 0x5020},
			})
			file := parseImage(t, image)

			table, err := file.Exports()
			if err != nil {
				t.Fatalf("Exports() error = %v", err)
			}
			if table.Truncated || len(table.Limitations) != 0 {
				t.Fatalf("Truncated = %t, limitations = %v", table.Truncated, table.Limitations)
			}
			if table.Name != "sample.dll" || !table.NameAvailable {
				t.Fatalf("DLL name = %+v", table)
			}
			if table.Base != 5 || table.NumberOfFunctions != 3 || table.NumberOfNames != 2 {
				t.Fatalf("counts = base %d, functions %d, names %d",
					table.Base, table.NumberOfFunctions, table.NumberOfNames)
			}
			if len(table.Exports) != 3 {
				t.Fatalf("export count = %d", len(table.Exports))
			}

			alpha := table.Exports[0]
			if alpha.Index != 0 || alpha.Ordinal != 5 || alpha.RVA != 0x5000 ||
				alpha.Name != "Alpha" || !alpha.NameAvailable || alpha.ForwarderAvailable {
				t.Fatalf("export 0 = %+v", alpha)
			}

			forwarded := table.Exports[1]
			if forwarded.Ordinal != 6 || forwarded.Name != "Forwarded" || !forwarded.NameAvailable {
				t.Fatalf("export 1 = %+v", forwarded)
			}
			if !forwarded.ForwarderAvailable || forwarded.Forwarder != "KERNEL32.Sleep" {
				t.Fatalf("export 1 forwarder = %+v", forwarded)
			}

			unnamed := table.Exports[2]
			if unnamed.Ordinal != 7 || unnamed.RVA != 0x5020 || unnamed.NameAvailable ||
				unnamed.Name != "" || unnamed.ForwarderAvailable {
				t.Fatalf("export 2 = %+v", unnamed)
			}
		})
	}
}

func TestExportsDirectoryErrors(t *testing.T) {
	t.Parallel()

	t.Run("absent", func(t *testing.T) {
		t.Parallel()

		file := parseImage(t, newMetadataImage(repe.MagicPE32))
		if _, err := file.Exports(); !errors.Is(err, repe.ErrNotFound) {
			t.Fatalf("Exports() error = %v, want ErrNotFound", err)
		}
	})

	t.Run("not declared", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.directoryCount = 0
		image.addExports("sample.dll", 1, []exportSpec{{name: "Alpha", rva: 0x5000}})
		file := parseImage(t, image)
		if _, err := file.Exports(); !errors.Is(err, repe.ErrNotFound) {
			t.Fatalf("Exports() error = %v, want ErrNotFound", err)
		}
	})

	t.Run("zero address", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.directories[0] = [2]uint32{0, 40}
		file := parseImage(t, image)
		if _, err := file.Exports(); !errors.Is(err, repe.ErrInvalid) {
			t.Fatalf("Exports() error = %v, want ErrInvalid", err)
		}
	})

	t.Run("zero size", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.directories[0] = [2]uint32{metadataRVA, 0}
		file := parseImage(t, image)
		if _, err := file.Exports(); !errors.Is(err, repe.ErrInvalid) {
			t.Fatalf("Exports() error = %v, want ErrInvalid", err)
		}
	})

	t.Run("unmapped structure", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.directories[0] = [2]uint32{0x9000, 40}
		file := parseImage(t, image)
		if _, err := file.Exports(); !errors.Is(err, repe.ErrUnavailable) {
			t.Fatalf("Exports() error = %v, want ErrUnavailable", err)
		}
	})
}

func TestExportsLimits(t *testing.T) {
	t.Parallel()

	t.Run("function limit", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.addExports("sample.dll", 1, []exportSpec{
			{name: "Alpha", rva: 0x5000},
			{name: "Beta", rva: 0x5010},
			{name: "Gamma", rva: 0x5020},
		})
		limits := repe.DefaultLimits()
		limits.Exports = 2
		file := parseImageWithLimits(t, image, limits)

		table, err := file.Exports()
		if err != nil {
			t.Fatalf("Exports() error = %v", err)
		}
		if len(table.Exports) != 2 || !table.Truncated {
			t.Fatalf("exports = %d, truncated = %t", len(table.Exports), table.Truncated)
		}
		if table.NumberOfFunctions != 3 {
			t.Fatalf("declared function count = %d", table.NumberOfFunctions)
		}
		if !hasLimitation(table.Limitations, "export function count 3 exceeds limit 2") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
		if !hasLimitation(table.Limitations, "export name count 3 exceeds limit 2") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("exact function limit", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.addExports("sample.dll", 1, []exportSpec{
			{name: "Alpha", rva: 0x5000},
			{name: "Beta", rva: 0x5010},
		})
		limits := repe.DefaultLimits()
		limits.Exports = 2
		file := parseImageWithLimits(t, image, limits)

		table, err := file.Exports()
		if err != nil {
			t.Fatalf("Exports() error = %v", err)
		}
		if table.Truncated || len(table.Limitations) != 0 || len(table.Exports) != 2 {
			t.Fatalf("truncated = %t, limitations = %v, exports = %d",
				table.Truncated, table.Limitations, len(table.Exports))
		}
	})
}

func TestExportsMalformed(t *testing.T) {
	t.Parallel()

	t.Run("bad name ordinal", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		layout := image.addExports("sample.dll", 1, []exportSpec{
			{name: "Alpha", rva: 0x5000},
			{name: "Beta", rva: 0x5010},
		})
		data := image.build(t)
		binary.LittleEndian.PutUint16(data[image.offset(layout.ordinalsRVA):], 9)
		file := parseImageData(t, data)

		table, err := file.Exports()
		if err != nil {
			t.Fatalf("Exports() error = %v", err)
		}
		if table.Exports[0].NameAvailable {
			t.Fatalf("bad ordinal still produced a name: %+v", table.Exports[0])
		}
		if !hasLimitation(table.Limitations, "1 export name ordinals are outside the function table") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("duplicate name", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		layout := image.addExports("sample.dll", 1, []exportSpec{
			{name: "Alpha", rva: 0x5000},
			{name: "Beta", rva: 0x5010},
		})
		data := image.build(t)
		binary.LittleEndian.PutUint16(data[image.offset(layout.ordinalsRVA)+2:], 0)
		file := parseImageData(t, data)

		table, err := file.Exports()
		if err != nil {
			t.Fatalf("Exports() error = %v", err)
		}
		if table.Exports[0].Name != "Alpha" || table.Exports[1].NameAvailable {
			t.Fatalf("exports = %+v", table.Exports)
		}
		if !hasLimitation(table.Limitations, "1 export functions have more than one name") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("missing name arrays", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		layout := image.addExports("sample.dll", 1, []exportSpec{{name: "Alpha", rva: 0x5000}})
		data := image.build(t)
		binary.LittleEndian.PutUint32(data[image.offset(layout.directoryRVA)+32:], 0)
		file := parseImageData(t, data)

		table, err := file.Exports()
		if err != nil {
			t.Fatalf("Exports() error = %v", err)
		}
		if !table.Truncated || table.Exports[0].NameAvailable {
			t.Fatalf("truncated = %t, exports = %+v", table.Truncated, table.Exports)
		}
		if !hasLimitation(table.Limitations, "export name arrays are missing") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("zero function array", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		layout := image.addExports("sample.dll", 1, []exportSpec{{rva: 0x5000}})
		data := image.build(t)
		binary.LittleEndian.PutUint32(data[image.offset(layout.directoryRVA)+28:], 0)
		file := parseImageData(t, data)

		table, err := file.Exports()
		if err != nil {
			t.Fatalf("Exports() error = %v", err)
		}
		if !table.Truncated || len(table.Exports) != 0 {
			t.Fatalf("truncated = %t, exports = %d", table.Truncated, len(table.Exports))
		}
		if !hasLimitation(table.Limitations, "export function array address is zero") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("unavailable name arrays", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		layout := image.addExports("sample.dll", 1, []exportSpec{{name: "Alpha", rva: 0x5000}})
		data := image.build(t)
		binary.LittleEndian.PutUint32(data[image.offset(layout.directoryRVA)+32:], 0x9000)
		file := parseImageData(t, data)

		table, err := file.Exports()
		if err != nil {
			t.Fatalf("Exports() error = %v", err)
		}
		if !table.Truncated || table.Exports[0].NameAvailable {
			t.Fatalf("truncated = %t, exports = %+v", table.Truncated, table.Exports)
		}
		if !hasLimitation(table.Limitations, "export name arrays are unavailable") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("zero name rva", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		layout := image.addExports("sample.dll", 1, []exportSpec{{name: "Alpha", rva: 0x5000}})
		data := image.build(t)
		binary.LittleEndian.PutUint32(data[image.offset(layout.namesRVA):], 0)
		file := parseImageData(t, data)

		table, err := file.Exports()
		if err != nil {
			t.Fatalf("Exports() error = %v", err)
		}
		if table.Exports[0].NameAvailable {
			t.Fatalf("export = %+v", table.Exports[0])
		}
		if !hasLimitation(table.Limitations, "1 export function names are unavailable") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("string limits", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.addExports("sample.dll", 1, []exportSpec{{name: "Alpha", rva: 0x5000}})
		limits := repe.DefaultLimits()
		limits.StringBytes = 4
		file := parseImageWithLimits(t, image, limits)

		table, err := file.Exports()
		if err != nil {
			t.Fatalf("Exports() error = %v", err)
		}
		if table.NameAvailable || table.Exports[0].NameAvailable {
			t.Fatalf("names = %q / %+v", table.Name, table.Exports[0])
		}
		if !hasLimitation(table.Limitations, "1 export DLL names exceed the string limit") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
		if !hasLimitation(table.Limitations, "1 export function names exceed the string limit") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("string budget", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.addExports("sample.dll", 1, []exportSpec{{name: "Alpha", rva: 0x5000}})
		limits := repe.DefaultLimits()
		limits.ExportStringBytes = 4
		file := parseImageWithLimits(t, image, limits)

		table, err := file.Exports()
		if err != nil {
			t.Fatalf("Exports() error = %v", err)
		}
		if !table.Truncated {
			t.Fatal("string budget exhaustion did not set Truncated")
		}
		if !hasLimitation(table.Limitations, "export string budget exhausted") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("invalid forwarder", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.addExports("sample.dll", 1, []exportSpec{
			{forwarder: string([]byte{0xff, 0xfe})},
		})
		file := parseImage(t, image)

		table, err := file.Exports()
		if err != nil {
			t.Fatalf("Exports() error = %v", err)
		}
		if table.Exports[0].ForwarderAvailable {
			t.Fatalf("forwarder = %+v", table.Exports[0])
		}
		if !hasLimitation(table.Limitations, "1 export forwarder strings are not valid UTF-8") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("forwarder string limit", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.addExports("sample.dll", 1, []exportSpec{{forwarder: "KERNEL32.Sleep"}})
		limits := repe.DefaultLimits()
		limits.StringBytes = 4
		file := parseImageWithLimits(t, image, limits)

		table, err := file.Exports()
		if err != nil {
			t.Fatalf("Exports() error = %v", err)
		}
		if table.Exports[0].ForwarderAvailable {
			t.Fatalf("forwarder = %+v", table.Exports[0])
		}
		if !hasLimitation(table.Limitations, "1 export forwarder strings exceed the string limit") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("unavailable function array", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		layout := image.addExports("sample.dll", 1, []exportSpec{{name: "Alpha", rva: 0x5000}})
		data := image.build(t)
		binary.LittleEndian.PutUint32(data[image.offset(layout.directoryRVA)+28:], 0x9000)
		file := parseImageData(t, data)

		table, err := file.Exports()
		if err != nil {
			t.Fatalf("Exports() error = %v", err)
		}
		if !table.Truncated || len(table.Exports) != 0 {
			t.Fatalf("truncated = %t, exports = %d", table.Truncated, len(table.Exports))
		}
		if !hasLimitation(table.Limitations, "export function array is unavailable") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("invalid function name", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.addExports("sample.dll", 1, []exportSpec{
			{name: string([]byte{0xff, 0xfe}), rva: 0x5000},
		})
		file := parseImage(t, image)

		table, err := file.Exports()
		if err != nil {
			t.Fatalf("Exports() error = %v", err)
		}
		if table.Exports[0].NameAvailable {
			t.Fatalf("export = %+v", table.Exports[0])
		}
		if !hasLimitation(table.Limitations, "1 export function names are not valid UTF-8") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("invalid DLL name", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.addExports(string([]byte{0x80, 0x81}), 1, []exportSpec{{name: "Alpha", rva: 0x5000}})
		file := parseImage(t, image)

		table, err := file.Exports()
		if err != nil {
			t.Fatalf("Exports() error = %v", err)
		}
		if table.NameAvailable {
			t.Fatalf("DLL name = %+v", table)
		}
		if !hasLimitation(table.Limitations, "1 export DLL names are not valid UTF-8") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("unavailable forwarder", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.addExports("sample.dll", 1, []exportSpec{{forwarder: "KERNEL32.Sleep"}})
		data := image.build(t)
		file := parseImageData(t, data)
		table, err := file.Exports()
		if err != nil {
			t.Fatalf("Exports() error = %v", err)
		}
		forwarderRVA := table.Exports[0].RVA
		if forwarderRVA == 0 {
			t.Fatal("fixture did not produce a forwarder entry")
		}
		binary.LittleEndian.PutUint32(data[image.offset(forwarderRVA):], 0x9000)

		file = parseImageData(t, data)
		table, err = file.Exports()
		if err != nil {
			t.Fatalf("Exports() error = %v", err)
		}
		if table.Exports[0].ForwarderAvailable {
			t.Fatalf("forwarder = %+v", table.Exports[0])
		}
		if !hasLimitation(table.Limitations, "1 export forwarder strings are unavailable") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})
}

func TestExportsReaderFailure(t *testing.T) {
	t.Parallel()

	image := newMetadataImage(repe.MagicPE32)
	image.addExports("sample.dll", 1, []exportSpec{{name: "Alpha", rva: 0x5000}})
	data := image.build(t)

	reader := failingReader{data: data, off: metadataRawOffset}
	file, err := repe.Parse(reader, int64(len(data)))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if _, err := file.Exports(); !errors.Is(err, repe.ErrRead) {
		t.Fatalf("Exports() error = %v, want ErrRead", err)
	}
}

func TestExportsUnterminatedName(t *testing.T) {
	t.Parallel()

	image := newMetadataImage(repe.MagicPE32)
	layout := image.addExports("sample.dll", 1, []exportSpec{{name: "Alpha", rva: 0x5000}})
	tailRVA := image.put([]byte("NoNull"))
	data := image.build(t)
	binary.LittleEndian.PutUint32(data[image.offset(layout.directoryRVA)+12:], tailRVA)
	file := parseImageData(t, data)

	table, err := file.Exports()
	if err != nil {
		t.Fatalf("Exports() error = %v", err)
	}
	if table.NameAvailable {
		t.Fatalf("unterminated DLL name was accepted: %+v", table)
	}
	if !hasLimitation(table.Limitations, "1 export DLL names are unavailable") {
		t.Fatalf("limitations = %v", table.Limitations)
	}
}

func TestExportsZeroForwarderTarget(t *testing.T) {
	t.Parallel()

	image := newMetadataImage(repe.MagicPE32)
	image.addExports("sample.dll", 1, []exportSpec{{forwarder: "KERNEL32.Sleep"}})
	data := image.build(t)
	file := parseImageData(t, data)

	table, err := file.Exports()
	if err != nil {
		t.Fatalf("Exports() error = %v", err)
	}
	forwarderRVA := table.Exports[0].RVA
	binary.LittleEndian.PutUint32(data[image.offset(forwarderRVA):], 0)

	file = parseImageData(t, data)
	table, err = file.Exports()
	if err != nil {
		t.Fatalf("Exports() error = %v", err)
	}
	if table.Exports[0].ForwarderAvailable {
		t.Fatalf("forwarder = %+v", table.Exports[0])
	}
	if !hasLimitation(table.Limitations, "1 export forwarder strings are unavailable") {
		t.Fatalf("limitations = %v", table.Limitations)
	}
}

func TestExportsDirectoryInHeadersBeyondArtifact(t *testing.T) {
	t.Parallel()

	image := newMetadataImage(repe.MagicPE32)
	image.directories[0] = [2]uint32{0x300, 40}
	data := image.build(t)
	binary.LittleEndian.PutUint32(data[0x84+20+60:], 0x400)
	file := parseImageData(t, data)

	if _, err := file.Exports(); !errors.Is(err, repe.ErrUnavailable) {
		t.Fatalf("Exports() error = %v, want ErrUnavailable", err)
	}
}
