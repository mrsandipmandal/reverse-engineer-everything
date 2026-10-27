package elf_test

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"testing"

	reeelf "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/elf"
)

func TestDifferentialAgainstDebugELF(t *testing.T) {
	t.Parallel()

	targets := []struct {
		name string
		data []byte
	}{
		{name: "fixture/ELF32/little", data: buildFixture(reeelf.Class32, reeelf.DataLittle).data},
		{name: "fixture/ELF32/big", data: buildFixture(reeelf.Class32, reeelf.DataBig).data},
		{name: "fixture/ELF64/little", data: buildFixture(reeelf.Class64, reeelf.DataLittle).data},
		{name: "fixture/ELF64/big", data: buildFixture(reeelf.Class64, reeelf.DataBig).data},
		{name: "fixture/metadata", data: buildMetadataFixture(reeelf.Class64, reeelf.DataLittle, metadataNotes(reeelf.DataLittle)).data},
	}
	if path, err := os.Executable(); err == nil {
		if data, err := os.ReadFile(path); err == nil && len(data) >= 4 &&
			bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}) {
			targets = append(targets, struct {
				name string
				data []byte
			}{name: "test-executable", data: data})
		}
	}

	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			t.Parallel()

			got, err := reeelf.Parse(bytes.NewReader(target.data), int64(len(target.data)))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			want, err := elf.NewFile(bytes.NewReader(target.data))
			if err != nil {
				t.Fatalf("debug/elf.NewFile() error = %v", err)
			}
			t.Cleanup(func() { _ = want.Close() })

			compareHeader(t, got, want.FileHeader)
			compareSections(t, got.SectionHeaders, want.Sections)
			comparePrograms(t, got.ProgramHeaders, want.Progs)
		})
	}
}

func compareHeader(t *testing.T, file *reeelf.File, want elf.FileHeader) {
	t.Helper()

	got := file.Header
	if want.Class != elf.ELFCLASS32 && want.Class != elf.ELFCLASS64 {
		t.Fatalf("debug/elf class = %v", want.Class)
	}
	wantClass := reeelf.Class32
	if want.Class == elf.ELFCLASS64 {
		wantClass = reeelf.Class64
	}
	if got.Class != wantClass {
		t.Fatalf("class = %v, want %v", got.Class, wantClass)
	}

	if got.Data != reeelf.DataLittle && got.Data != reeelf.DataBig {
		t.Fatalf("data encoding = %v", got.Data)
	}
	wantData := reeelf.DataLittle
	if want.Data == elf.ELFDATA2MSB {
		wantData = reeelf.DataBig
	}
	if got.Data != wantData {
		t.Fatalf("data encoding = %v, want %v", got.Data, wantData)
	}
	if got.IdentVersion != uint8(want.Version) {
		t.Fatalf("identifier version = %d, want %d", got.IdentVersion, uint8(want.Version))
	}
	if got.OSABI != uint8(want.OSABI) || got.ABIVersion != want.ABIVersion {
		t.Fatalf("osabi/abi = %d/%d, want %d/%d",
			got.OSABI, got.ABIVersion, uint8(want.OSABI), want.ABIVersion)
	}
	if got.Type != uint16(want.Type) || got.Machine != uint16(want.Machine) {
		t.Fatalf("type/machine = %d/%d, want %d/%d",
			got.Type, got.Machine, uint16(want.Type), uint16(want.Machine))
	}
	if got.Entry != want.Entry {
		t.Fatalf("entry = %#x, want %#x", got.Entry, want.Entry)
	}
	if file.Truncated {
		t.Fatalf("test target was truncated: %v", file.Limitations)
	}
	if uint64(len(file.SectionHeaders)) != got.SectionHeaderCount {
		t.Fatalf("section table incomplete: %d of %d", len(file.SectionHeaders), got.SectionHeaderCount)
	}
	if uint64(len(file.ProgramHeaders)) != got.ProgramHeaderCount {
		t.Fatalf("program table incomplete: %d of %d", len(file.ProgramHeaders), got.ProgramHeaderCount)
	}
}

func compareSections(t *testing.T, got []reeelf.SectionHeader, want []*elf.Section) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("section count = %d, want %d", len(got), len(want))
	}
	for i := range got {
		label := fmt.Sprintf("section %d", i)
		w := want[i].SectionHeader
		g := got[i]
		if g.Type != uint32(w.Type) || g.Flags != uint64(w.Flags) {
			t.Fatalf("%s type/flags = %d/%#x, want %d/%#x",
				label, g.Type, g.Flags, uint32(w.Type), uint64(w.Flags))
		}
		if g.Address != w.Addr || g.Offset != w.Offset || g.Size != w.Size {
			t.Fatalf("%s address/offset/size = %#x/%#x/%#x, want %#x/%#x/%#x",
				label, g.Address, g.Offset, g.Size, w.Addr, w.Offset, w.Size)
		}
		if g.Link != w.Link || g.Info != w.Info {
			t.Fatalf("%s link/info = %d/%d, want %d/%d", label, g.Link, g.Info, w.Link, w.Info)
		}
		if g.AddressAlign != w.Addralign || g.EntrySize != w.Entsize {
			t.Fatalf("%s alignment/entry size = %d/%d, want %d/%d",
				label, g.AddressAlign, g.EntrySize, w.Addralign, w.Entsize)
		}
	}
}

func comparePrograms(t *testing.T, got []reeelf.ProgramHeader, want []*elf.Prog) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("program count = %d, want %d", len(got), len(want))
	}
	for i := range got {
		label := fmt.Sprintf("program %d", i)
		w := want[i].ProgHeader
		g := got[i]
		if g.Type != uint32(w.Type) || g.Flags != uint32(w.Flags) {
			t.Fatalf("%s type/flags = %d/%#x, want %d/%#x",
				label, g.Type, g.Flags, uint32(w.Type), uint32(w.Flags))
		}
		if g.Offset != w.Off || g.VirtualAddress != w.Vaddr || g.PhysicalAddress != w.Paddr {
			t.Fatalf("%s offsets/addresses = %#x/%#x/%#x, want %#x/%#x/%#x",
				label, g.Offset, g.VirtualAddress, g.PhysicalAddress, w.Off, w.Vaddr, w.Paddr)
		}
		if g.FileSize != w.Filesz || g.MemorySize != w.Memsz || g.Align != w.Align {
			t.Fatalf("%s sizes/alignment = %#x/%#x/%#x, want %#x/%#x/%#x",
				label, g.FileSize, g.MemorySize, g.Align, w.Filesz, w.Memsz, w.Align)
		}
	}
}
