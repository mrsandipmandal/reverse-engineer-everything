package pe_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	repe "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/pe"
)

func sampleResourceTree() *resourceDir {
	return &resourceDir{children: []resourceChild{
		{id: 3, dir: &resourceDir{children: []resourceChild{
			{name: "CURSOR", dir: &resourceDir{children: []resourceChild{
				{id: 1033, leaf: &resourceLeaf{blob: []byte("cursor"), codePage: 1252}},
			}}},
			{id: 7, dir: &resourceDir{children: []resourceChild{
				{id: 1033, leaf: &resourceLeaf{blob: []byte("seven")}},
			}}},
		}}},
		{id: 24, dir: &resourceDir{children: []resourceChild{
			{id: 1, dir: &resourceDir{children: []resourceChild{
				{id: 1033, leaf: &resourceLeaf{blob: []byte("manifest")}},
			}}},
		}}},
	}}
}

func TestResources(t *testing.T) {
	t.Parallel()

	for _, magic := range []uint16{repe.MagicPE32, repe.MagicPE32P} {
		magic := magic
		t.Run(magicName(t, magic), func(t *testing.T) {
			t.Parallel()

			file := parseImage(t, buildResourceImage(t, magic, sampleResourceTree()))
			table, err := file.Resources()
			if err != nil {
				t.Fatalf("Resources() error = %v", err)
			}
			if table.Truncated || len(table.Limitations) != 0 {
				t.Fatalf("truncated = %t, limitations = %v", table.Truncated, table.Limitations)
			}
			if len(table.Resources) != 3 {
				t.Fatalf("resource count = %d", len(table.Resources))
			}

			cursor := table.Resources[0]
			if len(cursor.Path) != 3 {
				t.Fatalf("path = %+v", cursor.Path)
			}
			if got := cursor.Path[0]; got.IsName || got.ID != 3 {
				t.Fatalf("path[0] = %+v", got)
			}
			if got := cursor.Path[1]; !got.IsName || !got.NameAvailable || got.Name != "CURSOR" {
				t.Fatalf("path[1] = %+v", got)
			}
			if got := cursor.Path[2]; got.IsName || got.ID != 1033 {
				t.Fatalf("path[2] = %+v", got)
			}
			if cursor.DataSize != 6 || cursor.CodePage != 1252 || !cursor.DataAvailable {
				t.Fatalf("cursor = %+v", cursor)
			}

			seven := table.Resources[1]
			if seven.Path[1].ID != 7 || seven.DataSize != 5 || seven.CodePage != 0 {
				t.Fatalf("seven = %+v", seven)
			}

			manifest := table.Resources[2]
			if manifest.Path[0].ID != 24 || manifest.DataSize != 8 || !manifest.DataAvailable {
				t.Fatalf("manifest = %+v", manifest)
			}
			if manifest.DataRVA == 0 {
				t.Fatal("manifest data RVA is zero")
			}
			if mapping := file.MapRVA(manifest.DataRVA); !mapping.FileBacked {
				t.Fatalf("manifest data mapping = %+v", mapping)
			}
		})
	}
}

func TestResourcesEmptyAndErrors(t *testing.T) {
	t.Parallel()

	t.Run("empty root", func(t *testing.T) {
		t.Parallel()

		file := parseImage(t, buildResourceImage(t, repe.MagicPE32, &resourceDir{}))
		table, err := file.Resources()
		if err != nil {
			t.Fatalf("Resources() error = %v", err)
		}
		if len(table.Resources) != 0 || table.Truncated || len(table.Limitations) != 0 {
			t.Fatalf("table = %+v", table)
		}
	})

	t.Run("absent", func(t *testing.T) {
		t.Parallel()

		file := parseImage(t, newMetadataImage(repe.MagicPE32))
		if _, err := file.Resources(); !errors.Is(err, repe.ErrNotFound) {
			t.Fatalf("Resources() error = %v, want ErrNotFound", err)
		}
	})

	t.Run("not loaded", func(t *testing.T) {
		t.Parallel()

		image := buildResourceImage(t, repe.MagicPE32, sampleResourceTree())
		limits := repe.DefaultLimits()
		limits.DataDirectories = 2
		file := parseImageWithLimits(t, image, limits)
		if _, err := file.Resources(); !errors.Is(err, repe.ErrUnavailable) {
			t.Fatalf("Resources() error = %v, want ErrUnavailable", err)
		}
	})

	t.Run("contradictory directory", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.directories[2] = [2]uint32{0, 16}
		file := parseImage(t, image)
		if _, err := file.Resources(); !errors.Is(err, repe.ErrInvalid) {
			t.Fatalf("Resources() error = %v, want ErrInvalid", err)
		}
	})

	t.Run("outside artifact", func(t *testing.T) {
		t.Parallel()

		image := newMetadataImage(repe.MagicPE32)
		image.directories[2] = [2]uint32{0x9000, 64}
		file := parseImage(t, image)
		if _, err := file.Resources(); !errors.Is(err, repe.ErrUnavailable) {
			t.Fatalf("Resources() error = %v, want ErrUnavailable", err)
		}
	})
}

func TestResourcesLimits(t *testing.T) {
	t.Parallel()

	t.Run("entry limit", func(t *testing.T) {
		t.Parallel()

		image := buildResourceImage(t, repe.MagicPE32, sampleResourceTree())
		limits := repe.DefaultLimits()
		limits.ResourceEntries = 2
		file := parseImageWithLimits(t, image, limits)

		table, err := file.Resources()
		if err != nil {
			t.Fatalf("Resources() error = %v", err)
		}
		if !table.Truncated || len(table.Resources) != 0 {
			t.Fatalf("truncated = %t, resources = %d", table.Truncated, len(table.Resources))
		}
		if !hasLimitation(table.Limitations, "resource entry count exceeds limit 2") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("partial entry budget", func(t *testing.T) {
		t.Parallel()

		image := buildResourceImage(t, repe.MagicPE32, &resourceDir{children: []resourceChild{
			{id: 1, leaf: &resourceLeaf{blob: []byte("a")}},
			{id: 2, leaf: &resourceLeaf{blob: []byte("b")}},
			{id: 3, leaf: &resourceLeaf{blob: []byte("c")}},
		}})
		limits := repe.DefaultLimits()
		limits.ResourceEntries = 1
		file := parseImageWithLimits(t, image, limits)

		table, err := file.Resources()
		if err != nil {
			t.Fatalf("Resources() error = %v", err)
		}
		if !table.Truncated || len(table.Resources) != 0 {
			t.Fatalf("truncated = %t, resources = %d", table.Truncated, len(table.Resources))
		}
		if !hasLimitation(table.Limitations, "resource entry count exceeds limit 1") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("depth limit", func(t *testing.T) {
		t.Parallel()

		leaf := &resourceDir{children: []resourceChild{
			{id: 9, leaf: &resourceLeaf{blob: []byte("deep")}},
		}}
		for i := 0; i < 10; i++ {
			leaf = &resourceDir{children: []resourceChild{{id: uint32(i), dir: leaf}}}
		}
		image := buildResourceImage(t, repe.MagicPE32, leaf)
		limits := repe.DefaultLimits()
		limits.ResourceDepth = 3
		file := parseImageWithLimits(t, image, limits)

		table, err := file.Resources()
		if err != nil {
			t.Fatalf("Resources() error = %v", err)
		}
		if !table.Truncated || len(table.Resources) != 0 {
			t.Fatalf("truncated = %t, resources = %d", table.Truncated, len(table.Resources))
		}
		if !hasLimitation(table.Limitations, "resource directory nesting exceeds limit 3") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("name string limit", func(t *testing.T) {
		t.Parallel()

		image := buildResourceImage(t, repe.MagicPE32, &resourceDir{children: []resourceChild{
			{name: "LongResourceName", dir: &resourceDir{children: []resourceChild{
				{id: 1, leaf: &resourceLeaf{blob: []byte("x")}},
			}}},
		}})
		limits := repe.DefaultLimits()
		limits.StringBytes = 4
		file := parseImageWithLimits(t, image, limits)

		table, err := file.Resources()
		if err != nil {
			t.Fatalf("Resources() error = %v", err)
		}
		if len(table.Resources) != 1 {
			t.Fatalf("resource count = %d", len(table.Resources))
		}
		if table.Resources[0].Path[0].NameAvailable {
			t.Fatalf("path = %+v", table.Resources[0].Path)
		}
		if !hasLimitation(table.Limitations, "1 resource names exceed the string limit") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("name budget", func(t *testing.T) {
		t.Parallel()

		image := buildResourceImage(t, repe.MagicPE32, &resourceDir{children: []resourceChild{
			{name: "First", dir: &resourceDir{children: []resourceChild{
				{id: 1, leaf: &resourceLeaf{blob: []byte("x")}},
			}}},
			{name: "Second", dir: &resourceDir{children: []resourceChild{
				{id: 2, leaf: &resourceLeaf{blob: []byte("y")}},
			}}},
		}})
		limits := repe.DefaultLimits()
		limits.ResourceStringBytes = 8
		file := parseImageWithLimits(t, image, limits)

		table, err := file.Resources()
		if err != nil {
			t.Fatalf("Resources() error = %v", err)
		}
		if !table.Truncated {
			t.Fatal("budget exhaustion did not set Truncated")
		}
		if !hasLimitation(table.Limitations, "resource string budget exhausted") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})
}

func TestResourcesMalformed(t *testing.T) {
	t.Parallel()

	t.Run("invalid UTF-16 name", func(t *testing.T) {
		t.Parallel()

		image := buildResourceImage(t, repe.MagicPE32, &resourceDir{children: []resourceChild{
			{name: "CURSOR", dir: &resourceDir{children: []resourceChild{
				{id: 1, leaf: &resourceLeaf{blob: []byte("x")}},
			}}},
		}})
		data := image.build(t)
		needle := []byte{'C', 0, 'U', 0, 'R', 0, 'S', 0, 'O', 0, 'R', 0}
		at := bytes.Index(data, needle)
		if at < 0 {
			t.Fatal("resource name not found in fixture")
		}
		binary.LittleEndian.PutUint16(data[at:], 0xd800)

		file := parseImageData(t, data)
		table, err := file.Resources()
		if err != nil {
			t.Fatalf("Resources() error = %v", err)
		}
		if len(table.Resources) != 1 || table.Resources[0].Path[0].NameAvailable {
			t.Fatalf("resources = %+v", table.Resources)
		}
		if !hasLimitation(table.Limitations, "1 resource names are not valid UTF-16") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("declared entries beyond directory", func(t *testing.T) {
		t.Parallel()

		image := buildResourceImage(t, repe.MagicPE32, &resourceDir{children: []resourceChild{
			{id: 1, leaf: &resourceLeaf{blob: []byte("a")}},
		}})
		data := image.build(t)
		base := image.directories[2][0]
		header := image.offset(base)
		binary.LittleEndian.PutUint16(data[header+14:], 100)

		file := parseImageData(t, data)
		table, err := file.Resources()
		if err != nil {
			t.Fatalf("Resources() error = %v", err)
		}
		if !table.Truncated {
			t.Fatalf("table = %+v", table)
		}
		if !hasLimitation(table.Limitations, "resource directory at offset 0x0 declares 100 entries but only 3 fit") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("unavailable name", func(t *testing.T) {
		t.Parallel()

		image := buildResourceImage(t, repe.MagicPE32, &resourceDir{children: []resourceChild{
			{name: "Named", dir: &resourceDir{children: []resourceChild{
				{id: 1, leaf: &resourceLeaf{blob: []byte("a")}},
			}}},
		}})
		data := image.build(t)
		base := image.directories[2][0]
		entry := image.offset(base) + resourceDirectoryHeader
		binary.LittleEndian.PutUint32(data[entry:], resourceSubdirectoryFlag|(image.directories[2][1]+4))

		file := parseImageData(t, data)
		table, err := file.Resources()
		if err != nil {
			t.Fatalf("Resources() error = %v", err)
		}
		if len(table.Resources) != 1 || table.Resources[0].Path[0].NameAvailable {
			t.Fatalf("resources = %+v", table.Resources)
		}
		if !hasLimitation(table.Limitations, "1 resource names are unavailable") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("subdirectory outside directory", func(t *testing.T) {
		t.Parallel()

		image := buildResourceImage(t, repe.MagicPE32, sampleResourceTree())
		data := image.build(t)
		base := image.directories[2][0]
		entry := image.offset(base) + resourceDirectoryHeader + 4
		binary.LittleEndian.PutUint32(data[entry:], resourceSubdirectoryFlag|(image.directories[2][1]-8))

		file := parseImageData(t, data)
		table, err := file.Resources()
		if err != nil {
			t.Fatalf("Resources() error = %v", err)
		}
		if !table.Truncated || len(table.Resources) != 1 {
			t.Fatalf("truncated = %t, resources = %d", table.Truncated, len(table.Resources))
		}
		if !hasLimitation(table.Limitations, "resource subdirectory at offset") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("empty resource", func(t *testing.T) {
		t.Parallel()

		image := buildResourceImage(t, repe.MagicPE32, &resourceDir{children: []resourceChild{
			{id: 1, leaf: &resourceLeaf{}},
		}})
		file := parseImage(t, image)
		table, err := file.Resources()
		if err != nil {
			t.Fatalf("Resources() error = %v", err)
		}
		if len(table.Resources) != 1 || !table.Resources[0].DataAvailable || table.Resources[0].DataSize != 0 {
			t.Fatalf("resources = %+v", table.Resources)
		}
	})

	t.Run("cycle", func(t *testing.T) {
		t.Parallel()

		image := buildResourceImage(t, repe.MagicPE32, &resourceDir{children: []resourceChild{
			{id: 1, dir: &resourceDir{children: []resourceChild{
				{id: 2, leaf: &resourceLeaf{blob: []byte("x")}},
			}}},
		}})
		data := image.build(t)
		base := image.directories[2][0]

		// Point the root's only child at the root itself.
		entry := image.offset(base) + resourceDirectoryHeader + 4
		binary.LittleEndian.PutUint32(data[entry:], resourceSubdirectoryFlag)

		file := parseImageData(t, data)
		table, err := file.Resources()
		if err != nil {
			t.Fatalf("Resources() error = %v", err)
		}
		if !table.Truncated {
			t.Fatalf("cycle was not truncated: %+v", table)
		}
		if !hasLimitation(table.Limitations, "resource directory nesting exceeds limit") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("data entry outside directory", func(t *testing.T) {
		t.Parallel()

		image := buildResourceImage(t, repe.MagicPE32, &resourceDir{children: []resourceChild{
			{id: 1, leaf: &resourceLeaf{blob: []byte("x")}},
		}})
		data := image.build(t)
		base := image.directories[2][0]

		entry := image.offset(base) + resourceDirectoryHeader + 4
		binary.LittleEndian.PutUint32(data[entry:], image.directories[2][1]+4)

		file := parseImageData(t, data)
		table, err := file.Resources()
		if err != nil {
			t.Fatalf("Resources() error = %v", err)
		}
		if !table.Truncated || len(table.Resources) != 0 {
			t.Fatalf("truncated = %t, resources = %d", table.Truncated, len(table.Resources))
		}
		if !hasLimitation(table.Limitations, "1 resource data entries are outside the resource directory") {
			t.Fatalf("limitations = %v", table.Limitations)
		}
	})

	t.Run("data outside artifact", func(t *testing.T) {
		t.Parallel()

		image := buildResourceImage(t, repe.MagicPE32, &resourceDir{children: []resourceChild{
			{id: 1, leaf: &resourceLeaf{blob: []byte("x")}},
		}})
		base := image.directories[2][0]
		data := image.build(t)

		// The data entry lives after the root directory and its one entry.
		leafEntry := image.offset(base) + resourceDirectoryHeader + resourceEntryBytes
		binary.LittleEndian.PutUint32(data[leafEntry:], 0x9000)

		file := parseImageData(t, data)
		parsed, err := file.Resources()
		if err != nil {
			t.Fatalf("Resources() error = %v", err)
		}
		if len(parsed.Resources) != 1 || parsed.Resources[0].DataAvailable {
			t.Fatalf("resources = %+v", parsed.Resources)
		}
		if !hasLimitation(parsed.Limitations, "1 resource data ranges are not file-backed") {
			t.Fatalf("limitations = %v", parsed.Limitations)
		}
	})
}

func TestResourcesReaderFailure(t *testing.T) {
	t.Parallel()

	image := buildResourceImage(t, repe.MagicPE32, sampleResourceTree())
	data := image.build(t)

	reader := failingReader{data: data, off: metadataRawOffset}
	file, err := repe.Parse(reader, int64(len(data)))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if _, err := file.Resources(); !errors.Is(err, repe.ErrRead) {
		t.Fatalf("Resources() error = %v, want ErrRead", err)
	}
}
