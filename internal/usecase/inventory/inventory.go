// Package inventory turns an archive, package, or property list record into a
// flat, paginated list of names.
//
// A collection is derived from one sealed ree.evidence/1 record. The reader
// that produced the record already bounded the artifact, so this package only
// projects the payload: it never opens, parses, or extracts the artifact again.
// A nested archive member is flattened with its depth, so a caller sees one
// deterministic list rather than a tree it has to walk.
//
// Executable formats keep their own tables and are reported as unsupported:
// an inventory is a name list, and ELF, PE, and Mach-O do not have one.
package inventory

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/contracts/evidence"
)

// Page limits.
const (
	// DefaultPageLimit is used when a caller does not ask for a page size.
	DefaultPageLimit = 50
	// MaxPageLimit bounds one page.
	MaxPageLimit = 1000
)

// Payload schemas this package understands.
const (
	SchemaArchive = "ree.payload.archive/1"
	SchemaASAR    = "ree.payload.asar/1"
	SchemaAPK     = "ree.payload.apk/1"
	SchemaPlist   = "ree.payload.plist/1"
)

// Sentinel errors.
var (
	// ErrUnsupported reports a record whose payload has no inventory view.
	ErrUnsupported = errors.New("inventory: payload has no inventory view")
	// ErrQuery reports a search query that is empty after trimming.
	ErrQuery = errors.New("inventory: query is empty")
	// ErrPage reports a negative offset or a limit outside 1..MaxPageLimit.
	ErrPage = errors.New("inventory: invalid page")
)

// Item is one entry in a collection.
type Item struct {
	// Index is the position in the source inventory.
	Index int `json:"index"`
	// Kind is the reader's name for the entry: an archive type, an APK kind, a
	// property list type, or an ASAR node type.
	Kind string `json:"kind"`
	// Name is the decoded name. It is empty when NameAvailable is false.
	Name string `json:"name"`
	// NameAvailable reports that the reader decoded the name.
	NameAvailable bool `json:"name_available"`
	// Unsafe states why a path cannot be used, empty when it can.
	Unsafe string `json:"unsafe"`
	// Size is the declared uncompressed size, or the compressed size when the
	// reader did not know the uncompressed one.
	Size *int64 `json:"size"`
	// Digest is the lowercase hexadecimal content digest when the reader
	// computed one.
	Digest string `json:"digest"`
	// DigestAvailable reports that Digest covers the entry content.
	DigestAvailable bool `json:"digest_available"`
	// Depth is zero for a top-level entry and increases inside a nested archive.
	Depth int `json:"depth"`
	// Limitations states why this entry's view is incomplete.
	Limitations []string `json:"limitations"`
}

// Collection is the flat inventory of one record.
type Collection struct {
	// Schema is the payload schema the collection was derived from.
	Schema string `json:"schema"`
	// Format is the artifact format reported by the provider.
	Format string `json:"format"`
	// Items are the entries in source order.
	Items []Item `json:"items"`
	// Limitations states why the inventory itself is incomplete.
	Limitations []string `json:"limitations"`
}

// Page is one deterministic window over a collection.
type Page struct {
	// Offset is the requested start index.
	Offset int `json:"offset"`
	// Limit is the effective page size.
	Limit int `json:"limit"`
	// Total is the number of items in the collection.
	Total int `json:"total"`
	// Items are the entries in source order.
	Items []Item `json:"items"`
	// NextOffset is the start of the next page, nil on the last page.
	NextOffset *int `json:"next_offset"`
}

// CompareResult lists the differences between two collections by name.
type CompareResult struct {
	// Added are names present only on the right.
	Added []Item `json:"added"`
	// Removed are names present only on the left.
	Removed []Item `json:"removed"`
	// Changed are names present on both sides with a different kind, size, or
	// digest. Left is the item from the first collection, Right the second.
	Changed []Change `json:"changed"`
}

// Change is one name whose metadata differs between two collections.
type Change struct {
	// Name is the comparison key.
	Name string `json:"name"`
	// Left is the item from the first collection.
	Left Item `json:"left"`
	// Right is the item from the second collection.
	Right Item `json:"right"`
}

// Build projects a sealed record into a flat inventory.
//
// A record whose payload schema is not one of the four archive-family schemas
// returns ErrUnsupported; the executable readers keep their own tables.
func Build(rec evidence.Evidence) (*Collection, error) {
	var header struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(rec.Payload, &header); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsupported, err)
	}
	var collection *Collection
	var err error
	switch header.Schema {
	case SchemaArchive:
		collection, err = buildArchive(rec.Payload)
	case SchemaASAR:
		collection, err = buildASAR(rec.Payload)
	case SchemaAPK:
		collection, err = buildAPK(rec.Payload)
	case SchemaPlist:
		collection, err = buildPlist(rec.Payload)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupported, header.Schema)
	}
	if err != nil {
		return nil, err
	}
	collection.Limitations = append(collection.Limitations, rec.Limitations...)
	return collection, nil
}

// Page returns one window of the collection.
func (c *Collection) Page(offset, limit int) (Page, error) {
	if offset < 0 {
		return Page{}, fmt.Errorf("%w: negative offset %d", ErrPage, offset)
	}
	if limit <= 0 || limit > MaxPageLimit {
		return Page{}, fmt.Errorf("%w: limit %d is outside 1..%d", ErrPage, limit, MaxPageLimit)
	}
	if c == nil {
		return Page{}, fmt.Errorf("%w: nil collection", ErrPage)
	}
	page := Page{Offset: offset, Limit: limit, Total: len(c.Items), Items: []Item{}}
	if offset >= len(c.Items) {
		return page, nil
	}
	end := offset + limit
	if end > len(c.Items) {
		end = len(c.Items)
	}
	page.Items = append(page.Items, c.Items[offset:end]...)
	if end < len(c.Items) {
		next := end
		page.NextOffset = &next
	}
	return page, nil
}

// Search returns the items whose name contains query, ignoring ASCII case.
// An empty or whitespace-only query returns ErrQuery.
func (c *Collection) Search(query string) (*Collection, error) {
	trimmed := strings.TrimSpace(query)
	if trimmed == "" {
		return nil, ErrQuery
	}
	folded := strings.ToLower(trimmed)
	out := &Collection{Schema: c.Schema, Format: c.Format, Items: []Item{}}
	out.Limitations = append(out.Limitations, c.Limitations...)
	for _, item := range c.Items {
		if !item.NameAvailable {
			continue
		}
		if strings.Contains(strings.ToLower(item.Name), folded) {
			out.Items = append(out.Items, item)
		}
	}
	return out, nil
}

// Compare lists the names added, removed, or changed between two collections.
// Items are matched by name; an item without a name is keyed by its index so it
// is still comparable. The output is sorted by name.
func Compare(left, right *Collection) CompareResult {
	result := CompareResult{Added: []Item{}, Removed: []Item{}, Changed: []Change{}}
	leftByKey := keyed(left)
	rightByKey := keyed(right)

	for key, item := range rightByKey {
		other, ok := leftByKey[key]
		switch {
		case !ok:
			result.Added = append(result.Added, item)
		case differs(other, item):
			result.Changed = append(result.Changed, Change{Name: key, Left: other, Right: item})
		}
	}
	for key, item := range leftByKey {
		if _, ok := rightByKey[key]; !ok {
			result.Removed = append(result.Removed, item)
		}
	}
	sort.Slice(result.Added, func(i, j int) bool { return keyOf(result.Added[i]) < keyOf(result.Added[j]) })
	sort.Slice(result.Removed, func(i, j int) bool { return keyOf(result.Removed[i]) < keyOf(result.Removed[j]) })
	sort.Slice(result.Changed, func(i, j int) bool { return result.Changed[i].Name < result.Changed[j].Name })
	return result
}

func keyed(collection *Collection) map[string]Item {
	out := make(map[string]Item)
	if collection == nil {
		return out
	}
	for _, item := range collection.Items {
		out[keyOf(item)] = item
	}
	return out
}

func keyOf(item Item) string {
	if item.NameAvailable && item.Name != "" {
		return item.Name
	}
	return "#" + strconv.Itoa(item.Index)
}

func differs(left, right Item) bool {
	if left.Kind != right.Kind || left.Name != right.Name || left.Depth != right.Depth {
		return true
	}
	if left.DigestAvailable != right.DigestAvailable {
		return true
	}
	if left.DigestAvailable && left.Digest != right.Digest {
		return true
	}
	if (left.Size == nil) != (right.Size == nil) {
		return true
	}
	return left.Size != nil && *left.Size != *right.Size
}

// archivePayload mirrors the subset of ree.payload.archive/1 needed here.
type archivePayload struct {
	Schema   string `json:"schema"`
	Artifact struct {
		Container string `json:"container"`
	} `json:"artifact"`
	Entries []archivePayloadEntry `json:"entries"`
}

type archivePayloadEntry struct {
	Index            int             `json:"index"`
	Name             string          `json:"name"`
	NameAvailable    bool            `json:"name_available"`
	Unsafe           string          `json:"unsafe"`
	Type             string          `json:"type"`
	CompressedSize   *string         `json:"compressed_size"`
	UncompressedSize *string         `json:"uncompressed_size"`
	Limitations      []string        `json:"limitations"`
	Nested           *archivePayload `json:"nested"`
}

func buildArchive(payload json.RawMessage) (*Collection, error) {
	var decoded archivePayload
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return nil, fmt.Errorf("decode %s payload: %w", SchemaArchive, err)
	}
	format := decoded.Artifact.Container
	if format == "" {
		format = "archive"
	}
	out := &Collection{Schema: SchemaArchive, Format: format, Items: []Item{}}
	flattenArchive(out, decoded.Entries, 0)
	return out, nil
}

func flattenArchive(out *Collection, entries []archivePayloadEntry, depth int) {
	for _, entry := range entries {
		out.Items = append(out.Items, Item{
			Index:         entry.Index,
			Kind:          entry.Type,
			Name:          entry.Name,
			NameAvailable: entry.NameAvailable,
			Unsafe:        entry.Unsafe,
			Size:          sizeOf(entry.UncompressedSize, entry.CompressedSize),
			Depth:         depth,
			Limitations:   entry.Limitations,
		})
		if entry.Nested != nil {
			flattenArchive(out, entry.Nested.Entries, depth+1)
		}
	}
}

type asarPayload struct {
	Schema  string `json:"schema"`
	Entries []struct {
		Index         int      `json:"index"`
		Path          string   `json:"path"`
		PathAvailable bool     `json:"path_available"`
		Unsafe        string   `json:"unsafe"`
		Type          string   `json:"type"`
		Size          *string  `json:"size"`
		Limitations   []string `json:"limitations"`
	} `json:"entries"`
}

func buildASAR(payload json.RawMessage) (*Collection, error) {
	var decoded asarPayload
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return nil, fmt.Errorf("decode %s payload: %w", SchemaASAR, err)
	}
	out := &Collection{Schema: SchemaASAR, Format: "asar", Items: []Item{}}
	for _, entry := range decoded.Entries {
		out.Items = append(out.Items, Item{
			Index:         entry.Index,
			Kind:          entry.Type,
			Name:          entry.Path,
			NameAvailable: entry.PathAvailable,
			Unsafe:        entry.Unsafe,
			Size:          sizeOf(entry.Size, nil),
			Limitations:   entry.Limitations,
		})
	}
	return out, nil
}

type apkPayload struct {
	Schema  string `json:"schema"`
	Entries []struct {
		Index            int      `json:"index"`
		Name             string   `json:"name"`
		NameAvailable    bool     `json:"name_available"`
		Unsafe           string   `json:"unsafe"`
		Kind             string   `json:"kind"`
		CompressedSize   *string  `json:"compressed_size"`
		UncompressedSize *string  `json:"uncompressed_size"`
		Digest           *string  `json:"digest"`
		DigestAvailable  bool     `json:"digest_available"`
		Limitations      []string `json:"limitations"`
	} `json:"entries"`
}

func buildAPK(payload json.RawMessage) (*Collection, error) {
	var decoded apkPayload
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return nil, fmt.Errorf("decode %s payload: %w", SchemaAPK, err)
	}
	out := &Collection{Schema: SchemaAPK, Format: "apk", Items: []Item{}}
	for _, entry := range decoded.Entries {
		item := Item{
			Index:           entry.Index,
			Kind:            entry.Kind,
			Name:            entry.Name,
			NameAvailable:   entry.NameAvailable,
			Unsafe:          entry.Unsafe,
			Size:            sizeOf(entry.UncompressedSize, entry.CompressedSize),
			DigestAvailable: entry.DigestAvailable,
			Limitations:     entry.Limitations,
		}
		if entry.Digest != nil {
			item.Digest = *entry.Digest
		}
		out.Items = append(out.Items, item)
	}
	return out, nil
}

type plistPayload struct {
	Schema  string `json:"schema"`
	Objects []struct {
		Index         int      `json:"index"`
		Type          string   `json:"type"`
		Text          string   `json:"text"`
		TextAvailable bool     `json:"text_available"`
		Depth         int      `json:"depth"`
		Limitations   []string `json:"limitations"`
	} `json:"objects"`
}

func buildPlist(payload json.RawMessage) (*Collection, error) {
	var decoded plistPayload
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return nil, fmt.Errorf("decode %s payload: %w", SchemaPlist, err)
	}
	out := &Collection{Schema: SchemaPlist, Format: "plist", Items: []Item{}}
	for _, object := range decoded.Objects {
		item := Item{
			Index:       object.Index,
			Kind:        object.Type,
			Depth:       object.Depth,
			Limitations: object.Limitations,
		}
		if object.TextAvailable {
			item.Name = object.Text
			item.NameAvailable = true
		}
		out.Items = append(out.Items, item)
	}
	return out, nil
}

// sizeOf returns the first decimal size that parses.
func sizeOf(values ...*string) *int64 {
	for _, value := range values {
		if value == nil {
			continue
		}
		parsed, err := strconv.ParseInt(*value, 10, 64)
		if err != nil || parsed < 0 {
			continue
		}
		return &parsed
	}
	return nil
}
