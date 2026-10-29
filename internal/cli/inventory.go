package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mrsandipmandal/reverse-engineer-everything/internal/usecase/analyze"
	"github.com/mrsandipmandal/reverse-engineer-everything/internal/usecase/inventory"
	"github.com/mrsandipmandal/reverse-engineer-everything/internal/version"
)

// inventoryView is the JSON projection of one inventory page.
type inventoryView struct {
	Artifact string         `json:"artifact"`
	Format   string         `json:"format"`
	Schema   string         `json:"schema"`
	Page     inventory.Page `json:"page"`
}

// searchView is the JSON projection of one filtered inventory page.
type searchView struct {
	Artifact string         `json:"artifact"`
	Query    string         `json:"query"`
	Format   string         `json:"format"`
	Schema   string         `json:"schema"`
	Page     inventory.Page `json:"page"`
}

// sideView names one input of a comparison.
type sideView struct {
	Artifact string `json:"artifact"`
	Format   string `json:"format"`
	Schema   string `json:"schema"`
}

// changePage is one page of changed entries.
type changePage struct {
	Offset     int                `json:"offset"`
	Limit      int                `json:"limit"`
	Total      int                `json:"total"`
	Changes    []inventory.Change `json:"changes"`
	NextOffset *int               `json:"next_offset"`
}

// compareView is the JSON projection of one comparison.
type compareView struct {
	Left    sideView       `json:"left"`
	Right   sideView       `json:"right"`
	Added   inventory.Page `json:"added"`
	Removed inventory.Page `json:"removed"`
	Changed changePage     `json:"changed"`
}

// pageFlags are the options shared by the inventory views.
type pageFlags struct {
	jsonOutput bool
	format     string
	maxBytes   int64
	offset     int
	limit      int
}

// addPageFlags registers the flags shared by inventory and search.
func addPageFlags(fs *flag.FlagSet, values *pageFlags) {
	fs.BoolVar(&values.jsonOutput, "json", false, "print the view as JSON")
	fs.StringVar(&values.format, "format", analyze.FormatAuto,
		"artifact format: auto, zip, tar, gzip, apk, asar, or plist")
	fs.Int64Var(&values.maxBytes, "max-bytes", 0,
		"maximum artifact size in bytes; 0 uses the built-in limit")
	addWindowFlags(fs, values)
}

// addWindowFlags registers only the pagination flags.
func addWindowFlags(fs *flag.FlagSet, values *pageFlags) {
	fs.IntVar(&values.offset, "offset", 0, "index of the first item to print")
	fs.IntVar(&values.limit, "limit", inventory.DefaultPageLimit,
		fmt.Sprintf("maximum items to print, 1..%d", inventory.MaxPageLimit))
}

func runInventory(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if err := ctx.Err(); err != nil {
		_, _ = fmt.Fprintf(stderr, "ree: %v\n", err)
		return ExitFailure
	}

	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var values pageFlags
	addPageFlags(fs, &values)
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr,
			"Usage: ree inventory <path> [--json] [--format auto|zip|tar|gzip|apk|asar|plist] [--max-bytes N] [--offset N] [--limit N]")
	}
	if err := fs.Parse(splitFlags(args, valueFlags("format", "max-bytes", "offset", "limit"))); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, "ree: inventory requires exactly one artifact path")
		return ExitUsage
	}
	if code := validateWindow(values, stderr); code != ExitOK {
		return code
	}

	collection, code := buildCollection(ctx, fs.Arg(0), values, stderr)
	if collection == nil {
		return code
	}
	page, err := collection.Page(values.offset, values.limit)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "ree: %v\n", err)
		return ExitUsage
	}
	if values.jsonOutput {
		return encodeView(stdout, stderr, inventoryView{
			Artifact: filepath.Base(fs.Arg(0)),
			Format:   collection.Format,
			Schema:   collection.Schema,
			Page:     page,
		})
	}
	printInventory(stdout, fs.Arg(0), collection, page)
	return ExitOK
}

func runSearch(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if err := ctx.Err(); err != nil {
		_, _ = fmt.Fprintf(stderr, "ree: %v\n", err)
		return ExitFailure
	}

	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var values pageFlags
	addPageFlags(fs, &values)
	query := fs.String("query", "", "case-insensitive name substring to keep")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr,
			"Usage: ree search <path> --query TEXT [--json] [--format auto|zip|tar|gzip|apk|asar|plist] [--max-bytes N] [--offset N] [--limit N]")
	}
	flags := valueFlags("format", "max-bytes", "offset", "limit", "query")
	if err := fs.Parse(splitFlags(args, flags)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, "ree: search requires exactly one artifact path")
		return ExitUsage
	}
	if strings.TrimSpace(*query) == "" {
		_, _ = fmt.Fprintln(stderr, "ree: search requires --query")
		return ExitUsage
	}
	if code := validateWindow(values, stderr); code != ExitOK {
		return code
	}

	collection, code := buildCollection(ctx, fs.Arg(0), values, stderr)
	if collection == nil {
		return code
	}
	filtered, err := collection.Search(*query)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "ree: %v\n", err)
		return ExitUsage
	}
	page, err := filtered.Page(values.offset, values.limit)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "ree: %v\n", err)
		return ExitUsage
	}
	trimmed := strings.TrimSpace(*query)
	if values.jsonOutput {
		return encodeView(stdout, stderr, searchView{
			Artifact: filepath.Base(fs.Arg(0)),
			Query:    trimmed,
			Format:   filtered.Format,
			Schema:   filtered.Schema,
			Page:     page,
		})
	}
	printSearch(stdout, fs.Arg(0), trimmed, filtered, page)
	return ExitOK
}

func runCompare(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if err := ctx.Err(); err != nil {
		_, _ = fmt.Fprintf(stderr, "ree: %v\n", err)
		return ExitFailure
	}

	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var values pageFlags
	fs.BoolVar(&values.jsonOutput, "json", false, "print the comparison as JSON")
	addWindowFlags(fs, &values)
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr,
			"Usage: ree compare <left> <right> [--json] [--offset N] [--limit N]")
	}
	if err := fs.Parse(splitFlags(args, valueFlags("offset", "limit"))); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if fs.NArg() != 2 {
		_, _ = fmt.Fprintln(stderr, "ree: compare requires exactly two artifact paths")
		return ExitUsage
	}
	if code := validateWindow(values, stderr); code != ExitOK {
		return code
	}

	left, code := buildCollection(ctx, fs.Arg(0), values, stderr)
	if left == nil {
		return code
	}
	right, code := buildCollection(ctx, fs.Arg(1), values, stderr)
	if right == nil {
		return code
	}
	diff := inventory.Compare(left, right)

	added := pageOf(diff.Added, values.offset, values.limit)
	removed := pageOf(diff.Removed, values.offset, values.limit)
	changed := pageChanges(diff.Changed, values.offset, values.limit)

	if values.jsonOutput {
		return encodeView(stdout, stderr, compareView{
			Left:    sideView{Artifact: filepath.Base(fs.Arg(0)), Format: left.Format, Schema: left.Schema},
			Right:   sideView{Artifact: filepath.Base(fs.Arg(1)), Format: right.Format, Schema: right.Schema},
			Added:   added,
			Removed: removed,
			Changed: changed,
		})
	}
	printCompare(stdout, fs.Arg(0), fs.Arg(1), left, right, added, removed, changed)
	return ExitOK
}

// validateWindow rejects an out-of-range offset or limit.
func validateWindow(values pageFlags, stderr io.Writer) int {
	if values.offset < 0 {
		_, _ = fmt.Fprintln(stderr, "ree: --offset must not be negative")
		return ExitUsage
	}
	if values.limit < 1 || values.limit > inventory.MaxPageLimit {
		_, _ = fmt.Fprintf(stderr, "ree: --limit must be between 1 and %d\n", inventory.MaxPageLimit)
		return ExitUsage
	}
	return ExitOK
}

// buildCollection analyzes path and builds its inventory. A nil collection
// means the caller should return code.
func buildCollection(ctx context.Context, path string, values pageFlags, stderr io.Writer) (*inventory.Collection, int) {
	result, err := analyze.Analyze(ctx, path, analyze.Options{
		Format:          values.format,
		ProviderVersion: version.Get().Version,
		MaxBytes:        values.maxBytes,
	})
	if err != nil {
		switch {
		case errors.Is(err, analyze.ErrOptions):
			_, _ = fmt.Fprintf(stderr, "ree: %v\n", err)
			return nil, ExitUsage
		case errors.Is(err, os.ErrNotExist):
			_, _ = fmt.Fprintf(stderr, "ree: artifact not found: %s\n", path)
			return nil, ExitFailure
		default:
			_, _ = fmt.Fprintf(stderr, "ree: %v\n", err)
			return nil, ExitFailure
		}
	}

	collection, err := inventory.Build(result.Record)
	if err != nil {
		if errors.Is(err, inventory.ErrUnsupported) {
			_, _ = fmt.Fprintf(stderr,
				"ree: %s has no inventory view (ELF, PE, and Mach-O use \"ree analyze\")\n", path)
			return nil, ExitUsage
		}
		_, _ = fmt.Fprintf(stderr, "ree: %v\n", err)
		return nil, ExitFailure
	}
	return collection, ExitOK
}

// pageOf returns a page over items, reusing the inventory paging rules.
func pageOf(items []inventory.Item, offset, limit int) inventory.Page {
	collection := &inventory.Collection{Items: items}
	page, err := collection.Page(offset, limit)
	if err != nil {
		return inventory.Page{Offset: offset, Limit: limit, Items: []inventory.Item{}}
	}
	return page
}

// pageChanges returns one window of changed entries.
func pageChanges(changes []inventory.Change, offset, limit int) changePage {
	page := changePage{
		Offset:  offset,
		Limit:   limit,
		Total:   len(changes),
		Changes: []inventory.Change{},
	}
	if offset < len(changes) {
		end := offset + limit
		if end > len(changes) {
			end = len(changes)
		}
		page.Changes = append(page.Changes, changes[offset:end]...)
	}
	page.NextOffset = nextOffset(offset, limit, page.Total)
	return page
}

// nextOffset returns the first index after a full window, or nil at the end.
func nextOffset(offset, limit, total int) *int {
	next := offset + limit
	if next >= total {
		return nil
	}
	return &next
}

// encodeView writes one JSON view with two-space indentation.
func encodeView(w, stderr io.Writer, view any) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(view); err != nil {
		_, _ = fmt.Fprintf(stderr, "ree: encode view: %v\n", err)
		return ExitFailure
	}
	return ExitOK
}

func printInventory(w io.Writer, path string, collection *inventory.Collection, page inventory.Page) {
	_, _ = fmt.Fprintln(w, "REE Inventory")
	_, _ = fmt.Fprintf(w, "artifact: %s\n", filepath.Base(path))
	_, _ = fmt.Fprintf(w, "format: %s\n", collection.Format)
	_, _ = fmt.Fprintf(w, "schema: %s\n", collection.Schema)
	printPageWindow(w, page)
	printItems(w, page.Items)
	printNotes(w, "limitations", collection.Limitations)
}

func printSearch(w io.Writer, path, query string, collection *inventory.Collection, page inventory.Page) {
	_, _ = fmt.Fprintln(w, "REE Search")
	_, _ = fmt.Fprintf(w, "artifact: %s\n", filepath.Base(path))
	_, _ = fmt.Fprintf(w, "query: %s\n", query)
	_, _ = fmt.Fprintf(w, "format: %s\n", collection.Format)
	printPageWindow(w, page)
	printItems(w, page.Items)
	printNotes(w, "limitations", collection.Limitations)
}

func printCompare(w io.Writer, leftPath, rightPath string, left, right *inventory.Collection,
	added, removed inventory.Page, changed changePage) {
	_, _ = fmt.Fprintln(w, "REE Compare")
	_, _ = fmt.Fprintf(w, "left: %s (%s)\n", filepath.Base(leftPath), left.Format)
	_, _ = fmt.Fprintf(w, "right: %s (%s)\n", filepath.Base(rightPath), right.Format)
	_, _ = fmt.Fprintf(w, "added: %d\n", added.Total)
	printItems(w, added.Items)
	_, _ = fmt.Fprintf(w, "removed: %d\n", removed.Total)
	printItems(w, removed.Items)
	_, _ = fmt.Fprintf(w, "changed: %d\n", changed.Total)
	for _, change := range changed.Changes {
		_, _ = fmt.Fprintf(w, "  %s\n", change.Name)
		printItemDiff(w, "left", change.Left)
		printItemDiff(w, "right", change.Right)
	}
	printNotes(w, "left limitations", left.Limitations)
	printNotes(w, "right limitations", right.Limitations)
}

func printPageWindow(w io.Writer, page inventory.Page) {
	_, _ = fmt.Fprintf(w, "total: %d\n", page.Total)
	_, _ = fmt.Fprintf(w, "page: offset=%d limit=%d returned=%d\n",
		page.Offset, page.Limit, len(page.Items))
	if page.NextOffset != nil {
		_, _ = fmt.Fprintf(w, "next: --offset %d --limit %d\n", *page.NextOffset, page.Limit)
	}
}

func printItems(w io.Writer, items []inventory.Item) {
	if len(items) == 0 {
		_, _ = fmt.Fprintln(w, "items: none")
		return
	}
	for _, item := range items {
		_, _ = fmt.Fprintf(w, "  [%d] %s%s\n", item.Index, itemName(item), itemDetails(item))
	}
}

func printItemDiff(w io.Writer, label string, item inventory.Item) {
	_, _ = fmt.Fprintf(w, "    %s: %s%s\n", label, itemName(item), itemDetails(item))
}

// itemName is the decoded name, or a placeholder for an undecodable one.
func itemName(item inventory.Item) string {
	if item.NameAvailable && item.Name != "" {
		return item.Name
	}
	return fmt.Sprintf("<unavailable #%d>", item.Index)
}

// itemDetails renders the non-name fields of one item on the same line.
func itemDetails(item inventory.Item) string {
	var out strings.Builder
	_, _ = fmt.Fprintf(&out, " kind=%s", item.Kind)
	if item.Size != nil {
		_, _ = fmt.Fprintf(&out, " size=%d", *item.Size)
	}
	if item.Depth != 0 {
		_, _ = fmt.Fprintf(&out, " depth=%d", item.Depth)
	}
	if item.Unsafe != "" {
		_, _ = fmt.Fprintf(&out, " unsafe=%q", item.Unsafe)
	}
	if item.DigestAvailable {
		_, _ = fmt.Fprintf(&out, " sha256=%s", item.Digest)
	}
	return out.String()
}

// valueFlagsOf builds the set of flags whose value follows the flag name.
func valueFlags(names ...string) map[string]struct{} {
	flags := make(map[string]struct{}, len(names)*2)
	for _, name := range names {
		flags["-"+name] = struct{}{}
		flags["--"+name] = struct{}{}
	}
	return flags
}
