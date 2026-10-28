package archive

import (
	"bytes"
	"errors"
	"fmt"

	rearchive "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/archive"
)

const (
	// DefaultNestedDepth inspects one container level below the artifact.
	DefaultNestedDepth = 1
	// MaxNestedDepth is the deepest container level that is inspected.
	MaxNestedDepth = 2
	// DefaultNestedBytes bounds the total entry bytes decoded for nested
	// detection.
	DefaultNestedBytes int64 = 64 << 20
	// MinNestedBytes is the smallest configurable nested byte budget.
	MinNestedBytes int64 = 1 << 20
	// MaxNestedBytes is the largest configurable nested byte budget.
	MaxNestedBytes int64 = rearchive.MaxArtifactBytes
	// DefaultNestedMembers bounds how many entries are parsed as containers.
	DefaultNestedMembers = 256
	// MaxNestedMembers is the largest configurable nested member count.
	MaxNestedMembers = 4096

	// entryShare and nestedShare divide the payload budget when nested
	// detection is enabled. Without nesting every entry gets the whole budget.
	entryShare  = 65
	nestedShare = 35

	// detectPrefixBytes is enough for the reader's Detect, which needs 263
	// bytes to see the tar magic at offset 257.
	detectPrefixBytes = 263

	statusParsed = "parsed"
)

// buildPayload projects the reader inventory into a payload and attaches the
// nested containers it can afford to inspect.
func buildPayload(source *rearchive.Archive, opts Options, notes *collector) Payload {
	size := int64String(source.Size())
	payload := Payload{
		Schema:   PayloadSchema,
		Artifact: projectArchive(source, 0, &size, statusParsed),
	}
	for _, limitation := range source.Limitations {
		notes.addLimitation(limitation)
	}
	if source.Truncated {
		notes.addLimitation("artifact inventory is partial")
	}

	budget := newPayloadBudget(opts.PayloadBytes)
	budget.reserve(jsonSize(payload.Artifact) + len(PayloadSchema) + 64)

	share := 100
	if opts.NestedDepth > 0 {
		share = entryShare
	}
	budget.start(share)
	for index := range source.Entries {
		entry := projectEntry(source.Entries[index])
		cost := jsonSize(entry)
		if !budget.fits(cost) {
			notes.addLimitation(fmt.Sprintf("payload budget omits entries after %d of %d",
				len(payload.Entries), len(source.Entries)))
			break
		}
		budget.add(cost)
		payload.Entries = append(payload.Entries, entry)
	}
	budget.finish()
	payload.Artifact.LoadedEntryCount = len(payload.Entries)

	if opts.NestedDepth > 0 {
		state := &nestedState{remaining: opts.NestedBytes, members: opts.NestedMembers}
		budget.start(nestedShare)
		attachNested(source, payload.Entries, 0, opts, state, budget, notes)
		budget.finish()
	}
	return payload
}

// nestedState bounds the work nested detection may perform. It is shared by
// every nesting level so the whole payload stays inside one budget.
type nestedState struct {
	// remaining is the entry bytes still allowed for nested decoding.
	remaining int64
	// members is the number of nested containers still allowed.
	members int
	// stopped records that a budget stopped further inspection.
	stopped bool
}

// nestedCandidate reports whether an entry could hold a container. Links,
// devices, directories, encrypted entries, and unsupported methods are skipped:
// their bytes are not a container this adapter can parse.
func nestedCandidate(entry rearchive.Entry) bool {
	if entry.Type != rearchive.EntryFile || entry.NameUnsafe != "" || entry.Encrypted {
		return false
	}
	return entry.Method == rearchive.MethodStored || entry.Method == rearchive.MethodDeflate
}

// attachNested walks the projected entries of one container and fills in the
// nested view of every entry that holds another container. Entries are visited
// in container order so the payload is deterministic.
func attachNested(source *rearchive.Archive, entries []PayloadEntry, depth int, opts Options,
	state *nestedState, budget *payloadBudget, notes *collector) {
	if depth >= opts.NestedDepth {
		return
	}
	for i := range entries {
		if state.stopped {
			return
		}
		entry := source.Entries[entries[i].Index]
		if !nestedCandidate(entry) {
			continue
		}
		prefix, err := source.EntryPrefix(entry.Index, detectPrefixBytes)
		if err != nil {
			notes.addLimitation(fmt.Sprintf("entry %d nested detection skipped: %s",
				entry.Index, sentinelStatus(err)))
			continue
		}
		container := rearchive.Detect(prefix)
		if container == rearchive.ContainerUnknown {
			continue
		}
		if entry.UncompressedSizeKnown && entry.UncompressedSize > uint64(state.remaining) {
			state.stopped = true
			notes.addLimitation(fmt.Sprintf(
				"nested byte budget %d is exhausted before entry %d declares %d bytes",
				opts.NestedBytes, entry.Index, entry.UncompressedSize))
			return
		}
		if state.members == 0 {
			state.stopped = true
			notes.addLimitation(fmt.Sprintf("nested member limit %d reached at entry %d",
				opts.NestedMembers, entry.Index))
			return
		}
		state.members--

		nested := &PayloadArchive{
			Depth:     depth + 1,
			Container: container.String(),
			Status:    statusParsed,
		}
		data, err := source.EntryData(entry.Index)
		if err != nil {
			nested.Status = sentinelStatus(err)
			nested.Limitations = append(nested.Limitations, err.Error())
			notes.addLimitation(fmt.Sprintf("entry %d nested %s is unavailable: %s",
				entry.Index, nested.Container, nested.Status))
			entries[i].Nested = nested
			continue
		}
		if int64(len(data)) > state.remaining {
			nested.Status = "limit"
			nested.Limitations = append(nested.Limitations,
				fmt.Sprintf("decoded member is %d bytes, nested budget has %d", len(data), state.remaining))
			notes.addLimitation(fmt.Sprintf("entry %d nested member exceeds the nested byte budget",
				entry.Index))
			state.stopped = true
			entries[i].Nested = nested
			continue
		}
		state.remaining -= int64(len(data))

		child, err := rearchive.ParseWithLimits(bytes.NewReader(data), int64(len(data)), opts.Limits)
		if err != nil {
			nested.Status = sentinelStatus(err)
			nested.Limitations = append(nested.Limitations, err.Error())
			notes.addLimitation(fmt.Sprintf("entry %d nested %s is %s",
				entry.Index, nested.Container, nested.Status))
			entries[i].Nested = nested
			continue
		}

		view := projectArchive(child, depth+1, nil, statusParsed)
		for _, limitation := range child.Limitations {
			notes.addLimitation(fmt.Sprintf("entry %d nested: %s", entry.Index, limitation))
		}
		if child.Truncated {
			notes.addLimitation(fmt.Sprintf("entry %d nested inventory is partial", entry.Index))
		}
		cost := jsonSize(view)
		if !budget.fits(cost) {
			notes.addLimitation(fmt.Sprintf("payload budget omits the nested container in entry %d",
				entry.Index))
			continue
		}
		budget.add(cost)
		view.Entries = buildNestedEntries(child, depth+1, budget, notes)
		view.LoadedEntryCount = len(view.Entries)
		attachNested(child, view.Entries, depth+1, opts, state, budget, notes)
		entries[i].Nested = &view
	}
}

// buildNestedEntries projects a nested container's entries against the shared
// payload budget.
func buildNestedEntries(source *rearchive.Archive, depth int, budget *payloadBudget,
	notes *collector) []PayloadEntry {
	entries := make([]PayloadEntry, 0, len(source.Entries))
	for index := range source.Entries {
		entry := projectEntry(source.Entries[index])
		cost := jsonSize(entry)
		if !budget.fits(cost) {
			notes.addLimitation(fmt.Sprintf(
				"payload budget omits nested entries after %d of %d at depth %d",
				len(entries), len(source.Entries), depth))
			break
		}
		budget.add(cost)
		entries = append(entries, entry)
	}
	return entries
}

// sentinelStatus names the reader sentinel that stopped a parse.
func sentinelStatus(err error) string {
	switch {
	case errors.Is(err, rearchive.ErrInvalid):
		return "invalid"
	case errors.Is(err, rearchive.ErrTruncated):
		return "truncated"
	case errors.Is(err, rearchive.ErrLimit):
		return "limit"
	case errors.Is(err, rearchive.ErrUnavailable):
		return "unavailable"
	case errors.Is(err, rearchive.ErrRead):
		return "read"
	default:
		return "unknown"
	}
}
