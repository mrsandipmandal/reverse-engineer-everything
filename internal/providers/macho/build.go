package macho

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	remacho "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/macho"
)

// Payload shares. Each table gets a fair share of the bytes the artifact
// envelope left, so a symbol-heavy image cannot starve the section list.
const (
	shareSegments      = 20
	shareSections      = 30
	shareDylibs        = 20
	shareSymbols       = 20
	shareCodeSignature = 10
)

// Slice statuses reported in PayloadSlice.Status.
const (
	statusParsed      = "parsed"
	statusInvalid     = "invalid"
	statusTruncated   = "truncated"
	statusLimit       = "limit"
	statusUnavailable = "unavailable"
	statusRead        = "read"
)

// Load command numbers the adapter inspects but does not decode. They are
// reported as unknowns rather than silently ignored.
const (
	commandDyldInfo          uint32 = 0x22
	commandDyldInfoOnly      uint32 = 0x80000022
	commandDyldExportsTrie   uint32 = 0x80000033
	commandDyldChainedFixups uint32 = 0x80000034
)

// buildPayload projects the parsed artifact into a bounded payload.
//
// The artifact envelope is charged first, then every slice gets an equal share
// of what remains. A table that does not fit is marked truncated in the payload
// and reported as one limitation, so a consumer can tell a short view from a
// complete one.
func buildPayload(artifact *remacho.Artifact, opts Options, notes *collector) (Payload, error) {
	payload := Payload{
		Schema:   PayloadSchema,
		Artifact: payloadArtifact(artifact),
		Slices:   make([]PayloadSlice, 0, len(artifact.Slices)),
	}
	for _, note := range artifact.Limitations {
		notes.addLimitation(note)
	}
	if artifact.Truncated {
		notes.addLimitation("artifact header coverage is partial")
	}

	budget := newPayloadBudget(opts.PayloadBytes)
	budget.reserve(jsonSize(payload.Artifact) + len(payload.Schema) + 64)

	hasher := newContentHasher(opts.ContentBytes)
	remaining := len(artifact.Slices)
	for _, slice := range artifact.Slices {
		allowance := budget.remaining
		if remaining > 1 {
			allowance /= remaining
		}
		remaining--
		sub := newPayloadBudget(allowance)
		entry, err := buildSlice(slice, hasher, notes, sub)
		if err != nil {
			return Payload{}, err
		}
		budget.take(allowance - sub.remaining)
		payload.Slices = append(payload.Slices, entry)
	}

	reportHashing(hasher, notes)
	collectUnknowns(artifact, &payload, notes)
	return payload, nil
}

// payloadArtifact copies the artifact-level header.
func payloadArtifact(artifact *remacho.Artifact) PayloadArtifact {
	out := PayloadArtifact{
		Magic:      artifact.Magic,
		MagicName:  magicName(artifact.Magic),
		Fat:        artifact.Fat,
		ByteOrder:  byteOrderName(artifact.Data),
		Size:       uint64String(uint64(artifact.Size())),
		SliceCount: len(artifact.Slices),
		Truncated:  artifact.Truncated,
	}
	for _, slice := range artifact.Slices {
		if slice.File != nil {
			out.LoadedSliceCount++
		}
	}
	return out
}

// buildSlice projects one architecture image within its own budget.
func buildSlice(slice remacho.Slice, hasher *contentHasher, notes *collector, budget *payloadBudget) (PayloadSlice, error) {
	out := PayloadSlice{
		Index:       slice.Index,
		CPUType:     slice.CPUType,
		CPUSubtype:  slice.CPUSubtype,
		Offset:      uint64String(uint64(slice.Offset)),
		Size:        uint64String(uint64(slice.Size)),
		Alignment:   slice.Alignment,
		Status:      sliceStatus(slice.Err),
		Segments:    []PayloadSegment{},
		Sections:    []PayloadSection{},
		Limitations: []string{},
	}
	if slice.Err != nil {
		if errors.Is(slice.Err, remacho.ErrRead) {
			return PayloadSlice{}, slice.Err
		}
		out.Limitations = append(out.Limitations, slice.Err.Error())
	}
	file := slice.File
	if file == nil {
		budget.reserve(jsonSize(out) + 1)
		return out, nil
	}

	out.Header = payloadHeader(file)
	budget.reserve(jsonSize(out.Header) + 1)
	for _, limitation := range file.Limitations {
		out.Limitations = append(out.Limitations, limitation)
		notes.addLimitation(fmt.Sprintf("slice %d: %s", slice.Index, limitation))
	}
	if file.Truncated {
		notes.addLimitation(fmt.Sprintf("slice %d load command or section coverage is partial", slice.Index))
	}

	budget.start(shareSegments)
	out.Segments = buildSegments(file, notes, budget)
	budget.finish()

	budget.start(shareSections)
	var err error
	out.Sections, err = buildSections(file, hasher, notes, budget)
	if err != nil {
		return PayloadSlice{}, err
	}
	budget.finish()

	budget.start(shareDylibs)
	out.Dylibs, err = buildDylibs(file, notes, slice.Index, budget)
	if err != nil {
		return PayloadSlice{}, err
	}
	budget.finish()

	out.Build, err = buildVersion(file, notes, slice.Index)
	if err != nil {
		return PayloadSlice{}, err
	}
	out.Entry, err = buildEntry(file, notes, slice.Index)
	if err != nil {
		return PayloadSlice{}, err
	}

	budget.start(shareSymbols)
	out.Symbols, err = buildSymbols(file, notes, slice.Index, budget)
	if err != nil {
		return PayloadSlice{}, err
	}
	budget.finish()

	budget.start(shareCodeSignature)
	out.CodeSignature, err = buildCodeSignature(file, notes, slice.Index, budget)
	if err != nil {
		return PayloadSlice{}, err
	}
	budget.finish()

	return out, nil
}

func payloadHeader(file *remacho.File) *PayloadHeader {
	header := file.Header
	return &PayloadHeader{
		Magic:                header.Magic,
		MagicName:            magicName(header.Magic),
		Is64:                 header.Is64,
		ByteOrder:            byteOrderName(header.Data),
		CPUType:              header.CPUType,
		CPUSubtype:           header.CPUSubtype,
		FileType:             header.FileType,
		FileTypeName:         fileTypeName(header.FileType),
		Flags:                header.Flags,
		Reserved:             header.Reserved,
		DeclaredCommandCount: header.NumberOfCommands,
		LoadedCommandCount:   header.LoadedCommandCount,
		LoadedSegmentCount:   header.LoadedSegmentCount,
		LoadedSectionCount:   header.LoadedSectionCount,
		SizeOfCommands:       header.SizeOfCommands,
		Truncated:            file.Truncated,
	}
}

// sliceStatus classifies why a slice has no parsed file.
func sliceStatus(err error) string {
	switch {
	case err == nil:
		return statusParsed
	case errors.Is(err, remacho.ErrInvalid):
		return statusInvalid
	case errors.Is(err, remacho.ErrTruncated):
		return statusTruncated
	case errors.Is(err, remacho.ErrLimit):
		return statusLimit
	case errors.Is(err, remacho.ErrUnavailable):
		return statusUnavailable
	case errors.Is(err, remacho.ErrRead):
		return statusRead
	default:
		return statusInvalid
	}
}

func buildSegments(file *remacho.File, notes *collector, budget *payloadBudget) []PayloadSegment {
	out := make([]PayloadSegment, 0, len(file.Segments))
	omitted := 0
	for i, segment := range file.Segments {
		entry := PayloadSegment{
			Index:                segment.Index,
			Command:              segment.Command,
			Name:                 segment.Name,
			NameAvailable:        segment.NameAvailable,
			NameHex:              hex.EncodeToString(segment.NameBytes[:]),
			VMAddress:            uint64String(segment.VMAddress),
			VMSize:               uint64String(segment.VMSize),
			FileOffset:           uint64String(segment.FileOffset),
			FileSize:             uint64String(segment.FileSize),
			MaxProtection:        segment.MaxProtection,
			InitProtection:       segment.InitProtection,
			Flags:                segment.Flags,
			DeclaredSectionCount: segment.DeclaredSectionCount,
			FirstSection:         segment.FirstSection,
			SectionCount:         segment.SectionCount,
		}
		size := jsonSize(entry) + 1
		if !budget.fits(size) {
			omitted = len(file.Segments) - i
			break
		}
		budget.add(size)
		out = append(out, entry)
	}
	if omitted > 0 {
		notes.addLimitation(fmt.Sprintf("payload budget omitted %d segments", omitted))
	}
	return out
}

func buildSections(file *remacho.File, hasher *contentHasher, notes *collector, budget *payloadBudget) ([]PayloadSection, error) {
	out := make([]PayloadSection, 0, len(file.Sections))
	omitted := 0
	for i, section := range file.Sections {
		entry := PayloadSection{
			Index:               section.Index,
			SegmentIndex:        section.SegmentIndex,
			Name:                section.Name,
			NameAvailable:       section.NameAvailable,
			NameHex:             hex.EncodeToString(section.NameBytes[:]),
			Address:             uint64String(section.Address),
			Size:                uint64String(section.Size),
			Offset:              section.Offset,
			Alignment:           section.Alignment,
			RelocationOffset:    section.RelocationOffset,
			NumberOfRelocations: section.NumberOfRelocations,
			Flags:               section.Flags,
			Reserved1:           section.Reserved1,
			Reserved2:           section.Reserved2,
			Reserved3:           section.Reserved3,
		}
		size := jsonSize(entry) + 1
		if !budget.fits(size) {
			omitted = len(file.Sections) - i
			break
		}
		// Only an entry that will be kept may spend the content budget.
		digest, err := hasher.section(file, &file.Sections[i])
		if err != nil {
			return nil, err
		}
		entry.DataSHA256 = digest
		size = jsonSize(entry) + 1
		if !budget.fits(size) {
			omitted = len(file.Sections) - i
			break
		}
		budget.add(size)
		out = append(out, entry)
	}
	if omitted > 0 {
		notes.addLimitation(fmt.Sprintf("payload budget omitted %d sections", omitted))
	}
	return out, nil
}

func buildDylibs(file *remacho.File, notes *collector, sliceIndex int, budget *payloadBudget) (*PayloadDylibs, error) {
	table, err := file.Dylibs()
	if err != nil {
		return nil, noteTableError(notes, sliceIndex, "dylib commands", err)
	}
	out := &PayloadDylibs{Dylibs: []PayloadDylib{}}
	for _, limitation := range table.Limitations {
		notes.addLimitation(fmt.Sprintf("slice %d: %s", sliceIndex, limitation))
	}
	out.Truncated = table.Truncated
	if table.Truncated {
		notes.addLimitation(fmt.Sprintf("slice %d dylib coverage is partial", sliceIndex))
	}

	omitted := 0
	for i, dylib := range table.Dylibs {
		entry := PayloadDylib{
			Index:                dylib.Index,
			Command:              dylib.Command,
			CommandName:          commandName(dylib.Command),
			Kind:                 dylibKind(dylib.Command),
			Name:                 dylib.Name,
			NameAvailable:        dylib.NameAvailable,
			NameOffset:           dylib.NameOffset,
			Timestamp:            dylib.Timestamp,
			CurrentVersion:       dylib.CurrentVersion,
			CompatibilityVersion: dylib.CompatibilityVersion,
		}
		size := jsonSize(entry) + 1
		if !budget.fits(size) {
			omitted = len(table.Dylibs) - i
			break
		}
		budget.add(size)
		out.Dylibs = append(out.Dylibs, entry)
	}
	if omitted > 0 {
		out.Truncated = true
		notes.addLimitation(fmt.Sprintf("payload budget omitted %d dylib commands", omitted))
	}

	if install := installName(table.Dylibs); install != nil {
		name := install.Name
		out.InstallName = &name
		out.InstallNameAvailable = install.NameAvailable
	}
	return out, nil
}

// installName returns the LC_ID_DYLIB entry, when the image declares one.
func installName(dylibs []remacho.Dylib) *remacho.Dylib {
	for i := range dylibs {
		if dylibs[i].Command == remacho.CommandDylibID {
			return &dylibs[i]
		}
	}
	return nil
}

func buildVersion(file *remacho.File, notes *collector, sliceIndex int) (*PayloadBuild, error) {
	version, err := file.BuildVersion()
	if err != nil {
		return nil, noteTableError(notes, sliceIndex, "build version", err)
	}
	out := &PayloadBuild{
		Command:           version.Command,
		CommandName:       commandName(version.Command),
		Platform:          version.Platform,
		PlatformAvailable: version.PlatformAvailable,
		PlatformName:      platformName(version.Platform),
		MinimumOS:         version.MinimumOS,
		SDK:               version.SDK,
		Tools:             make([]PayloadBuildTool, 0, len(version.Tools)),
	}
	if !version.PlatformAvailable {
		out.PlatformName = ""
	}
	for _, limitation := range version.Limitations {
		notes.addLimitation(fmt.Sprintf("slice %d: %s", sliceIndex, limitation))
	}
	if version.Truncated {
		notes.addLimitation(fmt.Sprintf("slice %d build version tool coverage is partial", sliceIndex))
	}
	for _, tool := range version.Tools {
		out.Tools = append(out.Tools, PayloadBuildTool{
			Tool:     tool.Tool,
			ToolName: toolName(tool.Tool),
			Version:  tool.Version,
		})
	}
	return out, nil
}

func buildEntry(file *remacho.File, notes *collector, sliceIndex int) (*PayloadEntry, error) {
	entry, err := file.EntryPoint()
	if err != nil {
		return nil, noteTableError(notes, sliceIndex, "entry point", err)
	}
	return &PayloadEntry{
		EntryOffset: uint64String(entry.EntryOffset),
		StackSize:   uint64String(entry.StackSize),
	}, nil
}

func buildSymbols(file *remacho.File, notes *collector, sliceIndex int, budget *payloadBudget) (*PayloadSymbols, error) {
	table, err := file.Symbols()
	if err != nil {
		return nil, noteTableError(notes, sliceIndex, "symbol table", err)
	}
	out := &PayloadSymbols{
		DeclaredCount: table.DeclaredCount,
		LoadedCount:   len(table.Symbols),
		StringBytes:   uint64String(uint64(table.StringBytes)),
		Truncated:     table.Truncated,
		Symbols:       make([]PayloadSymbol, 0, len(table.Symbols)),
	}
	for _, limitation := range table.Limitations {
		notes.addLimitation(fmt.Sprintf("slice %d: %s", sliceIndex, limitation))
	}
	if table.Truncated {
		notes.addLimitation(fmt.Sprintf("slice %d symbol coverage is partial", sliceIndex))
	}

	omitted := 0
	for i, symbol := range table.Symbols {
		entry := PayloadSymbol{
			Index:         symbol.Index,
			StringIndex:   symbol.StringIndex,
			Name:          symbol.Name,
			NameAvailable: symbol.NameAvailable,
			Type:          symbol.Type,
			Section:       symbol.Section,
			Description:   symbol.Description,
			Value:         uint64String(symbol.Value),
		}
		size := jsonSize(entry) + 1
		if !budget.fits(size) {
			omitted = len(table.Symbols) - i
			break
		}
		budget.add(size)
		out.Symbols = append(out.Symbols, entry)
	}
	if omitted > 0 {
		out.Truncated = true
		out.LoadedCount = len(out.Symbols)
		notes.addLimitation(fmt.Sprintf("payload budget omitted %d symbols", omitted))
	}
	return out, nil
}

func buildCodeSignature(file *remacho.File, notes *collector, sliceIndex int, budget *payloadBudget) (*PayloadCodeSignature, error) {
	signature, err := file.CodeSignature()
	if err != nil {
		return nil, noteTableError(notes, sliceIndex, "code signature", err)
	}
	out := &PayloadCodeSignature{
		DataOffset: uint64String(uint64(signature.DataOffset)),
		DataSize:   uint64String(uint64(signature.DataSize)),
		Magic:      signature.Magic,
		Length:     signature.Length,
		Count:      signature.Count,
		Truncated:  signature.Truncated,
		Blobs:      make([]PayloadCodeSignatureBlob, 0, len(signature.Blobs)),
	}
	for _, limitation := range signature.Limitations {
		notes.addLimitation(fmt.Sprintf("slice %d: %s", sliceIndex, limitation))
	}

	omitted := 0
	for i, blob := range signature.Blobs {
		entry := PayloadCodeSignatureBlob{
			Index:  blob.Index,
			Type:   blob.Type,
			Offset: blob.Offset,
			Magic:  blob.Magic,
			Length: blob.Length,
		}
		size := jsonSize(entry) + 1
		if !budget.fits(size) {
			omitted = len(signature.Blobs) - i
			break
		}
		budget.add(size)
		out.Blobs = append(out.Blobs, entry)
	}
	if omitted > 0 {
		out.Truncated = true
		notes.addLimitation(fmt.Sprintf("payload budget omitted %d signature blobs", omitted))
	}
	return out, nil
}

// noteTableError records an unusable table.
//
// Absence is not a limitation: the table is simply omitted. A reader failure
// fails the observation, because the payload would otherwise understate the
// artifact without saying so.
func noteTableError(notes *collector, sliceIndex int, label string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, remacho.ErrRead) {
		return err
	}
	if errors.Is(err, remacho.ErrNotFound) {
		return nil
	}
	notes.addLimitation(fmt.Sprintf("slice %d %s unavailable: %v", sliceIndex, label, err))
	return nil
}

func reportHashing(hasher *contentHasher, notes *collector) {
	if hasher.omitted > 0 {
		notes.addLimitation(fmt.Sprintf("content hashing budget omitted %d section digests", hasher.omitted))
	}
	if hasher.unavailable > 0 {
		notes.addLimitation(fmt.Sprintf("%d section digests unavailable: %s", hasher.unavailable, hasher.firstUnavailable))
	}
	if hasher.failed > 0 {
		notes.addLimitation(fmt.Sprintf("%d section digests failed: %s", hasher.failed, hasher.firstFailure))
	}
}

// contentKey identifies section content by its declared range, so two sections
// that describe the same bytes share one digest.
type contentKey struct {
	offset uint32
	size   uint64
}

// contentHasher digests section bytes under one artifact-wide budget.
type contentHasher struct {
	remaining        int64
	cache            map[contentKey]*string
	omitted          int
	unavailable      int
	failed           int
	firstUnavailable string
	firstFailure     string
}

func newContentHasher(budget int64) *contentHasher {
	if budget < 0 {
		budget = 0
	}
	return &contentHasher{remaining: budget, cache: make(map[contentKey]*string)}
}

// section returns the digest of one section, or nil when it is empty, over
// budget, or unreadable. A reader failure is returned so the caller fails
// closed.
func (h *contentHasher) section(file *remacho.File, section *remacho.Section) (*string, error) {
	if section.Size == 0 {
		return nil, nil
	}
	key := contentKey{offset: section.Offset, size: section.Size}
	if digest, ok := h.cache[key]; ok {
		return digest, nil
	}
	if int64(section.Size) > h.remaining {
		h.omitted++
		h.cache[key] = nil
		return nil, nil
	}
	data, err := file.SectionData(section.Index)
	if err != nil {
		if errors.Is(err, remacho.ErrRead) {
			return nil, err
		}
		if h.unavailable == 0 {
			h.firstUnavailable = err.Error()
		}
		h.unavailable++
		h.cache[key] = nil
		return nil, nil
	}
	h.remaining -= int64(len(data))
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	h.cache[key] = &digest
	return &digest, nil
}

func collectUnknowns(artifact *remacho.Artifact, payload *Payload, notes *collector) {
	for _, slice := range artifact.Slices {
		file := slice.File
		if file == nil {
			continue
		}
		if slice.CPUSubtype == 0x80000002 {
			notes.addUnknown("ARM64e pointer authentication is not interpreted")
		}
		for _, section := range file.Sections {
			if section.NumberOfRelocations > 0 {
				notes.addUnknown("section relocations are not decoded")
			}
			if len(section.Name) > 7 && section.Name[:7] == "__objc_" {
				notes.addUnknown("Objective-C metadata is not interpreted")
			}
		}
		for _, command := range file.Commands {
			switch command.Command {
			case commandDyldInfo, commandDyldInfoOnly, commandDyldExportsTrie:
				notes.addUnknown("exported symbol trie is not decoded")
			case commandDyldChainedFixups:
				notes.addUnknown("chained fixups are not decoded")
			}
		}
	}
	if codeSignaturePresent(payload) {
		notes.addUnknown("code signatures are not validated")
		notes.addUnknown("entitlements are not decoded")
	}
}

func codeSignaturePresent(payload *Payload) bool {
	for _, slice := range payload.Slices {
		if slice.CodeSignature != nil {
			return true
		}
	}
	return false
}

func magicName(magic uint32) string {
	switch magic {
	case remacho.Magic32:
		return "mach-o-32"
	case remacho.Magic64:
		return "mach-o-64"
	case remacho.FatMagic:
		return "fat-32"
	case remacho.FatMagic64:
		return "fat-64"
	default:
		return ""
	}
}

func byteOrderName(data remacho.Data) string {
	switch data {
	case remacho.DataLittle:
		return "little"
	case remacho.DataBig:
		return "big"
	default:
		return ""
	}
}

func fileTypeName(fileType uint32) string {
	switch fileType {
	case 1:
		return "object"
	case 2:
		return "execute"
	case 3:
		return "fvmlib"
	case 4:
		return "core"
	case 5:
		return "preload"
	case 6:
		return "dylib"
	case 7:
		return "dylinker"
	case 8:
		return "bundle"
	case 9:
		return "dylib_stub"
	case 10:
		return "dsym"
	case 11:
		return "kext_bundle"
	case 12:
		return "fileset"
	default:
		return ""
	}
}

func commandName(command uint32) string {
	switch command {
	case remacho.CommandSegment:
		return "LC_SEGMENT"
	case remacho.CommandSegment64:
		return "LC_SEGMENT_64"
	case remacho.CommandSymtab:
		return "LC_SYMTAB"
	case remacho.CommandDylibID:
		return "LC_ID_DYLIB"
	case remacho.CommandLoadDylib:
		return "LC_LOAD_DYLIB"
	case remacho.CommandLoadWeakDylib:
		return "LC_LOAD_WEAK_DYLIB"
	case remacho.CommandReexportDylib:
		return "LC_REEXPORT_DYLIB"
	case remacho.CommandLazyLoadDylib:
		return "LC_LAZY_LOAD_DYLIB"
	case remacho.CommandLoadUpwardDylib:
		return "LC_LOAD_UPWARD_DYLIB"
	case remacho.CommandUUID:
		return "LC_UUID"
	case remacho.CommandCodeSignature:
		return "LC_CODE_SIGNATURE"
	case remacho.CommandVersionMinMacOSX:
		return "LC_VERSION_MIN_MACOSX"
	case remacho.CommandVersionMinIPhoneOS:
		return "LC_VERSION_MIN_IPHONEOS"
	case remacho.CommandVersionMinTVOS:
		return "LC_VERSION_MIN_TVOS"
	case remacho.CommandVersionMinWatchOS:
		return "LC_VERSION_MIN_WATCHOS"
	case remacho.CommandBuildVersion:
		return "LC_BUILD_VERSION"
	case remacho.CommandMain:
		return "LC_MAIN"
	case commandDyldInfo:
		return "LC_DYLD_INFO"
	case commandDyldInfoOnly:
		return "LC_DYLD_INFO_ONLY"
	case commandDyldExportsTrie:
		return "LC_DYLD_EXPORTS_TRIE"
	case commandDyldChainedFixups:
		return "LC_DYLD_CHAINED_FIXUPS"
	default:
		return ""
	}
}

func dylibKind(command uint32) string {
	switch command {
	case remacho.CommandDylibID:
		return "id"
	case remacho.CommandLoadDylib:
		return "load"
	case remacho.CommandLoadWeakDylib:
		return "weak"
	case remacho.CommandReexportDylib:
		return "reexport"
	case remacho.CommandLazyLoadDylib:
		return "lazy"
	case remacho.CommandLoadUpwardDylib:
		return "upward"
	default:
		return ""
	}
}

func platformName(platform uint32) string {
	switch platform {
	case 1:
		return "macos"
	case 2:
		return "ios"
	case 3:
		return "tvos"
	case 4:
		return "watchos"
	case 5:
		return "bridgeos"
	case 6:
		return "maccatalyst"
	case 7:
		return "ios-simulator"
	case 8:
		return "tvos-simulator"
	case 9:
		return "watchos-simulator"
	case 10:
		return "driverkit"
	case 11:
		return "visionos"
	case 12:
		return "visionos-simulator"
	default:
		return ""
	}
}

func toolName(tool uint32) string {
	switch tool {
	case 1:
		return "clang"
	case 2:
		return "swift"
	case 3:
		return "ld"
	default:
		return ""
	}
}
