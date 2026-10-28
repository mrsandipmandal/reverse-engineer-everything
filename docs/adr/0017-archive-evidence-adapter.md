# ADR 0017: Archive evidence adapter

- Status: accepted
- Date: 2026-10-28

## Context

ADR 0016 gave `internal/formats/archive` a bounded read of ZIP, tar, and gzip containers: a validated inventory, unsafe-path detection, explicit limits, and on-demand content reads that never touch the filesystem. Phase 6 still needs the step that turns that read into project evidence: a deterministic `ree.payload.archive/1` payload inside a `ree.evidence/1` record, with explicit coverage and limitations.

The PE and Mach-O adapters in ADR 0011 and ADR 0015 set the pattern: one record per artifact, a subject digest over the artifact bytes, a payload budget with fair shares, absence signalled by null rather than an empty list, and a limitation for every structure the adapter observed but could not decode.

Archives add a property the earlier adapters do not have: a member can itself be a container. A reverse engineer looking at a `.tar.gz` or a `.apk` usually cares about the inner inventory, and a payload that lists only the outer entries would be technically honest but practically thin. Nested inspection is nevertheless a denial-of-service surface: an archive can contain an archive at every entry, and each level can multiply the work.

The artifact is untrusted. A crafted entry count, name, declared size, or nesting fan-out must not inflate the record, exhaust memory, or make the payload claim more than the reader proved. The payload must also remain something a consumer can compare across runs, so nested inspection cannot depend on map iteration or goroutine timing.

## Decisions

### One record per artifact, nested containers inside the payload

`Observe` takes an `io.ReaderAt` and a size and returns one evidence record. `subject.sha256` covers exactly those bytes, including every nested member.

A nested container is reported as a `PayloadArchive` below the entry that declares it, not as a second record.

- A per-member record would need a subject digest for bytes that are not a file on disk, and a consumer could not recompute it from the artifact.
- Reporting only the outer inventory would hide the material a reverse engineer needs; reporting the nested inventory without the enclosing entry would lose where it came from.
- A recursive payload keeps the tree, so depth and provenance stay explicit.

### Nested detection policy

Detection runs only on regular-file entries whose name is safe, that are not encrypted, and whose method is stored or deflate. Links, devices, directories, and unsupported methods are skipped: their bytes are not a container this adapter can parse, and reading them would spend budget on a guess.

For each candidate the adapter reads a 263-byte prefix — enough for `archive.Detect` to see the tar magic at offset 257 — and only a recognized prefix causes the entry to be decoded. A plain file that happens to be large is therefore never decompressed for detection.

Nested inspection is bounded by three independent values:

- `NestedDepth`: zero selects one level, a negative value disables nesting, and values above two are clamped. Two levels cover the common `.tar.gz` and `archive-in-archive` cases without allowing arbitrary fan-out.
- `NestedMembers`: the number of entries that may be parsed as containers, default 256, maximum 4096.
- `NestedBytes`: the total entry bytes decoded for detection, default 64 MiB, minimum 1 MiB, maximum `MaxArtifactBytes`.

The byte budget is shared by every level. A member whose declared size already exceeds the remaining budget is not read, and detection stops with one limitation. A member whose size is unknown, such as a gzip stream inside a gzip stream, is decoded under the reader's content limit and then checked against the remaining budget; exceeding it yields a `limit` status and stops further detection.

Detection stops instead of skipping a large member and continuing: container order is the only stable order the reader exposes, and silently continuing after a budget stop would make the payload depend on which entries happened to be small.

A nested member that cannot be read or parsed keeps its `status` — `invalid`, `truncated`, `limit`, `unavailable`, or `read` — and its error text in its own limitations, and adds one deduplicated record limitation. It does not fail the record or hide the other members.

### Payload shape

`Payload` carries the artifact view, the outer entries, and, per entry, a nullable `nested` container. A nested container repeats the same shape, so depth is uniform and a consumer walks the tree the same way at every level.

Unsigned 64-bit sizes and offsets are decimal strings so values above 2^53 survive canonical JSON unchanged. `uint32` and `uint16` raw fields, including the declared CRC-32, stay JSON numbers. Raw names are lowercase hexadecimal, decoded names are text the reader validated without repair, and a name that failed a path check keeps its reason in `unsafe`.

Absence is null: `size` is null for a nested container, `mode`, `crc32`, `modified_unix`, and the known size fields are null when the container stores none, and `gzip` is null outside gzip.

### Budget

The payload budget defaults to 3,500,000 bytes, is clamped to at least 4 KiB, and stops 64 KiB below `evidence.MaxPayloadBytes` so the record envelope and canonicalization still fit.

The artifact envelope is charged first. With nesting enabled the entries take 65 percent of what remains and nested containers take the rest; without nesting the entries take all of it. A table or entry that does not fit stops projection, records one limitation naming the omitted count, and leaves `loaded_entry_count` below `entry_count`. A truncated projection is never presented as complete.

Reader truncation and payload truncation are separate: `truncated` mirrors the reader's header or directory chain, while `loaded_entry_count` below `entry_count` reports an abridged payload.

### Coverage and unknowns

Coverage is `complete` only when no limitation and no unknown was recorded, matching the other providers. The adapter records no unknowns: every structure the reader exposes is either projected or reported as a limitation. Reader limitations at the artifact and nested levels are copied into the record with a deterministic prefix, so a consumer can tell an outer truncation from a nested one.

Record limitations and unknowns are deduplicated and capped by the same collector used by the Mach-O adapter: 127 limitations plus one marker and 31 unknowns plus one marker.

### Schema

`ree.payload.archive/1` is a provider payload. It does not change `ree.evidence/1`, the bundle format, or the canonical JSON profile.

## Consequences

- A `.tar.gz` or archive-in-archive produces one record whose payload shows both levels, with the enclosing entry visible.
- Nested work is bounded by depth, member count, and bytes, so a recursive archive cannot multiply parsing cost without limit.
- Detection reads a prefix before decoding, so ordinary large files are not decompressed.
- The payload can be abridged by the payload budget; `entry_count`, `loaded_entry_count`, and one limitation make that visible rather than silent.
- Nested detection costs one extra decode of every recognized member. That is the price of proving the member is a container rather than guessing from its name.
- Wiring the archive provider into `ree analyze` and `ree_analyze`, archive inventory commands, APK, ASAR, and plist are deferred to later Phase 6 increments.
