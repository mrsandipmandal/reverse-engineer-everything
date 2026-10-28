package apk

import (
	"fmt"

	reapk "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/apk"
)

// statusParsed reports that the ZIP directory and the Android layout were
// decoded.
const statusParsed = "parsed"

// buildPayload projects the package inventory into a payload under the payload
// budget.
func buildPayload(source *reapk.APK, opts Options, notes *collector) Payload {
	payload := Payload{
		Schema:   PayloadSchema,
		Artifact: projectArtifact(source, statusParsed),
	}
	for _, limitation := range source.Limitations {
		notes.addLimitation(limitation)
	}
	if source.Truncated {
		notes.addLimitation("artifact inventory is partial")
	}

	budget := newPayloadBudget(opts.PayloadBytes)
	budget.reserve(jsonSize(payload.Artifact) + len(PayloadSchema) + 64)
	budget.start(100)
	for index := range source.Entries {
		entry := projectEntry(&source.ZIP.Entries[index], source.Entries[index])
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
	return payload
}
