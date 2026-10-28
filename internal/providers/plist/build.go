package plist

import (
	"fmt"

	replist "github.com/mrsandipmandal/reverse-engineer-everything/internal/formats/plist"
)

// statusParsed reports that the property list structure was decoded.
const statusParsed = "parsed"

// buildPayload projects the reader inventory into a payload under the payload
// budget.
func buildPayload(source *replist.Plist, opts Options, notes *collector) Payload {
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
	for index := range source.Objects {
		object := projectObject(source.Objects[index])
		cost := jsonSize(object)
		if !budget.fits(cost) {
			notes.addLimitation(fmt.Sprintf("payload budget omits objects after %d of %d",
				len(payload.Objects), len(source.Objects)))
			break
		}
		budget.add(cost)
		payload.Objects = append(payload.Objects, object)
	}
	budget.finish()
	payload.Artifact.LoadedObjectCount = len(payload.Objects)
	return payload
}
