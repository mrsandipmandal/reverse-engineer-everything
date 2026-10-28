package plist

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// xmlParser decodes the XML representation as a token stream so depth and
// object counts are enforced before a subtree is expanded.
type xmlParser struct {
	dec    *xml.Decoder
	limits Limits
	plist  *Plist
}

// parseXML reads the XML representation.
func parseXML(r io.ReaderAt, size int64, limits Limits) (*Plist, error) {
	decoder := xml.NewDecoder(io.NewSectionReader(r, 0, size))
	parser := &xmlParser{
		dec:    decoder,
		limits: limits,
		plist: &Plist{
			Format:    FormatXML,
			TopObject: -1,
			size:      size,
			limits:    limits,
		},
	}
	parsed, err := parser.run()
	if err != nil {
		return nil, err
	}
	parsed.walk(limits)
	return parsed, nil
}

func (p *xmlParser) run() (*Plist, error) {
	if err := p.findRoot(); err != nil {
		return nil, err
	}
	start, err := p.nextStart()
	if err != nil {
		return nil, err
	}
	index, err := p.element(start, 0)
	if err != nil {
		return nil, err
	}
	p.plist.TopObject = index
	if err := p.expectEnd("plist"); err != nil {
		return nil, err
	}
	for {
		tok, err := p.dec.Token()
		if errors.Is(err, io.EOF) {
			return p.plist, nil
		}
		if err != nil {
			return nil, xmlError(err)
		}
		switch typed := tok.(type) {
		case xml.CharData:
			if len(bytes.TrimSpace(typed)) != 0 {
				return nil, fmt.Errorf("%w: trailing text after the property list", ErrInvalid)
			}
		case xml.Comment, xml.ProcInst, xml.Directive:
		default:
			return nil, fmt.Errorf("%w: trailing content after the property list", ErrInvalid)
		}
	}
}

// findRoot consumes the prologue and the <plist> start element.
func (p *xmlParser) findRoot() error {
	for {
		tok, err := p.dec.Token()
		if err != nil {
			return xmlError(err)
		}
		switch typed := tok.(type) {
		case xml.StartElement:
			if typed.Name.Local != "plist" {
				return fmt.Errorf("%w: root element is %q, want plist", ErrInvalid, typed.Name.Local)
			}
			return nil
		case xml.CharData:
			if len(bytes.TrimSpace(typed)) != 0 {
				return fmt.Errorf("%w: text before the property list", ErrInvalid)
			}
		case xml.Comment, xml.ProcInst, xml.Directive:
		}
	}
}

// nextStart returns the next start element, skipping whitespace and
// non-element tokens.
func (p *xmlParser) nextStart() (xml.StartElement, error) {
	for {
		tok, err := p.dec.Token()
		if err != nil {
			return xml.StartElement{}, xmlError(err)
		}
		switch typed := tok.(type) {
		case xml.StartElement:
			return typed, nil
		case xml.CharData:
			if len(bytes.TrimSpace(typed)) != 0 {
				return xml.StartElement{}, fmt.Errorf("%w: unexpected text %q",
					ErrInvalid, clipText(typed))
			}
		case xml.EndElement:
			return xml.StartElement{}, fmt.Errorf("%w: unexpected end element %q",
				ErrInvalid, typed.Name.Local)
		case xml.Comment, xml.ProcInst, xml.Directive:
		}
	}
}

// expectEnd consumes tokens until the named end element.
func (p *xmlParser) expectEnd(name string) error {
	for {
		tok, err := p.dec.Token()
		if err != nil {
			return xmlError(err)
		}
		switch typed := tok.(type) {
		case xml.EndElement:
			if typed.Name.Local == name {
				return nil
			}
			return fmt.Errorf("%w: end element %q, want %q", ErrInvalid, typed.Name.Local, name)
		case xml.CharData:
			if len(bytes.TrimSpace(typed)) != 0 {
				return fmt.Errorf("%w: unexpected text %q", ErrInvalid, clipText(typed))
			}
		case xml.Comment, xml.ProcInst, xml.Directive:
		case xml.StartElement:
			return fmt.Errorf("%w: unexpected element %q", ErrInvalid, typed.Name.Local)
		}
	}
}

// element inventories one value element. A value skipped by a limit returns -1
// and leaves its subtree consumed but not inventoried.
func (p *xmlParser) element(start xml.StartElement, depth int) (int, error) {
	if depth > p.limits.Depth {
		p.truncate("object depth limit %d reached at %q", p.limits.Depth, start.Name.Local)
		return -1, p.skip()
	}
	if len(p.plist.Objects) >= p.limits.Objects {
		p.truncate("object limit %d reached at %q", p.limits.Objects, start.Name.Local)
		return -1, p.skip()
	}

	switch start.Name.Local {
	case "dict":
		return p.dictionary(start, depth)
	case "array":
		return p.array(start, depth)
	case "string":
		return p.scalar(start, TypeString)
	case "integer":
		return p.scalar(start, TypeInteger)
	case "real":
		return p.scalar(start, TypeReal)
	case "date":
		return p.scalar(start, TypeDate)
	case "data":
		return p.scalar(start, TypeData)
	case "uid":
		return p.scalar(start, TypeUID)
	case "true":
		return p.boolean(start, true)
	case "false":
		return p.boolean(start, false)
	default:
		index := p.newObject(TypeUnknown)
		p.plist.Objects[index].Limitations = append(p.plist.Objects[index].Limitations,
			fmt.Sprintf("unsupported element %q", start.Name.Local))
		return index, p.skip()
	}
}

// dictionary inventories a keyed collection.
func (p *xmlParser) dictionary(_ xml.StartElement, depth int) (int, error) {
	index := p.newObject(TypeDictionary)
	var keys, values []uint64
	for {
		tok, err := p.dec.Token()
		if err != nil {
			return 0, xmlError(err)
		}
		switch typed := tok.(type) {
		case xml.StartElement:
			if typed.Name.Local != "key" {
				return 0, fmt.Errorf("%w: dictionary member is %q, want key",
					ErrInvalid, typed.Name.Local)
			}
			key, err := p.key(typed)
			if err != nil {
				return 0, err
			}
			valueStart, err := p.nextStart()
			if err != nil {
				return 0, err
			}
			value, err := p.element(valueStart, depth+1)
			if err != nil {
				return 0, err
			}
			if key < 0 || value < 0 {
				continue
			}
			keys = append(keys, uint64(key))
			values = append(values, uint64(value))
		case xml.EndElement:
			if typed.Name.Local != "dict" {
				return 0, fmt.Errorf("%w: end element %q inside a dictionary",
					ErrInvalid, typed.Name.Local)
			}
			if len(keys) != len(values) {
				return 0, fmt.Errorf("%w: dictionary ends with a key and no value", ErrInvalid)
			}
			object := &p.plist.Objects[index]
			object.Keys, object.Values = keys, values
			return index, nil
		case xml.CharData:
			if len(bytes.TrimSpace(typed)) != 0 {
				return 0, fmt.Errorf("%w: text %q inside a dictionary", ErrInvalid, clipText(typed))
			}
		case xml.Comment, xml.ProcInst, xml.Directive:
		}
	}
}

// array inventories an ordered collection.
func (p *xmlParser) array(_ xml.StartElement, depth int) (int, error) {
	index := p.newObject(TypeArray)
	var refs []uint64
	for {
		tok, err := p.dec.Token()
		if err != nil {
			return 0, xmlError(err)
		}
		switch typed := tok.(type) {
		case xml.StartElement:
			value, err := p.element(typed, depth+1)
			if err != nil {
				return 0, err
			}
			if value >= 0 {
				refs = append(refs, uint64(value))
			}
		case xml.EndElement:
			if typed.Name.Local != "array" {
				return 0, fmt.Errorf("%w: end element %q inside an array",
					ErrInvalid, typed.Name.Local)
			}
			p.plist.Objects[index].Refs = refs
			return index, nil
		case xml.CharData:
			if len(bytes.TrimSpace(typed)) != 0 {
				return 0, fmt.Errorf("%w: text %q inside an array", ErrInvalid, clipText(typed))
			}
		case xml.Comment, xml.ProcInst, xml.Directive:
		}
	}
}

// key inventories a dictionary key as a string object.
func (p *xmlParser) key(start xml.StartElement) (int, error) {
	var text string
	if err := p.dec.DecodeElement(&text, &start); err != nil {
		return 0, xmlError(err)
	}
	index := p.newObject(TypeString)
	object := &p.plist.Objects[index]
	object.Text = text
	object.TextAvailable = true
	object.TextBytes = []byte(text)
	if len(text) > p.limits.StringBytes {
		object.Text = ""
		object.TextAvailable = false
		object.TextBytes = []byte(text[:p.limits.StringBytes])
		object.Limitations = append(object.Limitations,
			fmt.Sprintf("string exceeds %d bytes", p.limits.StringBytes))
	}
	return index, nil
}

// scalar inventories a text-valued element.
func (p *xmlParser) scalar(start xml.StartElement, kind Type) (int, error) {
	var text string
	if err := p.dec.DecodeElement(&text, &start); err != nil {
		return 0, xmlError(err)
	}
	index := p.newObject(kind)
	object := &p.plist.Objects[index]
	if len(text) > p.limits.StringBytes {
		p.truncate("string limit %d reached at %q", p.limits.StringBytes, start.Name.Local)
		object.TextBytes = []byte(text[:p.limits.StringBytes])
		object.Limitations = append(object.Limitations,
			fmt.Sprintf("string exceeds %d bytes", p.limits.StringBytes))
		return index, nil
	}
	object.TextBytes = []byte(text)

	switch kind {
	case TypeString:
		object.Text = text
		object.TextAvailable = true
	case TypeInteger:
		trimmed := strings.TrimSpace(text)
		object.Integer = trimmed
		if !validInteger(trimmed) {
			object.Limitations = append(object.Limitations, "integer is not a decimal number")
		}
	case TypeReal:
		trimmed := strings.TrimSpace(text)
		if value, err := strconv.ParseFloat(trimmed, 64); err != nil {
			object.Limitations = append(object.Limitations, "real is not a number")
		} else {
			object.Real = value
		}
	case TypeDate:
		trimmed := strings.TrimSpace(text)
		if parsed, err := time.Parse(time.RFC3339, trimmed); err != nil {
			object.Limitations = append(object.Limitations, "date is not an RFC 3339 timestamp")
		} else {
			object.DateUnix = parsed.Unix()
			object.DateAvailable = true
		}
	case TypeData:
		length, ok := base64Length(text)
		object.DataBytes = length
		if !ok {
			object.Limitations = append(object.Limitations, "data is not valid base64")
		}
	case TypeUID:
		trimmed := strings.TrimSpace(text)
		if value, err := strconv.ParseUint(trimmed, 10, 64); err != nil {
			object.Limitations = append(object.Limitations, "uid is not a decimal number")
		} else {
			object.UID = value
		}
	}
	return index, nil
}

// boolean inventories <true/> or <false/>.
func (p *xmlParser) boolean(_ xml.StartElement, value bool) (int, error) {
	if err := p.dec.Skip(); err != nil {
		return 0, xmlError(err)
	}
	index := p.newObject(TypeBoolean)
	p.plist.Objects[index].Boolean = value
	return index, nil
}

// newObject appends an empty object and returns its index.
func (p *xmlParser) newObject(kind Type) int {
	index := len(p.plist.Objects)
	p.plist.Objects = append(p.plist.Objects, Object{Index: index, Type: kind, Depth: -1})
	return index
}

// skip consumes the rest of the current element.
func (p *xmlParser) skip() error {
	if err := p.dec.Skip(); err != nil {
		return xmlError(err)
	}
	return nil
}

func (p *xmlParser) truncate(format string, args ...any) {
	p.plist.Truncated = true
	p.plist.note(format, args...)
}

// validInteger reports whether text is a decimal integer that fits a signed or
// unsigned 64-bit value.
func validInteger(text string) bool {
	if text == "" {
		return false
	}
	if _, err := strconv.ParseInt(text, 10, 64); err == nil {
		return true
	}
	_, err := strconv.ParseUint(text, 10, 64)
	return err == nil
}

// base64Length returns the decoded length of a base64 text and whether the text
// is structurally valid base64. It does not allocate the decoded bytes.
func base64Length(text string) (uint64, bool) {
	digits := 0
	padding := 0
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case ' ', '\t', '\r', '\n':
			continue
		case '=':
			padding++
		default:
			digits++
		}
	}
	total := digits + padding
	if total == 0 {
		return 0, true
	}
	if total%4 != 0 || padding > 2 {
		return 0, false
	}
	return uint64(total/4*3 - padding), true
}

// clipText bounds untrusted text quoted in an error message.
func clipText(text []byte) string {
	const clipLimit = 32
	if len(text) > clipLimit {
		return string(text[:clipLimit]) + "..."
	}
	return string(text)
}

// xmlError classifies a decoder error as truncated, invalid, or a reader
// failure.
func xmlError(err error) error {
	var syntax *xml.SyntaxError
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return fmt.Errorf("%w: %w", ErrTruncated, err)
	case errors.As(err, &syntax):
		if strings.HasSuffix(syntax.Msg, "EOF") {
			return fmt.Errorf("%w: %w", ErrTruncated, err)
		}
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	default:
		return fmt.Errorf("%w: %w", ErrRead, err)
	}
}
