package plist

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	// binaryTrailerBytes is the fixed size of the binary plist trailer.
	binaryTrailerBytes = 32
	// binaryMagicBytes is the size of the `bplist00` prefix.
	binaryMagicBytes = 8
	// binaryDateEpoch is the Unix time of 2001-01-01T00:00:00Z, the reference
	// date of a binary plist timestamp.
	binaryDateEpoch int64 = 978307200
)

// binary object markers, high nibble of the marker byte.
const (
	markerSimple  byte = 0x0
	markerInteger byte = 0x1
	markerReal    byte = 0x2
	markerDate    byte = 0x3
	markerData    byte = 0x4
	markerASCII   byte = 0x5
	markerUTF16   byte = 0x6
	markerUTF8    byte = 0x7
	markerUID     byte = 0x8
	markerArray   byte = 0xA
	markerOrdered byte = 0xB
	markerSet     byte = 0xC
	markerDict    byte = 0xD
)

// parseBinary reads the binary `bplist` representation.
func parseBinary(r io.ReaderAt, size int64, limits Limits) (*Plist, error) {
	if size < binaryMagicBytes+binaryTrailerBytes {
		return nil, fmt.Errorf("%w: artifact size %d is smaller than a binary plist header and trailer",
			ErrTruncated, size)
	}
	magic, err := readBytes(r, 0, binaryMagicBytes, size)
	if err != nil {
		return nil, err
	}
	if string(magic[:6]) != "bplist" {
		return nil, fmt.Errorf("%w: magic is not bplist", ErrInvalid)
	}
	version := string(magic[6:8])
	switch version {
	case "00", "15", "16":
	default:
		return nil, fmt.Errorf("%w: unsupported binary plist version %q", ErrInvalid, version)
	}

	trailer, err := readBytes(r, size-binaryTrailerBytes, binaryTrailerBytes, size)
	if err != nil {
		return nil, err
	}
	offsetIntSize := int(trailer[6])
	objectRefSize := int(trailer[7])
	numObjects := binary.BigEndian.Uint64(trailer[8:16])
	topObject := binary.BigEndian.Uint64(trailer[16:24])
	tableOffset := binary.BigEndian.Uint64(trailer[24:32])

	if offsetIntSize < 1 || offsetIntSize > 8 {
		return nil, fmt.Errorf("%w: offset integer size %d is outside 1..8", ErrInvalid, offsetIntSize)
	}
	if objectRefSize < 1 || objectRefSize > 8 {
		return nil, fmt.Errorf("%w: object reference size %d is outside 1..8", ErrInvalid, objectRefSize)
	}
	if numObjects == 0 {
		return nil, fmt.Errorf("%w: trailer declares no objects", ErrInvalid)
	}
	if numObjects > uint64(limits.Objects) {
		return nil, fmt.Errorf("%w: %d objects exceed limit %d",
			ErrLimit, numObjects, limits.Objects)
	}
	if topObject >= numObjects {
		return nil, fmt.Errorf("%w: top object %d is outside %d objects",
			ErrInvalid, topObject, numObjects)
	}
	area := uint64(size - binaryTrailerBytes)
	if tableOffset < binaryMagicBytes || tableOffset > area {
		return nil, fmt.Errorf("%w: offset table at %d is outside the object area",
			ErrInvalid, tableOffset)
	}
	tableBytes := numObjects * uint64(offsetIntSize)
	if tableBytes > area-tableOffset {
		return nil, fmt.Errorf("%w: offset table of %d bytes at %d extends beyond the object area",
			ErrTruncated, tableBytes, tableOffset)
	}

	table, err := readBytes(r, int64(tableOffset), int(tableBytes), size)
	if err != nil {
		return nil, err
	}
	count := int(numObjects)
	offsets := make([]int64, count)
	for i := 0; i < count; i++ {
		raw := table[i*offsetIntSize : (i+1)*offsetIntSize]
		offset := uint64(0)
		for _, b := range raw {
			offset = offset<<8 | uint64(b)
		}
		if offset < binaryMagicBytes || offset >= tableOffset {
			return nil, fmt.Errorf("%w: object %d offset %d is outside the object area",
				ErrInvalid, i, offset)
		}
		offsets[i] = int64(offset)
	}

	objects := make([]Object, count)
	for i := 0; i < count; i++ {
		object, err := decodeObject(r, size, offsets[i], int64(tableOffset), objectRefSize,
			numObjects, limits, i)
		if err != nil {
			return nil, fmt.Errorf("plist: object %d: %w", i, err)
		}
		objects[i] = object
	}

	out := &Plist{
		Format:    FormatBinary,
		Version:   version,
		Objects:   objects,
		TopObject: int(topObject),
		size:      size,
		limits:    limits,
	}
	out.walk(limits)
	return out, nil
}

// decodeObject reads one object at offset. Object data must end before limit.
func decodeObject(r io.ReaderAt, size int64, offset int64, limit int64, refSize int,
	numObjects uint64, limits Limits, index int) (Object, error) {
	head, err := readBytes(r, offset, 1, size)
	if err != nil {
		return Object{}, err
	}
	marker := head[0]
	high := marker >> 4
	low := marker & 0x0F
	object := Object{Index: index, Depth: -1}

	switch high {
	case markerSimple:
		switch marker {
		case 0x00:
			object.Type = TypeNull
		case 0x08:
			object.Type = TypeBoolean
		case 0x09:
			object.Type = TypeBoolean
			object.Boolean = true
		default:
			object.Type = TypeUnknown
			object.Limitations = append(object.Limitations,
				fmt.Sprintf("unsupported simple marker 0x%02x", marker))
		}
		return object, nil
	case markerInteger:
		return decodeInteger(r, size, offset, limit, low, object)
	case markerReal:
		return decodeReal(r, size, offset, limit, low, object)
	case markerDate:
		return decodeDate(r, size, offset, limit, object)
	case markerData:
		return decodeData(r, size, offset, limit, low, object)
	case markerASCII, markerUTF8, markerUTF16:
		return decodeString(r, size, offset, limit, low, limits, object, high == markerUTF16)
	case markerUID:
		return decodeUID(r, size, offset, limit, low, object)
	case markerArray, markerOrdered, markerSet:
		return decodeRefs(r, size, offset, limit, low, refSize, numObjects, object, high)
	case markerDict:
		return decodeDict(r, size, offset, limit, low, refSize, numObjects, object)
	default:
		return Object{}, fmt.Errorf("%w: unsupported marker 0x%02x", ErrInvalid, marker)
	}
}

// readCount decodes a variable-length count. It returns the count and the
// number of bytes consumed after the marker.
func readCount(r io.ReaderAt, size int64, pos int64, limit int64, low byte) (uint64, int64, error) {
	if low != 0x0F {
		return uint64(low), 1, nil
	}
	head, err := readBytes(r, pos+1, 1, size)
	if err != nil {
		return 0, 0, err
	}
	if head[0]>>4 != markerInteger {
		return 0, 0, fmt.Errorf("%w: count extension marker 0x%02x is not an integer",
			ErrInvalid, head[0])
	}
	intBytes := 1 << (head[0] & 0x0F)
	if intBytes > 8 {
		return 0, 0, fmt.Errorf("%w: count integer of %d bytes is too large", ErrInvalid, intBytes)
	}
	raw, err := readBytes(r, pos+2, intBytes, size)
	if err != nil {
		return 0, 0, err
	}
	count := uint64(0)
	for _, b := range raw {
		count = count<<8 | uint64(b)
	}
	consumed := 2 + int64(intBytes)
	if pos+consumed > limit {
		return 0, 0, fmt.Errorf("%w: count field at %d extends beyond the object area",
			ErrTruncated, pos)
	}
	return count, consumed, nil
}

func decodeInteger(r io.ReaderAt, size int64, offset, limit int64, low byte, object Object) (Object, error) {
	if low > 4 {
		return Object{}, fmt.Errorf("%w: integer width 2^%d is too large", ErrInvalid, low)
	}
	width := 1 << low
	raw, err := readBytes(r, offset+1, width, size)
	if err != nil {
		return Object{}, err
	}
	if offset+1+int64(width) > limit {
		return Object{}, fmt.Errorf("%w: integer at %d extends beyond the object area", ErrTruncated, offset)
	}
	value := uint64(0)
	if width > 8 {
		for _, b := range raw[:width-8] {
			if b != 0 {
				object.Limitations = append(object.Limitations,
					"integer exceeds 64 bits; the low 64 bits are reported")
				break
			}
		}
		raw = raw[width-8:]
	}
	for _, b := range raw {
		value = value<<8 | uint64(b)
	}
	object.Type = TypeInteger
	object.Integer = strconv.FormatUint(value, 10)
	return object, nil
}

func decodeReal(r io.ReaderAt, size int64, offset, limit int64, low byte, object Object) (Object, error) {
	if low != 2 && low != 3 {
		return Object{}, fmt.Errorf("%w: real width 2^%d is not 4 or 8", ErrInvalid, low)
	}
	width := 1 << low
	raw, err := readBytes(r, offset+1, width, size)
	if err != nil {
		return Object{}, err
	}
	if offset+1+int64(width) > limit {
		return Object{}, fmt.Errorf("%w: real at %d extends beyond the object area", ErrTruncated, offset)
	}
	object.Type = TypeReal
	if width == 4 {
		object.Real = float64(math.Float32frombits(binary.BigEndian.Uint32(raw)))
	} else {
		object.Real = math.Float64frombits(binary.BigEndian.Uint64(raw))
	}
	if math.IsNaN(object.Real) || math.IsInf(object.Real, 0) {
		object.Limitations = append(object.Limitations, "real is not a finite number")
	}
	return object, nil
}

func decodeDate(r io.ReaderAt, size int64, offset, limit int64, object Object) (Object, error) {
	raw, err := readBytes(r, offset+1, 8, size)
	if err != nil {
		return Object{}, err
	}
	if offset+9 > limit {
		return Object{}, fmt.Errorf("%w: date at %d extends beyond the object area", ErrTruncated, offset)
	}
	object.Type = TypeDate
	seconds := math.Float64frombits(binary.BigEndian.Uint64(raw))
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		object.Limitations = append(object.Limitations, "date is not a finite number")
		return object, nil
	}
	object.DateUnix = binaryDateEpoch + int64(seconds)
	object.DateAvailable = true
	return object, nil
}

func decodeData(r io.ReaderAt, size int64, offset, limit int64, low byte, object Object) (Object, error) {
	count, consumed, err := readCount(r, size, offset, limit, low)
	if err != nil {
		return Object{}, err
	}
	if count > uint64(size) || offset+consumed+int64(count) > limit {
		return Object{}, fmt.Errorf("%w: data of %d bytes at %d extends beyond the object area",
			ErrTruncated, count, offset)
	}
	object.Type = TypeData
	object.DataBytes = count
	return object, nil
}

func decodeString(r io.ReaderAt, size int64, offset, limit int64, low byte, limits Limits,
	object Object, utf16be bool) (Object, error) {
	count, consumed, err := readCount(r, size, offset, limit, low)
	if err != nil {
		return Object{}, err
	}
	bytes := count
	if utf16be {
		if count > uint64(size) {
			return Object{}, fmt.Errorf("%w: UTF-16 string of %d units at %d is too large",
				ErrTruncated, count, offset)
		}
		bytes = count * 2
	}
	if bytes > uint64(size) || offset+consumed+int64(bytes) > limit {
		return Object{}, fmt.Errorf("%w: string of %d bytes at %d extends beyond the object area",
			ErrTruncated, bytes, offset)
	}
	object.Type = TypeString
	read := bytes
	truncated := false
	if read > uint64(limits.StringBytes) {
		read = uint64(limits.StringBytes)
		truncated = true
	}
	raw, err := readBytes(r, offset+consumed, int(read), size)
	if err != nil {
		return Object{}, err
	}
	object.TextBytes = raw
	if truncated {
		object.Limitations = append(object.Limitations,
			fmt.Sprintf("string exceeds %d bytes", limits.StringBytes))
		return object, nil
	}
	if utf16be {
		text, ok := decodeUTF16(raw)
		object.Text, object.TextAvailable = text, ok
		if !ok {
			object.Limitations = append(object.Limitations, "string is not valid UTF-16")
		}
		return object, nil
	}
	if !utf8.Valid(raw) {
		object.Limitations = append(object.Limitations, "string is not valid UTF-8")
		return object, nil
	}
	object.Text = string(raw)
	object.TextAvailable = true
	return object, nil
}

func decodeUTF16(raw []byte) (string, bool) {
	units := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		units = append(units, binary.BigEndian.Uint16(raw[i:]))
	}
	decoded := utf16.Decode(units)
	for _, r := range decoded {
		if r == utf8.RuneError {
			return "", false
		}
	}
	return string(decoded), true
}

func decodeUID(r io.ReaderAt, size int64, offset, limit int64, low byte, object Object) (Object, error) {
	width := int(low) + 1
	raw, err := readBytes(r, offset+1, width, size)
	if err != nil {
		return Object{}, err
	}
	if offset+1+int64(width) > limit {
		return Object{}, fmt.Errorf("%w: UID at %d extends beyond the object area", ErrTruncated, offset)
	}
	object.Type = TypeUID
	if width > 8 {
		raw = raw[width-8:]
		object.Limitations = append(object.Limitations,
			"UID exceeds 64 bits; the low 64 bits are reported")
	}
	value := uint64(0)
	for _, b := range raw {
		value = value<<8 | uint64(b)
	}
	object.UID = value
	return object, nil
}

func decodeRefs(r io.ReaderAt, size int64, offset, limit int64, low byte, refSize int,
	numObjects uint64, object Object, high byte) (Object, error) {
	count, consumed, err := readCount(r, size, offset, limit, low)
	if err != nil {
		return Object{}, err
	}
	refs, err := readRefs(r, size, offset+consumed, limit, count, refSize, numObjects)
	if err != nil {
		return Object{}, err
	}
	switch high {
	case markerArray:
		object.Type = TypeArray
	case markerOrdered:
		object.Type = TypeSet
	default:
		object.Type = TypeSet
	}
	object.Refs = refs
	return object, nil
}

func decodeDict(r io.ReaderAt, size int64, offset, limit int64, low byte, refSize int,
	numObjects uint64, object Object) (Object, error) {
	count, consumed, err := readCount(r, size, offset, limit, low)
	if err != nil {
		return Object{}, err
	}
	if count > uint64(size) {
		return Object{}, fmt.Errorf("%w: dictionary of %d pairs at %d is too large",
			ErrTruncated, count, offset)
	}
	start := offset + consumed
	keys, err := readRefs(r, size, start, limit, count, refSize, numObjects)
	if err != nil {
		return Object{}, err
	}
	values, err := readRefs(r, size, start+int64(count)*int64(refSize), limit, count, refSize, numObjects)
	if err != nil {
		return Object{}, err
	}
	object.Type = TypeDictionary
	object.Keys = keys
	object.Values = values
	return object, nil
}

// readRefs reads count object references and validates each against the table.
func readRefs(r io.ReaderAt, size int64, pos, limit int64, count uint64, refSize int, numObjects uint64) ([]uint64, error) {
	if count > uint64(size) {
		return nil, fmt.Errorf("%w: %d references at %d are too many", ErrTruncated, count, pos)
	}
	bytes := count * uint64(refSize)
	if bytes > uint64(size) || pos < 0 || pos+int64(bytes) > limit {
		return nil, fmt.Errorf("%w: %d reference bytes at %d extend beyond the object area",
			ErrTruncated, bytes, pos)
	}
	raw, err := readBytes(r, pos, int(bytes), size)
	if err != nil {
		return nil, err
	}
	refs := make([]uint64, count)
	for i := uint64(0); i < count; i++ {
		value := uint64(0)
		for _, b := range raw[i*uint64(refSize) : (i+1)*uint64(refSize)] {
			value = value<<8 | uint64(b)
		}
		if value >= numObjects {
			return nil, fmt.Errorf("%w: reference %d at index %d is outside %d objects",
				ErrInvalid, value, i, numObjects)
		}
		refs[i] = value
	}
	return refs, nil
}

// walk marks reachable objects and enforces the depth limit from the top
// object. Object-table order is preserved; only Depth and Reachable change.
func (p *Plist) walk(limits Limits) {
	if p.TopObject < 0 || p.TopObject >= len(p.Objects) {
		return
	}
	depths := make([]int, len(p.Objects))
	for i := range depths {
		depths[i] = -1
	}
	depths[p.TopObject] = 0
	queue := []int{p.TopObject}
	for len(queue) > 0 {
		index := queue[0]
		queue = queue[1:]
		object := &p.Objects[index]
		object.Reachable = true
		object.Depth = depths[index]

		refs := append(append([]uint64(nil), object.Keys...), object.Values...)
		refs = append(refs, object.Refs...)
		if len(refs) == 0 {
			continue
		}
		if depths[index] >= limits.Depth {
			p.Truncated = true
			object.Limitations = append(object.Limitations, "children exceed the depth limit")
			p.note("object depth limit %d reached at object %d", limits.Depth, index)
			object.Keys, object.Values, object.Refs = nil, nil, nil
			continue
		}
		for _, ref := range refs {
			child := int(ref)
			if depths[child] < 0 {
				depths[child] = depths[index] + 1
				queue = append(queue, child)
			}
		}
	}
	unreachable := 0
	for i := range p.Objects {
		if depths[i] < 0 {
			unreachable++
		}
	}
	if unreachable > 0 {
		p.note("%d objects are not reachable from the top object", unreachable)
	}
}
