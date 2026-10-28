package apk

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
)

// signingBlockMagic is the trailing magic of the APK Signing Block.
const signingBlockMagic = "APK Sig Block 42"

// signingBlockFooterBytes is the size field plus magic at the end of the block.
const signingBlockFooterBytes = 24

// Known signing block identifiers.
const (
	idV2          uint32 = 0x7109871a
	idV3          uint32 = 0xf05368c0
	idV31         uint32 = 0x1b93ad61
	idSourceStamp uint32 = 0x6dff800d
	idVerityPad   uint32 = 0x42726577
)

// schemeOf names a known signing block pair.
func schemeOf(id uint32) string {
	switch id {
	case idV2:
		return "v2"
	case idV3:
		return "v3"
	case idV31:
		return "v3.1"
	case idSourceStamp:
		return "source_stamp"
	case idVerityPad:
		return "verity_padding"
	default:
		return ""
	}
}

// readFooter reads the fixed signing block footer. A footer that does not fit
// means the artifact has no block, not that it is invalid.
func readFooter(r io.ReaderAt, size, cdOffset int64) ([]byte, bool) {
	footer, err := readAt(r, cdOffset-signingBlockFooterBytes, signingBlockFooterBytes, size)
	return footer, err == nil
}

// parseSigningBlock reads the APK Signing Block that ends at cdOffset.
//
// A block whose magic is absent is not an error: most artifacts carry only a
// scheme v1 signature in META-INF. A block whose declared sizes contradict the
// artifact is invalid, because a partial pair list would understate the
// signing metadata.
func parseSigningBlock(r io.ReaderAt, size, cdOffset int64, limits Limits) (SigningBlock, error) {
	if cdOffset < signingBlockFooterBytes+8 || cdOffset > size {
		return SigningBlock{}, nil
	}
	footer, ok := readFooter(r, size, cdOffset)
	if !ok || string(footer[8:]) != signingBlockMagic {
		return SigningBlock{}, nil
	}
	declared := binary.LittleEndian.Uint64(footer)
	if declared < signingBlockFooterBytes || declared > uint64(cdOffset) {
		return SigningBlock{}, fmt.Errorf(
			"%w: signing block size %d does not fit before the central directory at %d",
			ErrInvalid, declared, cdOffset)
	}
	total := declared + 8
	offset := cdOffset - int64(total)
	head, err := readAt(r, offset, 8, size)
	if err != nil {
		return SigningBlock{}, err
	}
	if binary.LittleEndian.Uint64(head) != declared {
		return SigningBlock{}, fmt.Errorf(
			"%w: signing block sizes disagree: %d and %d",
			ErrInvalid, binary.LittleEndian.Uint64(head), declared)
	}

	block := SigningBlock{
		Present: true,
		Offset:  offset,
		Size:    total,
	}
	pairs := declared - signingBlockFooterBytes
	read := pairs
	if read > uint64(limits.SigningBytes) {
		read = uint64(limits.SigningBytes)
		block.Truncated = true
		block.Limitations = append(block.Limitations,
			fmt.Sprintf("signing block pair area exceeds %d bytes", limits.SigningBytes))
	}
	area, err := readAt(r, offset+8, int(read), size)
	if err != nil {
		return SigningBlock{}, err
	}

	pos := 0
	for pos < len(area) {
		if len(area)-pos < 8 {
			block.Truncated = true
			block.Limitations = append(block.Limitations,
				"signing block ends inside a pair length")
			break
		}
		length := binary.LittleEndian.Uint64(area[pos:])
		if length < 4 {
			return SigningBlock{}, fmt.Errorf("%w: signing pair length %d is below 4",
				ErrInvalid, length)
		}
		if length > uint64(len(area)-pos-8) {
			if block.Truncated {
				block.Limitations = append(block.Limitations,
					"signing block pair value is outside the inspected area")
				break
			}
			return SigningBlock{}, fmt.Errorf(
				"%w: signing pair length %d at %d extends beyond the pair area",
				ErrTruncated, length, pos)
		}
		if len(block.Pairs) >= limits.SigningPairs {
			block.Truncated = true
			block.Limitations = append(block.Limitations,
				fmt.Sprintf("signing pair limit %d reached", limits.SigningPairs))
			break
		}
		id := binary.LittleEndian.Uint32(area[pos+8:])
		value := area[pos+12 : pos+8+int(length)]
		sum := sha256.Sum256(value)
		block.Pairs = append(block.Pairs, Pair{
			ID:              id,
			Scheme:          schemeOf(id),
			ValueBytes:      length - 4,
			Digest:          hex.EncodeToString(sum[:]),
			DigestAvailable: true,
		})
		pos += 8 + int(length)
	}
	return block, nil
}
