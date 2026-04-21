package apkparser

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	stringFlagSorted = 0x00000001
	stringFlagUtf8   = 0x00000100

	// Marker appended to strings that were truncated by the budget.
	truncatedMarker = "<TRUNCATED>"
)

type stringTable struct {
	isUtf8        bool
	stringOffsets []byte
	strings       []string
}

// sanitizeString replaces NUL bytes and invalid UTF-8 sequences with U+FFFE.
func sanitizeString(s string) string {
	if !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		return strings.Map(func(r rune) rune {
			switch r {
			case 0, utf8.RuneError:
				return '\uFFFE'
			default:
				return r
			}
		}, s)
	}
	return s
}

func parseStringTableWithChunk(r io.Reader, budget int64) (res stringTable, err error) {
	id, _, totalLen, err := parseChunkHeader(r)
	if err != nil {
		return
	}

	if id != chunkStringTable {
		err = fmt.Errorf("Invalid chunk id 0x%08x, expected 0x%08x", id, chunkStringTable)
		return
	}

	return parseStringTable(&io.LimitedReader{R: r, N: int64(totalLen) - chunkHeaderSize}, budget)
}

func parseStringTable(r *io.LimitedReader, budget int64) (stringTable, error) {
	var err error
	var stringCnt, stringOffset, flags uint32
	var res stringTable

	if err := binary.Read(r, binary.LittleEndian, &stringCnt); err != nil {
		return res, fmt.Errorf("error reading stringCnt: %s", err.Error())
	}

	// skip styles count
	if _, err = io.CopyN(ioutil.Discard, r, 4); err != nil {
		return res, fmt.Errorf("error reading styleCnt: %s", err.Error())
	}

	if err := binary.Read(r, binary.LittleEndian, &flags); err != nil {
		return res, fmt.Errorf("error reading flags: %s", err.Error())
	}

	res.isUtf8 = (flags & stringFlagUtf8) != 0
	if res.isUtf8 {
		flags &^= stringFlagUtf8
	}
	flags &^= stringFlagSorted // just ignore

	if flags != 0 {
		return res, fmt.Errorf("Unknown string flag: 0x%08x", flags)
	}

	if err := binary.Read(r, binary.LittleEndian, &stringOffset); err != nil {
		return res, fmt.Errorf("error reading stringOffset: %s", err.Error())
	}

	// skip styles offset
	if _, err = io.CopyN(ioutil.Discard, r, 4); err != nil {
		return res, fmt.Errorf("error reading styleOffset: %s", err.Error())
	}

	// Read lengths
	if stringCnt >= 2*1024*1024 {
		return res, fmt.Errorf("Too many strings in this file (%d).", stringCnt)
	}

	remainder := int64(stringOffset) - 7*4 - 4*int64(stringCnt)
	if remainder < 0 {
		// eb9b8603b58f1829cad3efba7c81eb8fe7bf6a97fc4007d02533b5c2c3cd69b4
		if remainder%4 == 0 && uint32((-1*remainder)/4) < stringCnt {
			stringCnt -= uint32(-1*remainder/4)
		} else {
			return res, fmt.Errorf("Wrong string offset (got remainder %d)", remainder)
		}
	}

	// Validate that the string offsets fit within available data.
	if 4*int64(stringCnt) > r.N {
		return res, fmt.Errorf("string count %d requires %d offset bytes but only %d available",
			stringCnt, 4*int64(stringCnt), r.N)
	}

	res.stringOffsets = make([]byte, 4*stringCnt)
	if _, err := io.ReadFull(r, res.stringOffsets); err != nil {
		return res, fmt.Errorf("Failed to read string offsets data: %s", err.Error())
	}

	if remainder > 0 {
		if _, err = io.CopyN(ioutil.Discard, r, remainder); err != nil {
			return res, fmt.Errorf("error reading styleArray: %s", err.Error())
		}
	}

	// Stream through the data section once, parsing each string at its
	// offset. For small tables this is equivalent to the old bulk-read
	// approach; for oversize tables (inflated string tables used for
	// it avoids buffering the entire declared section.
	// Strings are clipped (longest first) to fit within maxTotalStringBytes.
	res.strings = make([]string, stringCnt)

	if r.N <= 0 {
		return res, nil
	}

	// Build offset → []idx mapping and a sorted list of unique offsets.
	offsetMap := make(map[int64]*pendingStr)
	for i := uint32(0); i < stringCnt; i++ {
		off := int64(binary.LittleEndian.Uint32(res.stringOffsets[4*i : 4*i+4]))
		if p, ok := offsetMap[off]; ok {
			p.idxs = append(p.idxs, i)
		} else {
			offsetMap[off] = &pendingStr{offset: off, idxs: []uint32{i}}
		}
	}

	pending := make([]*pendingStr, 0, len(offsetMap))
	for _, p := range offsetMap {
		pending = append(pending, p)
	}
	sort.Slice(pending, func(i, j int) bool {
		return pending[i].offset < pending[j].offset
	})

	// Compute slot sizes: gap between consecutive offsets gives an upper
	// bound on the encoded byte size of each string. The last string's
	// slot extends to the end of the data section.
	dataLen := r.N
	for i, p := range pending {
		if i+1 < len(pending) {
			p.slotSize = pending[i+1].offset - p.offset
		} else {
			p.slotSize = dataLen - p.offset
		}
		if p.slotSize < 0 {
			p.slotSize = 0
		}
	}

	// Compute per-string byte limits so the total fits within the budget.
	computeStringBudget(pending, budget)

	pos := int64(0) // current position in data section stream
	for _, p := range pending {
		if p.offset < pos {
			continue // stream is past this offset
		}

		// Skip gap to this string.
		if skip := p.offset - pos; skip > 0 {
			n, err := io.CopyN(ioutil.Discard, r, skip)
			pos += n
			if err != nil {
				break
			}
		}

		s, n, err := readStringFromStream(r, res.isUtf8, p.maxData)
		pos += n
		if err != nil {
			break
		}
		s = sanitizeString(s)
		for _, idx := range p.idxs {
			res.strings[idx] = s
		}
	}

	// Caller (binxml.go) drains remaining lm.N bytes.
	return res, nil
}

func (t *stringTable) get(idx uint32) (string, error) {
	if idx == math.MaxUint32 {
		return "", nil
	}

	if idx >= uint32(len(t.strings)) {
		return "", fmt.Errorf("String with idx %d not found!", idx)
	}

	return t.strings[idx], nil
}

func (t *stringTable) isEmpty() bool {
	return t.strings == nil
}

type pendingStr struct {
	offset   int64
	slotSize int64 // estimated data bytes for this string (gap to next offset)
	maxData  int64 // budget-assigned byte limit for reading
	idxs     []uint32
}

// computeStringBudget assigns per-string byte limits (p.maxData) so that
// the total decoded content fits within budget. Small strings keep their
// full slot; only the largest entries are clipped. Algorithm: sort slot
// sizes ascending, walk through accumulating; when the next slot would
// push total over budget, the remaining budget divided evenly among the
// remaining (larger) strings gives the clip cap.
func computeStringBudget(pending []*pendingStr, budget int64) {
	if len(pending) == 0 {
		return
	}

	// Collect slot sizes and check if everything fits.
	sizes := make([]int64, len(pending))
	var total int64
	for i, p := range pending {
		sizes[i] = p.slotSize
		total += p.slotSize
	}

	if total <= budget {
		// Everything fits — no clipping needed.
		for _, p := range pending {
			p.maxData = p.slotSize
		}
		return
	}

	// Sort sizes ascending to find the clip threshold.
	sorted := make([]int64, len(sizes))
	copy(sorted, sizes)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	remaining := budget
	n := int64(len(sorted))
	var clipCap int64

	for i, sz := range sorted {
		// If we give this string its full slot, how much is left per remaining?
		countLeft := n - int64(i)
		if sz*countLeft <= remaining {
			// This string (and all smaller) fit at full size.
			remaining -= sz
			continue
		}
		// Budget exceeded: distribute remaining evenly among this and larger strings.
		clipCap = remaining / countLeft
		break
	}

	// If clipCap is still 0 but budget > 0, the loop above ran to completion
	// without breaking (shouldn't happen when total > budget, but be safe).
	if clipCap == 0 && remaining > 0 {
		clipCap = remaining / int64(len(sorted))
	}

	for _, p := range pending {
		if p.slotSize <= clipCap {
			p.maxData = p.slotSize
		} else {
			p.maxData = clipCap
		}
	}
}

// readStringFromStream reads a single string directly from a forward-only
// stream. maxDataBytes limits how many content bytes are kept; excess is
// skipped to maintain stream position. Returns the decoded string, bytes
// consumed, and any error.
func readStringFromStream(r io.Reader, isUtf8 bool, maxDataBytes int64) (string, int64, error) {
	if isUtf8 {
		return readString8FromStream(r, maxDataBytes)
	}
	return readString16FromStream(r, maxDataBytes)
}

func readString16FromStream(r io.Reader, maxDataBytes int64) (string, int64, error) {
	var consumed int64

	var charHigh uint16
	if err := binary.Read(r, binary.LittleEndian, &charHigh); err != nil {
		return "", 0, err
	}
	consumed += 2

	var strChars uint32
	if (charHigh & 0x8000) != 0 {
		var charLow uint16
		if err := binary.Read(r, binary.LittleEndian, &charLow); err != nil {
			return "", consumed, err
		}
		consumed += 2
		strChars = (uint32(charHigh&0x7FFF) << 16) | uint32(charLow)
	} else {
		strChars = uint32(charHigh)
	}

	dataBytes := int64(strChars) * 2

	// Determine how many chars to actually read (clip if over budget).
	readBytes := dataBytes
	if readBytes > maxDataBytes {
		readBytes = maxDataBytes &^ 1 // round down to even (UTF-16 pair boundary)
	}
	readChars := readBytes / 2

	buf := make([]uint16, readChars)
	if readChars > 0 {
		if err := binary.Read(r, binary.LittleEndian, buf); err != nil {
			return "", consumed, err
		}
		consumed += readBytes
	}

	// Skip any remaining data bytes we didn't read, plus the 2-byte null terminator.
	skipBytes := dataBytes - readBytes + 2
	if skipBytes > 0 {
		n, err := io.CopyN(ioutil.Discard, r, skipBytes)
		consumed += n
		if err != nil {
			// Best-effort: return what we have so far.
			decoded := utf16.Decode(buf)
			return string(trimNulRunes(decoded)), consumed, err
		}
	}

	decoded := utf16.Decode(buf)
	s := string(trimNulRunes(decoded))
	if readBytes < dataBytes && len(s) > len(truncatedMarker) {
		s = s[:len(s)-len(truncatedMarker)] + truncatedMarker
	}
	return s, consumed, nil
}

func trimNulRunes(rs []rune) []rune {
	for len(rs) != 0 && rs[len(rs)-1] == 0 {
		rs = rs[:len(rs)-1]
	}
	return rs
}

func readString8FromStream(r io.Reader, maxDataBytes int64) (string, int64, error) {
	var consumed int64

	readByte := func() (uint8, error) {
		var b uint8
		if err := binary.Read(r, binary.LittleEndian, &b); err != nil {
			return 0, err
		}
		consumed++
		return b, nil
	}

	// UTF-16 length (1-2 bytes, discarded).
	b, err := readByte()
	if err != nil {
		return "", consumed, err
	}
	if (b & 0x80) != 0 {
		if _, err := readByte(); err != nil {
			return "", consumed, err
		}
	}

	// UTF-8 length (1-2 bytes).
	b, err = readByte()
	if err != nil {
		return "", consumed, err
	}
	var len8 int64
	if (b & 0x80) != 0 {
		bLow, err := readByte()
		if err != nil {
			return "", consumed, err
		}
		len8 = int64(b&0x7F)<<8 | int64(bLow)
	} else {
		len8 = int64(b)
	}

	// Determine how many bytes to actually read (clip if over budget).
	readLen := len8
	if readLen > maxDataBytes {
		readLen = maxDataBytes
	}

	buf := make([]byte, readLen)
	if readLen > 0 {
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", consumed, err
		}
		consumed += readLen
	}

	// Skip remaining data bytes + null terminator.
	skipBytes := len8 - readLen + 1
	if skipBytes > 0 {
		n, err := io.CopyN(ioutil.Discard, r, skipBytes)
		consumed += n
		if err != nil {
			// Best-effort: return what we have.
			return string(trimNulBytes(buf)), consumed, err
		}
	}

	// If we clipped mid-string, ensure we don't break a UTF-8 sequence.
	clipped := readLen < len8
	if clipped {
		buf = trimIncompleteUTF8(buf)
	}

	s := string(trimNulBytes(buf))
	if clipped && len(s) > len(truncatedMarker) {
		s = s[:len(s)-len(truncatedMarker)] + truncatedMarker
	}
	return s, consumed, nil
}

func trimNulBytes(b []byte) []byte {
	for len(b) != 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	return b
}

// trimIncompleteUTF8 removes trailing bytes that form an incomplete UTF-8
// sequence (can happen when we clip in the middle of a multi-byte char).
func trimIncompleteUTF8(b []byte) []byte {
	if len(b) == 0 || utf8.Valid(b) {
		return b
	}
	// Walk back at most 3 bytes (max UTF-8 continuation) to find a clean cut.
	for i := 1; i <= 3 && i <= len(b); i++ {
		if utf8.Valid(b[:len(b)-i]) {
			return b[:len(b)-i]
		}
	}
	return b
}
