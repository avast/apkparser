package binxml

import (
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	chunkNull        = 0x0000
	chunkStringTable = 0x0001
	chunkTable       = 0x0002
	chunkAxmlFile    = 0x0003
	chunkResourceIds = 0x0180

	chunkMaskXml     = 0x0100
	chunkXmlNsStart  = 0x0100
	chunkXmlNsEnd    = 0x0101
	chunkXmlTagStart = 0x0102
	chunkXmlTagEnd   = 0x0103
	chunkXmlText     = 0x0104

	attrIdxNamespace = 0
	attrIdxName      = 1
	attrIdxString    = 2
	attrIdxType      = 3
	attrIdxData      = 4
	attrValuesCount  = 5

	attrTypeReference = 1
	attrTypeString    = 3
	attrTypeIntDec    = 16
	attrTypeIntHex    = 17
	attrTypeIntBool   = 18

	stringFlagSorted = 0x00000001
	stringFlagUtf8   = 0x00000100
)

type binXmlParseInfo struct {
	stringTable []string
	resourceIds []uint32

	encoder Encoder
}

func Parse(r io.Reader, enc Encoder) error {
	x := binXmlParseInfo{
		encoder: enc,
	}

	id, _, totalLen, err := x.parseChunkHeader(r)
	if err != nil {
		return nil
	}

	// Android doesn't care.
	/*if id != chunkAxmlFile {
	    return fmt.Errorf("Invalid top chunk id: 0x%08x", id)
	}*/

	defer x.encoder.Flush()

	totalLen -= 2 * 4
	var len uint32
	var lastId uint16
	for i := uint32(0); i < totalLen; i += len {
		id, _, len, err = x.parseChunkHeader(r)
		if err != nil {
			return fmt.Errorf("Error parsing header at 0x%08x of 0x%08x %08x: %s", i, totalLen, lastId, err.Error())
		}

		lastId = id

		lm := &io.LimitedReader{R: r, N: int64(len) - 2*4}

		switch id {
		case chunkStringTable:
			err = x.parseStringTable(lm)
		case chunkResourceIds:
			err = x.parseResourceIds(lm)
		default:
			if (id & chunkMaskXml) == 0 {
				err = fmt.Errorf("Unknown chunk id 0x%x", id)
				break
			}

			// skip line number and unknown 0xFFFFFFFF
			if _, err = io.CopyN(ioutil.Discard, lm, 2*4); err != nil {
				break
			}

			switch id {
			case chunkXmlNsStart:
				err = x.parseNsStart(lm)
			case chunkXmlNsEnd:
				err = x.parseNsEnd(lm)
			case chunkXmlTagStart:
				err = x.parseTagStart(lm)
			case chunkXmlTagEnd:
				err = x.parseTagEnd(lm)
			case chunkXmlText:
				err = x.parseText(lm)
			default:
				err = fmt.Errorf("Unknown chunk id 0x%x", id)
			}
		}

		if err != nil {
			return fmt.Errorf("Chunk: 0x%08x: %s", id, err.Error())
		} else if lm.N != 0 {
			return fmt.Errorf("Chunk: 0x%08x: was not fully read", id)
		}
	}
	return nil
}

func (x *binXmlParseInfo) getString(idx uint32) (string, error) {
	if idx == math.MaxUint32 {
		return "", nil
	} else if idx > uint32(len(x.stringTable)) {
		return "", fmt.Errorf("String with idx %d not found!", idx)
	} else {
		return x.stringTable[idx], nil
	}
}

func (*binXmlParseInfo) parseChunkHeader(r io.Reader) (id, headerLen uint16, len uint32, err error) {
	if err = binary.Read(r, binary.LittleEndian, &id); err != nil {
		return
	}

	if err = binary.Read(r, binary.LittleEndian, &headerLen); err != nil {
		return
	}

	if err = binary.Read(r, binary.LittleEndian, &len); err != nil {
		return
	}
	return
}

func (x *binXmlParseInfo) parseString16(r *io.LimitedReader, bufPtr *[]uint16) (string, uint32, error) {
	var strCharacters uint32
	var strCharactersLow, strCharactersHigh uint16
	var readBytes uint32

	if err := binary.Read(r, binary.LittleEndian, &strCharactersHigh); err != nil {
		return "", 0, fmt.Errorf("error reading string char count: %s %d %d", err.Error(), r.N, r.N)
	}
	readBytes += 2

	if (strCharactersHigh & 0x8000) != 0 {
		if err := binary.Read(r, binary.LittleEndian, &strCharactersLow); err != nil {
			return "", 0, fmt.Errorf("error reading string char count: %s %d %d", err.Error(), r.N, r.N)
		}
		readBytes += 2

		strCharacters = (uint32(strCharactersHigh&0x7FFF) << 16) | uint32(strCharactersLow)
	} else {
		strCharacters = uint32(strCharactersHigh)
	}

	buf := *bufPtr
	buf = buf[:cap(buf)]
	utfDataPairs := int64(strCharacters)
	if int64(len(buf)) < utfDataPairs {
		buf = append(buf, make([]uint16, utfDataPairs-int64(len(buf)))...)
	} else {
		buf = buf[:utfDataPairs]
	}
	*bufPtr = buf

	if err := binary.Read(r, binary.LittleEndian, &buf); err != nil {
		return "", 0, fmt.Errorf("error reading string : %s", err.Error())
	}

	readBytes += uint32(len(buf) * 2)

	decoded := utf16.Decode(buf)
	for len(decoded) != 0 && decoded[len(decoded)-1] == 0 {
		decoded = decoded[:len(decoded)-1]
	}

	return string(decoded), readBytes, nil
}

func (x *binXmlParseInfo) parseString8Len(r *io.LimitedReader, readBytes *uint32) (int64, error) {
	var strCharacters int64
	var strCharactersLow, strCharactersHigh uint8

	if err := binary.Read(r, binary.LittleEndian, &strCharactersHigh); err != nil {
		return 0, fmt.Errorf("error reading string char count: %s %d %d", err.Error(), r.N, r.N)
	}
	*readBytes++

	if (strCharactersHigh & 0x80) != 0 {
		if err := binary.Read(r, binary.LittleEndian, &strCharactersLow); err != nil {
			return 0, fmt.Errorf("error reading string char count: %s %d %d", err.Error(), r.N, r.N)
		}
		*readBytes++
		strCharacters = (int64(strCharactersHigh&0x7F) << 8) | int64(strCharactersLow)
	} else {
		strCharacters = int64(strCharactersHigh)
	}
	return strCharacters, nil
}

func (x *binXmlParseInfo) parseString8(r *io.LimitedReader, bufPtr *[]uint8) (string, uint32, error) {
	var readBytes uint32

	// Length of the string in UTF16
	_, err := x.parseString8Len(r, &readBytes)
	if err != nil {
		return "", 0, err
	}

	len8, err := x.parseString8Len(r, &readBytes)
	if err != nil {
		return "", 0, err
	}

	buf := *bufPtr
	buf = buf[:cap(buf)]
	if int64(len(buf)) < len8 {
		buf = append(buf, make([]uint8, len8-int64(len(buf)))...)
	} else {
		buf = buf[:len8]
	}
	*bufPtr = buf

	if err := binary.Read(r, binary.LittleEndian, &buf); err != nil {
		return "", 0, fmt.Errorf("error reading string : %s", err.Error())
	}

	readBytes += uint32(len(buf))

	for len(buf) != 0 && buf[len(buf)-1] == 0 {
		buf = buf[:len(buf)-1]
	}

	if !utf8.Valid(buf) {
		return "", 0, fmt.Errorf("invalid utf8 sequence: %v", buf)
	}

	return string(buf), readBytes, nil
}

func (x *binXmlParseInfo) parseStringTable(r *io.LimitedReader) error {
	var err error
	var stringCnt, stringOffset, flags uint32

	if err := binary.Read(r, binary.LittleEndian, &stringCnt); err != nil {
		return fmt.Errorf("error reading stringCnt: %s", err.Error())
	}

	// skip styles count
	if _, err = io.CopyN(ioutil.Discard, r, 4); err != nil {
		return fmt.Errorf("error reading styleCnt: %s", err.Error())
	}

	if err := binary.Read(r, binary.LittleEndian, &flags); err != nil {
		return fmt.Errorf("error reading flags: %s", err.Error())
	}

	isUtf8 := (flags & stringFlagUtf8) != 0
	if isUtf8 {
		flags &^= stringFlagUtf8
	}
	flags &^= stringFlagSorted // just ignore

	if flags != 0 {
		return fmt.Errorf("Unknown string flag: 0x%08x", flags)
	}

	if err := binary.Read(r, binary.LittleEndian, &stringOffset); err != nil {
		return fmt.Errorf("error reading stringOffset: %s", err.Error())
	}

	// skip styles offset
	if _, err = io.CopyN(ioutil.Discard, r, 4); err != nil {
		return fmt.Errorf("error reading styleOffset: %s", err.Error())
	}

	// Read lengths
	var curOff uint32
	var stringOffsets []uint32
	for i := uint32(0); i < stringCnt; i++ {
		if err := binary.Read(r, binary.LittleEndian, &curOff); err != nil {
			return fmt.Errorf("error reading stringOffset: %s", err.Error())
		}
		stringOffsets = append(stringOffsets, curOff)
	}

	remainder := int64(stringOffset) - 7*4 - 4*int64(stringCnt)
	if remainder < 0 {
		return fmt.Errorf("Wrong string offset (got remainder %d)", remainder)
	} else if remainder > 0 {
		if _, err = io.CopyN(ioutil.Discard, r, remainder); err != nil {
			return fmt.Errorf("error reading styleArray: %s", err.Error())
		}
	}

	// Read strings
	var buf16 []uint16
	var buf8 []uint8
	offsetMap := make(map[uint32]int)
	read := uint32(0)
	for i := uint32(0); i < stringCnt; i++ {
		off := stringOffsets[i]
		if strIdx, present := offsetMap[off]; present {
			if strIdx > len(x.stringTable) {
				return fmt.Errorf("malformed string table")
			}
			x.stringTable = append(x.stringTable, x.stringTable[strIdx])
			continue
		}

		if off > read {
			if _, err = io.CopyN(ioutil.Discard, r, int64(off-read)); err != nil {
				return fmt.Errorf("error reading string padding: %s", err.Error())
			}
			read += off - read
		}

		var decoded string
		var readBytes uint32
		if isUtf8 {
			if decoded, readBytes, err = x.parseString8(r, &buf8); err != nil {
				return err
			}
		} else {
			if decoded, readBytes, err = x.parseString16(r, &buf16); err != nil {
				return err
			}
		}

		x.stringTable = append(x.stringTable, decoded)
		offsetMap[off] = len(x.stringTable) - 1
		read += readBytes
	}

	if r.N != 0 {
		if _, err = io.CopyN(ioutil.Discard, r, r.N); err != nil {
			return fmt.Errorf("error reading string table padding: %s", err.Error())
		}
	}

	return nil
}

func (x *binXmlParseInfo) parseResourceIds(r *io.LimitedReader) error {
	if (r.N % 4) != 0 {
		return fmt.Errorf("Invalid chunk size!")
	}

	count := uint32((r.N / 4))
	var id uint32
	for i := uint32(0); i < count; i++ {
		if err := binary.Read(r, binary.LittleEndian, &id); err != nil {
			return err
		}
		x.resourceIds = append(x.resourceIds, id)
	}
	return nil
}

func (x *binXmlParseInfo) parseNsStart(r *io.LimitedReader) error {
	var err error
	ns := &xml.Name{}

	var idx uint32
	if err = binary.Read(r, binary.LittleEndian, &idx); err != nil {
		return err
	}

	if ns.Local, err = x.getString(idx); err != nil {
		return err
	}

	if err = binary.Read(r, binary.LittleEndian, &idx); err != nil {
		return err
	}

	if ns.Space, err = x.getString(idx); err != nil {
		return err
	}

	// TODO: what to do with this?
	_ = ns
	return nil
}

func (x *binXmlParseInfo) parseNsEnd(r *io.LimitedReader) error {
	if _, err := io.CopyN(ioutil.Discard, r, 2*4); err != nil {
		return fmt.Errorf("error skipping: %s", err.Error())
	}

	// TODO: what to do with this?
	return nil
}

func (x *binXmlParseInfo) parseTagStart(r *io.LimitedReader) error {
	var namespaceIdx, nameIdx, attrCnt, classAttrIdx uint32

	if err := binary.Read(r, binary.LittleEndian, &namespaceIdx); err != nil {
		return fmt.Errorf("error reading namespace idx: %s", err.Error())
	}

	if err := binary.Read(r, binary.LittleEndian, &nameIdx); err != nil {
		return fmt.Errorf("error reading name idx: %s", err.Error())
	}

	if _, err := io.CopyN(ioutil.Discard, r, 4); err != nil {
		return fmt.Errorf("error skipping flag: %s", err.Error())
	}

	if err := binary.Read(r, binary.LittleEndian, &attrCnt); err != nil {
		return fmt.Errorf("error reading attrCnt: %s", err.Error())
	}

	if err := binary.Read(r, binary.LittleEndian, &classAttrIdx); err != nil {
		return fmt.Errorf("error reading classAttr: %s", err.Error())
	}

	idAttributeIdx := (attrCnt >> 16) - 1
	attrCnt = (attrCnt & 0xFFFF)

	styleAttrIdx := (classAttrIdx >> 16) - 1
	classAttrIdx = (classAttrIdx & 0xFFFF)

	_ = styleAttrIdx
	_ = idAttributeIdx

	namespace, err := x.getString(namespaceIdx)
	if err != nil {
		return fmt.Errorf("error decoding namespace: %s", err.Error())
	}

	name, err := x.getString(nameIdx)
	if err != nil {
		return fmt.Errorf("error decoding name: %s", err.Error())
	}

	tok := xml.StartElement{
		Name: xml.Name{Local: name, Space: namespace},
	}

	var attrData [attrValuesCount]uint32
	for i := uint32(0); i < attrCnt; i++ {
		if err := binary.Read(r, binary.LittleEndian, &attrData); err != nil {
			return fmt.Errorf("error reading attrData: %s", err.Error())
		}

		// Android actually reads attributes purely by their IDs (see frameworks/base/core/res/res/values/attrs_manifest.xml
		// and its generated R class, that's where the indexes come from, namely the AndroidManifestActivity array)
		// but good guy android actually puts the strings into the string table on the same indexes anyway, most of the time.
		// This is for the samples that don't have it, mostly due to obfuscators/minimizers.
		// The ID can't change, because it would break current APKs.
		var attrName string
		if attrData[attrIdxName] < uint32(len(x.resourceIds)) {
			attrName = getAttributteName(x.resourceIds[attrData[attrIdxName]])
		}

		if attrName == "" {
			attrName, err = x.getString(attrData[attrIdxName])
			if err != nil {
				return fmt.Errorf("error decoding attrNameIdx: %s", err.Error())
			}
		}

		attrNameSpace, err := x.getString(attrData[attrIdxNamespace])
		if err != nil {
			return fmt.Errorf("error decoding attrNamespaceIdx: %s", err.Error())
		}

		attr := xml.Attr{
			Name: xml.Name{Local: attrName, Space: attrNameSpace},
		}

		switch attrData[attrIdxType] >> 24 {
		case attrTypeString:
			attr.Value, err = x.getString(attrData[attrIdxString])
			if err != nil {
				return fmt.Errorf("error decoding attrStringIdx: %s", err.Error())
			}
		case attrTypeIntBool:
			attr.Value = strconv.FormatBool(attrData[attrIdxData] != 0)
		case attrTypeIntHex:
			attr.Value = fmt.Sprintf("0x%x", attrData[attrIdxData])
		case attrTypeReference:
			attr.Value = fmt.Sprintf("@%x", attrData[attrIdxData])
		default:
			attr.Value = strconv.FormatInt(int64(attrData[attrIdxData]), 10)
		}
		tok.Attr = append(tok.Attr, attr)
	}

	return x.encoder.EncodeToken(tok)
}

func (x *binXmlParseInfo) parseTagEnd(r *io.LimitedReader) error {
	var namespaceIdx, nameIdx uint32
	if err := binary.Read(r, binary.LittleEndian, &namespaceIdx); err != nil {
		return fmt.Errorf("error reading namespace idx: %s", err.Error())
	}

	if err := binary.Read(r, binary.LittleEndian, &nameIdx); err != nil {
		return fmt.Errorf("error reading name idx: %s", err.Error())
	}

	namespace, err := x.getString(namespaceIdx)
	if err != nil {
		return fmt.Errorf("error decoding namespace: %s", err.Error())
	}

	name, err := x.getString(nameIdx)
	if err != nil {
		return fmt.Errorf("error decoding name: %s", err.Error())
	}

	return x.encoder.EncodeToken(xml.EndElement{Name: xml.Name{Local: name, Space: namespace}})
}

func (x *binXmlParseInfo) parseText(r *io.LimitedReader) error {
	var idx uint32
	if err := binary.Read(r, binary.LittleEndian, &idx); err != nil {
		return fmt.Errorf("error reading idx: %s", err.Error())
	}

	text, err := x.getString(idx)
	if err != nil {
		return fmt.Errorf("error decoding idx: %s", err.Error())
	}

	if _, err := io.CopyN(ioutil.Discard, r, 2*4); err != nil {
		return fmt.Errorf("error skipping: %s", err.Error())
	}

	return x.encoder.EncodeToken(xml.CharData(text))
}
