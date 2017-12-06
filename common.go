package apkparser

import (
	"encoding/binary"
	"io"
)

const (
	chunkNull          = 0x0000
	chunkStringTable   = 0x0001
	chunkTable         = 0x0002
	chunkAxmlFile      = 0x0003
	chunkResourceIds   = 0x0180
	chunkTablePackage  = 0x0200
	chunkTableType     = 0x0201
	chunkTableTypeSpec = 0x0202
	chunkTableLibrary  = 0x0203

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

	attrTypeNull      = 0x00
	attrTypeReference = 0x01
	attrTypeAttribute = 0x02
	attrTypeString    = 0x03
	attrTypeFloat     = 0x04
	attrTypeIntDec    = 0x10
	attrTypeIntHex    = 0x11
	attrTypeIntBool   = 0x12

	attrTypeIntColorArgb8 = 0x1c
	attrTypeIntColorRgb8  = 0x1d
	attrTypeIntColorArgb4 = 0x1e
	attrTypeIntColorRgb4  = 0x1f

	chunkHeaderSize = (2 + 2 + 4)
)

func parseChunkHeader(r io.Reader) (id, headerLen uint16, len uint32, err error) {
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
