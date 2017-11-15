package binxml

import (
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"unsafe"
)

type manifestParseInfo struct {
	strings     stringTable
	resourceIds []uint32

	encoder ManifestEncoder
	res     *ResourceTable
}

func ParseManifest(r io.Reader, enc ManifestEncoder, resources *ResourceTable) error {
	x := manifestParseInfo{
		encoder: enc,
		res:     resources,
	}

	id, _, totalLen, err := parseChunkHeader(r)
	if err != nil {
		return err
	}

	// Android doesn't care.
	/*if id != chunkAxmlFile {
	    return fmt.Errorf("Invalid top chunk id: 0x%08x", id)
	}*/

	defer x.encoder.Flush()

	totalLen -= chunkHeaderSize

	var len uint32
	var lastId uint16
	for i := uint32(0); i < totalLen; i += len {
		id, _, len, err = parseChunkHeader(r)
		if err != nil {
			return fmt.Errorf("Error parsing header at 0x%08x of 0x%08x %08x: %s", i, totalLen, lastId, err.Error())
		}

		lastId = id

		lm := &io.LimitedReader{R: r, N: int64(len) - 2*4}

		switch id {
		case chunkStringTable:
			x.strings, err = parseStringTable(lm)
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

func (x *manifestParseInfo) parseResourceIds(r *io.LimitedReader) error {
	if (r.N % 4) != 0 {
		return fmt.Errorf("Invalid chunk size!")
	}

	count := uint32(r.N / 4)
	var id uint32
	for i := uint32(0); i < count; i++ {
		if err := binary.Read(r, binary.LittleEndian, &id); err != nil {
			return err
		}
		x.resourceIds = append(x.resourceIds, id)
	}
	return nil
}

func (x *manifestParseInfo) parseNsStart(r *io.LimitedReader) error {
	var err error
	ns := &xml.Name{}

	var idx uint32
	if err = binary.Read(r, binary.LittleEndian, &idx); err != nil {
		return err
	}

	if ns.Local, err = x.strings.get(idx); err != nil {
		return err
	}

	if err = binary.Read(r, binary.LittleEndian, &idx); err != nil {
		return err
	}

	if ns.Space, err = x.strings.get(idx); err != nil {
		return err
	}

	// TODO: what to do with this?
	_ = ns
	return nil
}

func (x *manifestParseInfo) parseNsEnd(r *io.LimitedReader) error {
	if _, err := io.CopyN(ioutil.Discard, r, 2*4); err != nil {
		return fmt.Errorf("error skipping: %s", err.Error())
	}

	// TODO: what to do with this?
	return nil
}

func (x *manifestParseInfo) parseTagStart(r *io.LimitedReader) error {
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

	namespace, err := x.strings.get(namespaceIdx)
	if err != nil {
		return fmt.Errorf("error decoding namespace: %s", err.Error())
	}

	name, err := x.strings.get(nameIdx)
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
			attrName, err = x.strings.get(attrData[attrIdxName])
			if err != nil {
				return fmt.Errorf("error decoding attrNameIdx: %s", err.Error())
			}
		}

		attrNameSpace, err := x.strings.get(attrData[attrIdxNamespace])
		if err != nil {
			return fmt.Errorf("error decoding attrNamespaceIdx: %s", err.Error())
		}

		attr := xml.Attr{
			Name: xml.Name{Local: attrName, Space: attrNameSpace},
		}

		switch attrData[attrIdxType] >> 24 {
		case attrTypeString:
			attr.Value, err = x.strings.get(attrData[attrIdxString])
			if err != nil {
				return fmt.Errorf("error decoding attrStringIdx: %s", err.Error())
			}
		case attrTypeIntBool:
			attr.Value = strconv.FormatBool(attrData[attrIdxData] != 0)
		case attrTypeIntHex:
			attr.Value = fmt.Sprintf("0x%x", attrData[attrIdxData])
		case attrTypeFloat:
			val := (*float32)(unsafe.Pointer(&attrData[attrIdxData]))
			attr.Value = fmt.Sprintf("%g", *val)
		case attrTypeReference:
			if x.res != nil {
				cfg := ConfigFirst
				if attr.Name.Local == "icon" {
					cfg = ConfigLast
				}

				e, err := x.res.GetResourceEntryEx(attrData[attrIdxData], cfg)
				if err == nil {
					for i := 0; e.value.dataType == attrTypeReference && i < 5; i++ {
						lower, err := x.res.GetResourceEntryEx(e.value.data, cfg)
						if err != nil {
							break
						}
						e = lower
					}
					attr.Value = e.value.String()
				}
			}

			if attr.Value == "" {
				attr.Value = fmt.Sprintf("@%x", attrData[attrIdxData])
			}
		default:
			attr.Value = strconv.FormatInt(int64(attrData[attrIdxData]), 10)
		}
		tok.Attr = append(tok.Attr, attr)
	}

	return x.encoder.EncodeToken(tok)
}

func (x *manifestParseInfo) parseTagEnd(r *io.LimitedReader) error {
	var namespaceIdx, nameIdx uint32
	if err := binary.Read(r, binary.LittleEndian, &namespaceIdx); err != nil {
		return fmt.Errorf("error reading namespace idx: %s", err.Error())
	}

	if err := binary.Read(r, binary.LittleEndian, &nameIdx); err != nil {
		return fmt.Errorf("error reading name idx: %s", err.Error())
	}

	namespace, err := x.strings.get(namespaceIdx)
	if err != nil {
		return fmt.Errorf("error decoding namespace: %s", err.Error())
	}

	name, err := x.strings.get(nameIdx)
	if err != nil {
		return fmt.Errorf("error decoding name: %s", err.Error())
	}

	return x.encoder.EncodeToken(xml.EndElement{Name: xml.Name{Local: name, Space: namespace}})
}

func (x *manifestParseInfo) parseText(r *io.LimitedReader) error {
	var idx uint32
	if err := binary.Read(r, binary.LittleEndian, &idx); err != nil {
		return fmt.Errorf("error reading idx: %s", err.Error())
	}

	text, err := x.strings.get(idx)
	if err != nil {
		return fmt.Errorf("error decoding idx: %s", err.Error())
	}

	if _, err := io.CopyN(ioutil.Discard, r, 2*4); err != nil {
		return fmt.Errorf("error skipping: %s", err.Error())
	}

	return x.encoder.EncodeToken(xml.CharData(text))
}
