package apkparser

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"io"
	"strings"
	"testing"
)

// writeChunkHeader appends a ResChunk_header to buf.
func writeChunkHeader(buf *bytes.Buffer, id uint16, headerLen uint16, totalLen uint32) {
	binary.Write(buf, binary.LittleEndian, id)
	binary.Write(buf, binary.LittleEndian, headerLen)
	binary.Write(buf, binary.LittleEndian, totalLen)
}

func TestParseChunkHeader(t *testing.T) {
	tests := []struct {
		name      string
		id        uint16
		headerLen uint16
		totalLen  uint32
		wantErr   string // substring; empty means expect success
	}{
		{
			name:      "valid",
			id:        chunkAxmlFile,
			headerLen: 8,
			totalLen:  100,
		},
		{
			name:      "valid/large header",
			id:        chunkStringTable,
			headerLen: 28,
			totalLen:  1024,
		},
		{
			name:      "header too small",
			id:        chunkAxmlFile,
			headerLen: 4,
			totalLen:  100,
			wantErr:   "chunk header size 4 is smaller than minimum",
		},
		{
			name:      "header zero",
			id:        chunkAxmlFile,
			headerLen: 0,
			totalLen:  100,
			wantErr:   "chunk header size 0 is smaller than minimum",
		},
		{
			name:      "total smaller than header",
			id:        chunkAxmlFile,
			headerLen: 8,
			totalLen:  4,
			wantErr:   "chunk total size 4 is smaller than header size 8",
		},
		{
			name:      "total equals header",
			id:        chunkAxmlFile,
			headerLen: 8,
			totalLen:  8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			writeChunkHeader(&buf, tt.id, tt.headerLen, tt.totalLen)

			id, hdrLen, totalLen, err := parseChunkHeader(&buf)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if id != tt.id || hdrLen != tt.headerLen || totalLen != tt.totalLen {
				t.Fatalf("got id=%d hdrLen=%d totalLen=%d, want %d/%d/%d",
					id, hdrLen, totalLen, tt.id, tt.headerLen, tt.totalLen)
			}
		})
	}
}

func TestParseXml_InnerChunkOverflowsParent(t *testing.T) {
	var buf bytes.Buffer

	// Outer AXML chunk: 8-byte header + 16 bytes of data = 24 total.
	writeChunkHeader(&buf, chunkAxmlFile, 8, 24)

	// Inner chunk claiming 1000 bytes, but only 16 bytes remain in parent.
	writeChunkHeader(&buf, chunkStringTable, 8, 1000)
	buf.Write(make([]byte, 8)) // fill the remaining 8 bytes of parent data

	enc := xml.NewEncoder(io.Discard)
	err := ParseXml(&buf, enc, nil)
	if err == nil {
		t.Fatal("expected error for inner chunk overflowing parent")
	}
	if !strings.Contains(err.Error(), "claims") || !strings.Contains(err.Error(), "remain") {
		t.Fatalf("unexpected error: %s", err)
	}
}
func TestParseTypeSpec_EntryCountExceedsData(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(1)                                               // id = 1
	buf.WriteByte(0)                                               // padding res0
	binary.Write(&buf, binary.LittleEndian, uint16(0))             // padding res1
	binary.Write(&buf, binary.LittleEndian, uint32(1_000_000))     // entryCount = 1M

	r := &io.LimitedReader{
		R: &buf,
		N: int64(buf.Len()),
	}

	x := &ResourceTable{packages: make(map[uint32]*packageGroup)}
	pkg := &resourcePackage{}
	group := &packageGroup{types: make(map[uint8][]resourceTypeSpec)}

	err := x.parseTypeSpec(r, pkg, group)
	if err == nil {
		t.Fatal("expected error for entry count exceeding available data")
	}
	if !strings.Contains(err.Error(), "exceeds available data") {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestParseStringTable_StringCountExceedsData(t *testing.T) {
	var buf bytes.Buffer
	stringCnt := uint32(100_000)
	stringOffset := 7*4 + 4*stringCnt // offset that makes remainder = 0

	binary.Write(&buf, binary.LittleEndian, stringCnt)      // stringCnt
	binary.Write(&buf, binary.LittleEndian, uint32(0))       // styleCnt
	binary.Write(&buf, binary.LittleEndian, uint32(0))       // flags (UTF-16)
	binary.Write(&buf, binary.LittleEndian, stringOffset)    // stringsStart
	binary.Write(&buf, binary.LittleEndian, uint32(0))       // stylesStart

	r := &io.LimitedReader{
		R: &buf,
		N: int64(buf.Len()), // only 20 bytes — can't hold 400K offset bytes
	}

	_, err := parseStringTable(r)
	if err == nil {
		t.Fatal("expected error for string count exceeding available data")
	}
	if !strings.Contains(err.Error(), "offset bytes") {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestParseStringTableWithChunk_TotalLenTooSmall(t *testing.T) {
	var buf bytes.Buffer
	// Chunk with totalLen (4) smaller than headerLen (8).
	// parseChunkHeader rejects this before the uint32 underflow can occur.
	writeChunkHeader(&buf, chunkStringTable, 8, 4)

	_, err := parseStringTableWithChunk(&buf)
	if err == nil {
		t.Fatal("expected error for totalLen < headerLen")
	}
	if !strings.Contains(err.Error(), "chunk total size") {
		t.Fatalf("unexpected error: %s", err)
	}
}
