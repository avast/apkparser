package binxml

import (
	"archive/zip"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
)

type zipReaderFileSubEntry struct {
	offset int64
	method uint16
}

type ZipReaderFile struct {
	Name  string
	IsDir bool

	zipFile        *os.File
	internalReader io.ReadCloser

	zipEntry *zip.File

	entries  []zipReaderFileSubEntry
	curEntry int
}

type ZipReader struct {
	File map[string]*ZipReaderFile

	zipFile *os.File
}

func (zr *ZipReaderFile) Open() error {
	if zr.internalReader != nil {
		return errors.New("File is already opened.")
	}

	if zr.zipEntry != nil {
		var err error
		zr.curEntry = 0
		zr.internalReader, err = zr.zipEntry.Open()
		return err
	} else {
		zr.curEntry = -1
	}

	return nil
}

func (zr *ZipReaderFile) Read(p []byte) (int, error) {
	if zr.internalReader == nil {
		if zr.curEntry == -1 && !zr.Next() {
			return 0, io.ErrUnexpectedEOF
		}

		if zr.curEntry >= len(zr.entries) {
			return 0, io.ErrUnexpectedEOF
		}

		_, err := zr.zipFile.Seek(zr.entries[zr.curEntry].offset, 0)
		if err != nil {
			return 0, err
		}

		switch zr.entries[zr.curEntry].method {
		case zip.Deflate:
			zr.internalReader = flate.NewReader(zr.zipFile)
		case zip.Store:
			zr.internalReader = zr.zipFile
		}
	}
	return zr.internalReader.Read(p)
}

func (zr *ZipReaderFile) Next() bool {
	if len(zr.entries) == 0 && zr.internalReader != nil {
		zr.curEntry++
		return zr.curEntry == 1
	}

	if zr.internalReader != nil {
		if zr.internalReader != zr.zipFile {
			zr.internalReader.Close()
		}
		zr.internalReader = nil
	}

	if zr.curEntry+1 >= len(zr.entries) {
		return false
	}
	zr.curEntry++
	return true
}

func (zr *ZipReaderFile) Close() error {
	if zr.internalReader != nil {
		if zr.internalReader != zr.zipFile {
			zr.internalReader.Close()
		}
		zr.internalReader = nil
	}
	return nil
}

func (zr *ZipReader) Close() error {
	if zr.zipFile == nil {
		return nil
	}

	for _, zf := range zr.File {
		zf.Close()
	}

	err := zr.zipFile.Close()
	zr.zipFile = nil
	return err
}

func OpenZip(zippath string) (zr *ZipReader, err error) {
	f, err := os.Open(zippath)
	if err != nil {
		return
	}

	defer func() {
		if err != nil {
			f.Close()
		}
	}()

	zr = &ZipReader{
		File:    make(map[string]*ZipReaderFile),
		zipFile: f,
	}

	var zipinfo *zip.Reader
	zipinfo, err = tryReadZip(f)
	if err == nil {
		for _, zf := range zipinfo.File {
			cl := path.Clean(zf.Name)
			if zr.File[cl] == nil {
				zr.File[cl] = &ZipReaderFile{
					Name:     cl,
					IsDir:    zf.FileInfo().IsDir(),
					zipFile:  f,
					zipEntry: zf,
				}
			}
		}
		return
	}

	f.Seek(0, 0)

	var off int64
	for {
		off, err = findNextFileHeader(f)
		if off == -1 || err != nil {
			return
		}

		var nameLen, extraLen, method uint16
		f.Seek(off+8, 0)
		if err = binary.Read(f, binary.LittleEndian, &method); err != nil {
			return
		}

		f.Seek(off+26, 0)

		if err = binary.Read(f, binary.LittleEndian, &nameLen); err != nil {
			return
		}

		if err = binary.Read(f, binary.LittleEndian, &extraLen); err != nil {
			return
		}

		buf := make([]byte, nameLen)
		if _, err = f.ReadAt(buf, off+30); err != nil {
			return
		}

		fileName := path.Clean(string(buf))
		fileOffset := off + 30 + int64(nameLen) + int64(extraLen)

		zrf := zr.File[fileName]
		if zrf == nil {
			zrf = &ZipReaderFile{
				Name:     fileName,
				zipFile:  f,
				curEntry: -1,
			}
			zr.File[fileName] = zrf
		}

		zrf.entries = append([]zipReaderFileSubEntry{zipReaderFileSubEntry{
			offset: fileOffset,
			method: method,
		}}, zrf.entries...)

		f.Seek(off+4, 0)
	}
}

func tryReadZip(f *os.File) (r *zip.Reader, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
			r = nil
		}
	}()

	fi, err := f.Stat()
	if err != nil {
		return
	}

	r, err = zip.NewReader(f, fi.Size())
	return
}

func findNextFileHeader(f *os.File) (int64, error) {
	start, err := f.Seek(0, 1)
	if err != nil {
		return -1, err
	}
	defer f.Seek(start, 0)

	buf := make([]byte, 64*1024)
	toCmp := []byte{0x50, 0x4B, 0x03, 0x04}

	ok := 0
	offset := start

	for {
		n, err := f.Read(buf)
		if err != nil && err != io.EOF {
			return -1, err
		}

		if n == 0 {
			return -1, nil
		}

		for i := 0; i < n; i++ {
			if buf[i] == toCmp[ok] {
				ok++
				if ok == len(toCmp) {
					offset += int64(i) - int64(len(toCmp)-1)
					return offset, nil
				}
			} else {
				ok = 0
			}
		}

		offset += int64(n)
	}
}
