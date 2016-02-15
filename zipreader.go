package binxml

import (
    "io"
    "binxml/carelesszip"
    "fmt"
    "os"
    "path/filepath"
    "encoding/binary"
    "archive/zip"
    "compress/flate"
)

type zipReaderFileEntry struct {
    offset int64
    method uint16
}

type ZipReader struct {
    zipFile *os.File
    internalReader io.ReadCloser
    entries []zipReaderFileEntry
    curEntry int
}

func (zr *ZipReader) Read(p []byte) (int, error) {
    if zr.internalReader == nil {
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

func (zr *ZipReader) Next() bool {
    if len(zr.entries) == 0 && zr.internalReader != nil {
        zr.curEntry++
        return zr.curEntry == 1
    }

    if zr.internalReader != nil {
        zr.internalReader.Close()
        zr.internalReader = nil
    }

    if zr.curEntry + 1 >= len(zr.entries) {
        return false
    }
    zr.curEntry++
    return true
}

func (zr *ZipReader) Close() error {
    if zr.zipFile == nil {
        return nil
    }

    if zr.internalReader != nil && zr.internalReader != zr.zipFile {
        zr.internalReader.Close()
    }

    err := zr.zipFile.Close()
    zr.zipFile = nil
    return err
}

func OpenFileInZip(zippath, filename string) (zr *ZipReader, err error) {
    f, err := os.Open(zippath)
    if err != nil {
        return
    }

    defer func() {
        if err != nil {
            f.Close()
        }
    }()

    var zipinfo *carelesszip.Reader
    zipinfo, err = tryReadZip(f)
    if err == nil {
        for _, zf := range zipinfo.File {
            if filepath.Clean(zf.Name) == filename {
                var rc io.ReadCloser
                rc, err = zf.Open()
                if err == nil {
                    zr = &ZipReader { zipFile: f, internalReader: rc }
                    return
                }
            }
        }
    }

    f.Seek(0, 0)

    var off int64
    for {
        off, err = findNextFileHeader(f)
        if off == -1 {
            if zr != nil && len(zr.entries) != 0 {
                return
            }
            err = fmt.Errorf("Unable to find file %s!", filename)
        }
        if err != nil {
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

        if int(nameLen) < len(filename) || int(nameLen) > len(filename)*2 {
            f.Seek(off+4, 0)
            continue
        }

        if err = binary.Read(f, binary.LittleEndian, &extraLen); err != nil {
            return
        }

        buf := make([]byte, nameLen)
        if _, err = f.ReadAt(buf, off+30); err != nil {
            return
        }

        if filepath.Clean(string(buf)) == filename {
            fileOffset := off+30+int64(nameLen)+int64(extraLen)
            switch method {
            case zip.Deflate, zip.Store:
                if zr == nil {
                    zr = &ZipReader { zipFile: f, curEntry: -1 }
                }
                zr.entries = append(zr.entries, zipReaderFileEntry{
                    offset: fileOffset,
                    method: method,
                })
            }
        }

        f.Seek(off+4, 0)
    }

    return
}

func tryReadZip(f *os.File) (r *carelesszip.Reader, err error) {
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

    r, err = carelesszip.NewReader(f, fi.Size())
    return
}

func findNextFileHeader(f *os.File) (int64, error) {
    start, err := f.Seek(0, 1)
    if err != nil {
        return -1, err
    }
    defer f.Seek(start, 0)

    buf := make([]byte, 64*1024)
    toCmp := []byte{ 0x50, 0x4B, 0x03, 0x04 }

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
                    offset += int64(i) - int64(len(toCmp) - 1)
                    return offset, nil
                }
            } else {
                ok = 0
            }
        }

        offset += int64(n)
    }
    return -1, nil
}
