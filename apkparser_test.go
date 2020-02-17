package apkparser_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"github.com/avast/apkparser"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func Example() {
	enc := xml.NewEncoder(os.Stdout)
	enc.Indent("", "\t")
	zipErr, resErr, manErr := apkparser.ParseApk(os.Args[1], enc)
	if zipErr != nil {
		fmt.Fprintf(os.Stderr, "Failed to open the APK: %s", zipErr.Error())
		os.Exit(1)
		return
	}

	if resErr != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse resources: %s", resErr.Error())
	}
	if manErr != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse AndroidManifest.xml: %s", manErr.Error())
		os.Exit(1)
		return
	}
	fmt.Println()
}

func testExpectedOutputFile(t *testing.T, fnBase string) {
	in, err := os.Open(fnBase + ".bin")
	if err != nil {
		t.Fatalf("failed to open file %s.bin: %s", fnBase, err.Error())
		return
	}
	defer in.Close()

	hasher := sha256.New()
	enc := xml.NewEncoder(hasher)
	enc.Indent("", "    ")

	if err := apkparser.ParseXml(in, enc, nil); err != nil {
		t.Fatalf("failed to parse manifest %s.bin: %s", fnBase, err.Error())
		return
	}

	hasher.Write([]byte("\n"))

	currentSha256 := hasher.Sum(nil)
	hasher.Reset()

	expected, err := os.Open(fnBase + ".xml")
	if err != nil {
		t.Fatalf("failed to open file %s.xml: %s", fnBase, err.Error())
		return
	}
	defer expected.Close()

	if _, err := io.Copy(hasher, expected); err != nil {
		t.Fatalf("failed to read %s.xml: %s", fnBase, err.Error())
		return
	}

	if expectedSha256 := hasher.Sum(nil); !bytes.Equal(currentSha256, expectedSha256) {
		t.Fatalf("parsing %s.bin does not produce the expected output!", fnBase)
	}
}

func TestExpectedOutput(t *testing.T) {
	files, err := ioutil.ReadDir("testdata")
	if err != nil {
		t.Fatalf("failed to open testdata directory: %s", err.Error())
		return
	}

	for _, fi := range files {
		if fi.IsDir() || !strings.HasSuffix(fi.Name(), ".bin") {
			continue
		}

		base := fi.Name()[:len(fi.Name())-4]
		t.Run(base, func(t *testing.T) {
			testExpectedOutputFile(t, filepath.Join("testdata", base))
		})
	}
}

func TestPlainManifest(t *testing.T) {
	plainManifests := []string{
		`<?xml version="1.0" encoding="utf-8" standalone="no"?>`,
		`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">`,
	}

	enc := xml.NewEncoder(ioutil.Discard)

	for _, man := range plainManifests {
		r := strings.NewReader(man)
		if err := apkparser.ParseXml(r, enc, nil); err != apkparser.ErrPlainTextManifest {
			t.Fatalf("failed to produce ErrPlainTextManifest on string '%s', got '%v' instead", man, err)
			return
		}
	}
}
