package apkparser

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Test sample: 70ffe20fae868a373d7a04e3d41d6ce974a46d0a1f1d25064537f05a4325168e
// An APK whose AndroidManifest.xml inflates to ~803MB. The manifest
// string table contains 353 strings, including a ~764MB UTF-16 string of '/'
// characters (idx 282) and a ~1.5MB random junk string (idx 351).
//
// Run with: go test -run TestStringTableBudget -sample /path/to/sample.apk
var sampleFlag = flag.String("sample", "", "path to sample APK for budget tests")

// getManifestStringsWithBudget opens the sample APK and parses the manifest's
// string table with the given budget.
func getManifestStringsWithBudget(t *testing.T, path string, budget int64) []string {
	t.Helper()

	zip, err := OpenZip(path)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer zip.Close()

	manifest := zip.File["AndroidManifest.xml"]
	if manifest == nil {
		t.Fatal("no AndroidManifest.xml in APK")
	}
	if err := manifest.Open(); err != nil {
		t.Fatalf("open manifest: %v", err)
	}
	defer manifest.Close()

	for manifest.Next() {
		strs, err := parseManifestStringTableInternal(manifest, budget)
		if err != nil {
			continue
		}
		return strs
	}
	t.Fatal("failed to parse manifest string table")
	return nil
}

// parseManifestStringTableInternal walks the AXML outer chunk to find the
// string table chunk, then parses it with the given budget.
func parseManifestStringTableInternal(r io.Reader, budget int64) ([]string, error) {
	if budget <= 0 {
		budget = DefaultMaxStringTableBytes
	}

	_, headerLen, totalLen, err := parseChunkHeader(r)
	if err != nil {
		return nil, err
	}

	dataLen := int64(totalLen) - int64(headerLen)
	if skip := int64(headerLen) - chunkHeaderSize; skip > 0 {
		if _, err := io.CopyN(io.Discard, r, skip); err != nil {
			return nil, err
		}
		dataLen -= skip
	}

	for dataLen > chunkHeaderSize {
		cid, _, clen, err := parseChunkHeader(r)
		if err != nil {
			return nil, err
		}
		dataLen -= chunkHeaderSize

		bodyLen := int64(clen) - chunkHeaderSize
		lm := &io.LimitedReader{R: r, N: bodyLen}

		if cid == chunkStringTable {
			st, err := parseStringTable(lm, budget)
			if err != nil {
				return nil, err
			}
			return st.strings, nil
		}

		if _, err := io.CopyN(io.Discard, lm, lm.N); err != nil {
			return nil, err
		}
		dataLen -= bodyLen
	}

	return nil, nil
}

func countTruncated(strs []string) int {
	n := 0
	for _, s := range strs {
		if strings.HasSuffix(s, truncatedMarker) {
			n++
		}
	}
	return n
}

func totalStringBytes(strs []string) int64 {
	var total int64
	for _, s := range strs {
		total += int64(len(s))
	}
	return total
}

// TestParseConfig_StringBudget verifies that ParseConfig.stringBudget() returns
// sane values for all edge cases.
func TestParseConfig_StringBudget(t *testing.T) {
	tests := []struct {
		name   string
		config *ParseConfig
		want   int64
	}{
		{"nil config", nil, DefaultMaxStringTableBytes},
		{"zero value struct", &ParseConfig{}, DefaultMaxStringTableBytes},
		{"explicit zero", &ParseConfig{MaxStringTableBytes: 0}, DefaultMaxStringTableBytes},
		{"negative", &ParseConfig{MaxStringTableBytes: -1}, DefaultMaxStringTableBytes},
		{"negative large", &ParseConfig{MaxStringTableBytes: -999999}, DefaultMaxStringTableBytes},
		{"min negative", &ParseConfig{MaxStringTableBytes: math.MinInt64}, DefaultMaxStringTableBytes},
		{"custom 1MB", &ParseConfig{MaxStringTableBytes: 1024 * 1024}, 1024 * 1024},
		{"custom 1GB", &ParseConfig{MaxStringTableBytes: 1024 * 1024 * 1024}, 1024 * 1024 * 1024},
		{"custom 1 byte", &ParseConfig{MaxStringTableBytes: 1}, 1},
		{"max int64", &ParseConfig{MaxStringTableBytes: math.MaxInt64}, math.MaxInt64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.stringBudget()
			if got != tt.want {
				t.Errorf("stringBudget() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestParseXmlWithConfig_AllConfigValues parses real testdata manifests with
// various ParseConfig values to verify nothing crashes.
func TestParseXmlWithConfig_AllConfigValues(t *testing.T) {
	files, err := ioutil.ReadDir("testdata")
	if err != nil {
		t.Fatalf("failed to open testdata directory: %s", err)
	}

	configs := []*ParseConfig{
		nil,
		{},
		{MaxStringTableBytes: 0},
		{MaxStringTableBytes: -1},
		{MaxStringTableBytes: 1},
		{MaxStringTableBytes: 100},
		{MaxStringTableBytes: 1024},
		{MaxStringTableBytes: 1024 * 1024},
		{MaxStringTableBytes: DefaultMaxStringTableBytes},
		{MaxStringTableBytes: 1024 * 1024 * 1024},
		{MaxStringTableBytes: math.MaxInt64},
	}

	for _, fi := range files {
		if fi.IsDir() || !strings.HasSuffix(fi.Name(), ".bin") {
			continue
		}

		for _, cfg := range configs {
			name := fi.Name()
			budgetName := "nil"
			if cfg != nil {
				budgetName = fmt.Sprintf("%d", cfg.MaxStringTableBytes)
			}

			t.Run(name+"/budget="+budgetName, func(t *testing.T) {
				f, err := os.Open(filepath.Join("testdata", fi.Name()))
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()

				enc := xml.NewEncoder(io.Discard)
				err = ParseXmlWithConfig(f, enc, nil, cfg)
				if err != nil {
					t.Logf("parse error (may be expected with tiny budget): %v", err)
				}
				// The main assertion is that we don't panic/crash.
			})
		}
	}
}

// TestStringTableBudget_SampleAPK verifies that the configurable string table
// budget correctly controls truncation on an APK with an inflated
// manifest string table (~764MB UTF-16 → ~382MB UTF-8 decoded).
//
// The sample has 353 strings. String idx 282 is ~382MB of '/' characters.
// String idx 351 is ~1.5MB of random junk.
//
// Skipped unless -sample flag is provided.
func TestStringTableBudget_SampleAPK(t *testing.T) {
	if *sampleFlag == "" {
		t.Skip("-sample flag not set")
	}

	zip, err := OpenZip(*sampleFlag)
	if err != nil {
		t.Skipf("sample APK not available: %v", err)
	}
	zip.Close()

	tests := []struct {
		name            string
		budget          int64
		expectTruncated bool
		minTruncCount   int // minimum expected <TRUNCATED> markers
	}{
		{
			name:            "default budget clips giant string",
			budget:          DefaultMaxStringTableBytes,
			expectTruncated: true,
			minTruncCount:   1,
		},
		{
			name:            "1GB budget fits everything",
			budget:          1024 * 1024 * 1024,
			expectTruncated: false,
		},
		{
			name:            "1MB budget clips multiple strings",
			budget:          1 * 1024 * 1024,
			expectTruncated: true,
			minTruncCount:   2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strs := getManifestStringsWithBudget(t, *sampleFlag, tt.budget)

			if len(strs) != 353 {
				t.Fatalf("expected 353 strings, got %d", len(strs))
			}

			trunc := countTruncated(strs)
			total := totalStringBytes(strs)

			t.Logf("budget=%d total_bytes=%d truncated=%d", tt.budget, total, trunc)

			if tt.expectTruncated && trunc < tt.minTruncCount {
				t.Errorf("expected at least %d truncated strings, got %d", tt.minTruncCount, trunc)
			}
			if !tt.expectTruncated && trunc > 0 {
				t.Errorf("expected no truncation, got %d truncated strings", trunc)
			}

			// With truncation active, total bytes must be within budget.
			if tt.expectTruncated && total > tt.budget {
				t.Errorf("total string bytes %d exceeds budget %d", total, tt.budget)
			}
		})
	}
}
