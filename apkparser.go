// Package apkparser parses AndroidManifest.xml and resources.arsc from Android APKs.
package apkparser

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"
)

// DefaultMaxStringTableBytes is the default total memory budget for all decoded
// strings in a single string table (50 MB).
const DefaultMaxStringTableBytes int64 = 50 * 1024 * 1024

// ParseConfig holds optional configuration for APK/XML/resource parsing.
// A nil *ParseConfig is valid and uses defaults for all fields.
type ParseConfig struct {
	// MaxStringTableBytes limits the total decoded bytes per string table.
	// Strings are clipped (longest first) so that total usage fits within
	// this budget. Zero means DefaultMaxStringTableBytes.
	MaxStringTableBytes int64
}

func (c *ParseConfig) stringBudget() int64 {
	if c != nil && c.MaxStringTableBytes > 0 {
		return c.MaxStringTableBytes
	}
	return DefaultMaxStringTableBytes
}

type ApkParser struct {
	apkPath string
	zip     *ZipReader

	encoder ManifestEncoder
	resources *ResourceTable
	Config  *ParseConfig
}

// Calls ParseApkReader
func ParseApk(path string, encoder ManifestEncoder) (zipErr, resourcesErr, manifestErr error) {
	f, zipErr := os.Open(path)
	if zipErr != nil {
		return
	}
	defer f.Close()
	return ParseApkReader(f, encoder)
}

// Parse APK's Manifest, including resolving refences to resource values.
// encoder expects an XML encoder instance, like Encoder from encoding/xml package.
//
// zipErr != nil means the APK couldn't be opened. The manifest will be parsed
// even when resourcesErr != nil, just without reference resolving.
func ParseApkReader(r io.ReadSeeker, encoder ManifestEncoder) (zipErr, resourcesErr, manifestErr error) {
	zip, zipErr := OpenZipReader(r)
	if zipErr != nil {
		return
	}
	defer zip.Close()

	resourcesErr, manifestErr = ParseApkWithZip(zip, encoder)
	return
}

// Parse APK's Manifest, including resolving refences to resource values.
// encoder expects an XML encoder instance, like Encoder from encoding/xml package.
//
// Use this if you already opened the zip with OpenZip or OpenZipReader before.
// This method will not Close() the zip.
//
// The manifest will be parsed even when resourcesErr != nil, just without reference resolving.
func ParseApkWithZip(zip *ZipReader, encoder ManifestEncoder) (resourcesErr, manifestErr error) {
	p := ApkParser{
		zip:     zip,
		encoder: encoder,
	}

	resourcesErr = p.parseResources()
	manifestErr = p.ParseXml("AndroidManifest.xml")
	return
}

// Prepare the ApkParser instance, load resources if possible.
// encoder expects an XML encoder instance, like Encoder from encoding/xml package.
//
// This method will not Close() the zip, you are still the owner.
func NewParser(zip *ZipReader, encoder ManifestEncoder) (parser *ApkParser, resourcesErr error) {
	parser = &ApkParser{
		zip:     zip,
		encoder: encoder,
	}
	resourcesErr = parser.parseResources()
	return
}

func (p *ApkParser) parseResources() (err error) {
	if p.resources != nil {
		return nil
	}

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("Panic: %v\n%s", r, string(debug.Stack()))
		}
	}()

	resourcesFile := p.zip.File["resources.arsc"]
	if resourcesFile == nil {
		return os.ErrNotExist
	}

	if err := resourcesFile.Open(); err != nil {
		return fmt.Errorf("Failed to open resources.arsc: %s", err.Error())
	}
	defer resourcesFile.Close()

	p.resources, err = ParseResourceTableWithConfig(resourcesFile, p.Config)
	return
}

func (p *ApkParser) ParseXml(name string) error {
	file := p.zip.File[name]
	if file == nil {
		return fmt.Errorf("Failed to find %s in APK!", name)
	}

	if err := file.Open(); err != nil {
		return err
	}
	defer file.Close()

	var lastErr error
	for file.Next() {
		if err := ParseXmlWithConfig(file, p.encoder, p.resources, p.Config); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}

	if lastErr == ErrPlainTextManifest {
		return lastErr
	}

	return fmt.Errorf("Failed to parse %s, last error: %v", name, lastErr)
}
