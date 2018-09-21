// Package apkparser parses AndroidManifest.xml and resources.arsc from Android APKs.
package apkparser

import (
	"fmt"
	"os"
	"runtime/debug"
)

type apkParser struct {
	apkPath string
	zip     *ZipReader

	encoder   ManifestEncoder
	resources *ResourceTable
}

// Parse APK's Manifest, including resolving refences to resource values.
// encoder expects an XML encoder instance, like Encoder from encoding/xml package.
//
// zipErr != nil means the APK couldn't be opened. The manifest will be parsed
// even when resourcesErr != nil, just without reference resolving.
func ParseApk(path string, encoder ManifestEncoder) (zipErr, resourcesErr, manifestErr error) {
	zip, zipErr := OpenZip(path)
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
// Use this if you already opened the zip with OpenZip before. This method will not Close() the zip.
//
// The manifest will be parsed even when resourcesErr != nil, just without reference resolving.
func ParseApkWithZip(zip *ZipReader, encoder ManifestEncoder) (resourcesErr, manifestErr error) {
	p := apkParser{
		zip:     zip,
		encoder: encoder,
	}

	resourcesErr = p.parseResources()
	manifestErr = p.parseManifestXml()
	return
}

func (p *apkParser) parseResources() (err error) {
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

	p.resources, err = ParseResourceTable(resourcesFile)
	return
}

func (p *apkParser) parseManifestXml() error {
	manifest := p.zip.File["AndroidManifest.xml"]
	if manifest == nil {
		return fmt.Errorf("Failed to find AndroidManifest.xml!")
	}

	if err := manifest.Open(); err != nil {
		return err
	}
	defer manifest.Close()

	var lastErr error
	for manifest.Next() {
		if err := ParseManifest(manifest, p.encoder, p.resources); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}

	if lastErr == ErrPlainTextManifest {
		return lastErr
	}

	return fmt.Errorf("Failed to parse manifest, last error: %v", lastErr)
}
