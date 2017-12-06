package apkparser

import "encoding/xml"

// Encoder for writing the XML data. For example Encoder from encoding/xml matches this interface.
type ManifestEncoder interface {
	EncodeToken(t xml.Token) error
	Flush() error
}
