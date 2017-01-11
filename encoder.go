package binxml

import "encoding/xml"

type ManifestEncoder interface {
	EncodeToken(t xml.Token) error
	Flush() error
}
