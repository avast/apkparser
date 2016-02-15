package binxml

import "encoding/xml"

type Encoder interface {
    EncodeToken(t xml.Token) error
    Flush() error
}
