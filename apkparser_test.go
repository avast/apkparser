package apkparser_test

import (
	"encoding/xml"
	"fmt"
	"github.com/avast/apkparser"
	"os"
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
