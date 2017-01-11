package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"os"

	"binxml"
	"strings"
)

func main() {
	isApk := flag.Bool("a", false, "The input file is an apk (default if INPUT is *.apk)")
	isManifest := flag.Bool("m", false, "The input file is an AndroidManifest.xml (default)")
	isResources := flag.Bool("r", false, "The input is resources.arsc file (default if INPUT is *.arsc)")

	flag.Parse()

	if len(flag.Args()) != 1 {
		fmt.Printf("%s INPUT\n", os.Args[0])
		os.Exit(1)
	}

	var r io.Reader
	input := flag.Args()[0]

	if !*isApk && !*isManifest && !*isResources {
		if strings.HasSuffix(input, ".apk") {
			*isApk = true
		} else if strings.HasSuffix(input, ".arsc") {
			*isResources = true
		} else {
			*isManifest = true
		}
	}

	if *isApk {
		processApk(input)
	} else {
		if input == "-" {
			r = os.Stdin
		} else {
			f, err := os.Open(input)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			defer f.Close()
			r = f
		}

		var err error
		if *isManifest {
			enc := xml.NewEncoder(os.Stdout)
			enc.Indent("", "    ")

			err = binxml.ParseManifest(r, enc, nil)
		} else {
			_, err = binxml.ParseResourceTable(r)
		}

		fmt.Println()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

func processApk(input string) {
	zr, err := binxml.OpenZip(input)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer zr.Close()

	var res *binxml.ResourceTable

	zrf := zr.File["resources.arsc"]
	if zrf == nil {
		fmt.Fprintln(os.Stderr, input, "Failed to find resources.arsc")
	} else {
		if err := zrf.Open(); err != nil {
			fmt.Fprintln(os.Stderr, input, err)
		} else {
			defer zrf.Close()

			zrf.Next()
			res, err = binxml.ParseResourceTable(zrf)
			if err != nil {
				fmt.Fprintln(os.Stderr, input, err)
			}
		}
	}

	zrf = zr.File["AndroidManifest.xml"]
	if zrf == nil {
		fmt.Fprintln(os.Stderr, "Failed to find manifest")
		os.Exit(1)
	}

	if err := zrf.Open(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer zrf.Close()

	zrf.Next()

	enc := xml.NewEncoder(os.Stdout)
	enc.Indent("", "    ")

	err = binxml.ParseManifest(zrf, enc, res)
	fmt.Println()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
