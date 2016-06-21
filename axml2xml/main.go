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
	isApk := flag.Bool("a", false, "The input file is an apk")

	flag.Parse()

	if len(flag.Args()) != 1 {
		fmt.Printf("%s INPUT\n", os.Args[0])
		os.Exit(1)
	}

	var r io.Reader
	input := flag.Args()[0]

	if strings.HasSuffix(input, ".apk") {
		*isApk = true
	}

	if input == "-" {
		r = os.Stdin
	} else if *isApk {
		zr, err := binxml.OpenZip(input)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer zr.Close()

		zrf := zr.File["AndroidManifest.xml"]
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
		r = zrf
	} else {
		f, err := os.Open(input)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer f.Close()
		r = f
	}

	enc := xml.NewEncoder(os.Stdout)
	enc.Indent("", "    ")

	err := binxml.Parse(r, enc)
	fmt.Println()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
