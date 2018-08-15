// This is a tool to extract AndroidManifest.xml from apks and verify their signatures.
package main

import (
	"bufio"
	"crypto/x509"
	"encoding/xml"
	"flag"
	"fmt"
	"github.com/avast/apkparser"
	"github.com/avast/apkverifier"
	"io"
	"io/ioutil"
	"os"
	"runtime/pprof"
	"strings"
)

func main() {
	isApk := flag.Bool("a", false, "The input file is an apk (default if INPUT is *.apk)")
	isManifest := flag.Bool("m", false, "The input file is an AndroidManifest.xml (default)")
	isResources := flag.Bool("r", false, "The input is resources.arsc file (default if INPUT is *.arsc)")
	verifyApk := flag.Bool("v", false, "Verify the file signature if it is an APK.")
	dumpManifest := flag.Bool("d", true, "Print the AndroidManifest.xml (only makes sense for APKs)")
	cpuProfile := flag.String("cpuprofile", "", "Write cpu profiling info")
	fileListPath := flag.String("l", "", "Process file list")
	dumpFrostingProto := flag.String("dumpfrosting", "", "Dump Google Play Frosting protobuf data")

	flag.Parse()

	if *fileListPath == "" && len(flag.Args()) < 1 {
		fmt.Printf("%s INPUT\n", os.Args[0])
		os.Exit(1)
	}

	exitcode := 0
	defer func() {
		if r := recover(); r != nil {
			panic(r)
		}
		os.Exit(exitcode)
	}()

	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			exitcode = 1
			return
		}
		defer f.Close()

		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	if *fileListPath == "" {
		for i, input := range flag.Args() {
			if i != 0 {
				fmt.Println()
			}

			if len(flag.Args()) != 1 {
				fmt.Println("File:", input)
			}

			if !processInput(input, *isApk, *isManifest, *isResources, *verifyApk, *dumpManifest, *dumpFrostingProto) {
				exitcode = 1
			}
		}
	} else {
		f, err := os.Open(*fileListPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer f.Close()

		s := bufio.NewScanner(f)
		for s.Scan() {
			if !processInput(s.Text(), *isApk, *isManifest, *isResources, *verifyApk, *dumpManifest, *dumpFrostingProto) {
				exitcode = 1
			}
		}
	}
}

func processInput(input string, isApk, isManifest, isResources, verifyApk, dumpManifest bool, dumpFrostingProto string) bool {
	var r io.Reader

	if !isApk && !isManifest && !isResources {
		if strings.HasSuffix(input, ".apk") {
			isApk = true
		} else if strings.HasSuffix(input, ".arsc") {
			isResources = true
		} else {
			isManifest = true
		}
	}

	if isApk {
		return processApk(input, verifyApk, dumpManifest, dumpFrostingProto)
	} else {
		if input == "-" {
			r = os.Stdin
		} else {
			f, err := os.Open(input)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return false
			}
			defer f.Close()
			r = f
		}

		var err error
		if isManifest {
			enc := xml.NewEncoder(os.Stdout)
			enc.Indent("", "    ")

			err = apkparser.ParseManifest(r, enc, nil)
		} else {
			_, err = apkparser.ParseResourceTable(r)
		}

		fmt.Println()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return false
		}
	}
	return true
}

func processApk(input string, verify, dumpManifest bool, dumpFrostingProto string) bool {
	enc := xml.NewEncoder(os.Stdout)
	enc.Indent("", "    ")

	apkReader, err := apkparser.OpenZip(input)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return false
	}
	defer apkReader.Close()

	if dumpManifest {
		reserr, err := apkparser.ParseApkWithZip(apkReader, enc)
		if reserr != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse resources: %s", err.Error())
		}

		fmt.Println()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return false
		}
	}

	if !verify {
		return true
	}

	if dumpManifest {
		fmt.Print("\n=====================================\n")
	}

	res, err := apkverifier.Verify(input, apkReader)

	fmt.Printf("Verification scheme used: v%d\n", res.SigningSchemeId)

	_, picked := apkverifier.PickBestApkCert(res.SignerCerts)

	cinfo := &apkverifier.CertInfo{}
	var x int
	var cert *x509.Certificate
	for i, ca := range res.SignerCerts {
		for x, cert = range ca {
			cinfo.Fill(cert)

			fmt.Println()
			if picked == cert {
				fmt.Printf("Chain %d, cert %d [PICKED AS BEST]:\n", i, x)
			} else {
				fmt.Printf("Chain %d, cert %d:\n", i, x)
			}
			fmt.Println("algo:", cert.SignatureAlgorithm)
			fmt.Println("validfrom:", cinfo.ValidFrom)
			fmt.Println("validto:", cinfo.ValidTo)
			fmt.Println("serialnumber:", cert.SerialNumber.Text(16))
			fmt.Println("thumbprint-md5:", cinfo.Md5)
			fmt.Println("thumbprint-sha1:", cinfo.Sha1)
			fmt.Println("thumbprint-sha256:", cinfo.Sha256)
			fmt.Printf("Subject:\n  %s\n", cinfo.Subject)
			fmt.Printf("Issuer:\n  %s\n", cinfo.Issuer)
		}
	}

	fmt.Println()

	if blk := res.SigningBlockResult; blk != nil {
		if blk.SigningLineage != nil {
			fmt.Println("Signing lineage:")
			for i, n := range blk.SigningLineage.Nodes {
				fmt.Printf("Node #%d:\n", i)
				n.Dump(os.Stdout)
				fmt.Println()
			}
		}

		fmt.Printf("Google Play Store Frosting: ")
		if blk.Frosting != nil {
			fmt.Println("present")
			if blk.Frosting.Error == nil {
				fmt.Printf("  verification: ok\n")
			} else {
				fmt.Printf("  verification: FAILED, %s\n", blk.Frosting.Error.Error())
			}

			fmt.Println("  protobuf data length:", len(blk.Frosting.ProtobufInfo))

			if blk.Frosting.KeySha256 != "" {
				fmt.Println("  used key sha256:", blk.Frosting.KeySha256)
			}
			fmt.Println()

			if dumpFrostingProto != "" {
				if err := ioutil.WriteFile(dumpFrostingProto, blk.Frosting.ProtobufInfo, 0644); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to dump Google Play Frosting protobuf: %s", err.Error())
				}
			}
		} else {
			fmt.Println("missing")
		}

		if len(blk.Warnings) != 0 {
			fmt.Println("Warnings:")
			for _, w := range blk.Warnings {
				fmt.Println(" ", w)
			}
			fmt.Println()
		}

		if len(blk.Errors) > 1 {
			fmt.Println("Additional errors:")
			for i := 0; i < len(blk.Errors)-1; i++ {
				fmt.Println(" ", blk.Errors[i])
			}
			fmt.Println()
		}
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return false
	}
	return true
}
