// This is a tool to extract AndroidManifest.xml from apks and verify their signatures.
package main

import (
	"bufio"
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"runtime/pprof"
	"strings"

	"github.com/avast/apkparser"
	"github.com/avast/apkverifier"
	"github.com/avast/apkverifier/apilevel"
)

type optsType struct {
	isApk                      bool
	isManifest                 bool
	isResources                bool
	verifyApk                  bool
	verifyAllSignatureVersions bool
	dumpManifest               bool
	extractCert                bool

	cpuProfile        string
	fileListPath      string
	dumpFrostingProto string
	xmlFileName       string
}

type sdkLevelPair struct {
	min, max int32
}

var allSigsSdks = [...]sdkLevelPair{
	{apilevel.V1_5_Cupcake, apilevel.V6_0_Marshmallow},
	{apilevel.V7_0_Nougat, apilevel.V8_1_Oreo},
	{apilevel.V9_0_Pie, math.MaxInt32},
}

func main() {
	var opts optsType

	flag.BoolVar(&opts.isApk, "a", false, "The input file is an apk (default if INPUT is *.apk)")
	flag.BoolVar(&opts.isManifest, "m", false, "The input file is an AndroidManifest.xml (default)")
	flag.BoolVar(&opts.isResources, "r", false, "The input is resources.arsc file (default if INPUT is *.arsc)")
	flag.BoolVar(&opts.verifyApk, "v", false, "Verify the file signature if it is an APK.")
	flag.BoolVar(&opts.verifyAllSignatureVersions, "allsig", false, "Verify all signature version if it is an APK.")
	flag.BoolVar(&opts.extractCert, "e", false, "Extract the certificate without verifying it.")
	flag.BoolVar(&opts.dumpManifest, "d", true, "Print the AndroidManifest.xml (only makes sense for APKs)")
	flag.StringVar(&opts.cpuProfile, "cpuprofile", "", "Write cpu profiling info")
	flag.StringVar(&opts.fileListPath, "l", "", "Process file list")
	flag.StringVar(&opts.dumpFrostingProto, "dumpfrosting", "", "Dump Google Play Frosting protobuf data")
	flag.StringVar(&opts.xmlFileName, "f", "AndroidManifest.xml", "Name of the XML file from inside apk to parse")

	flag.Parse()

	if opts.verifyAllSignatureVersions {
		opts.verifyApk = true
	}

	if opts.fileListPath == "" && len(flag.Args()) < 1 {
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

	if opts.cpuProfile != "" {
		f, err := os.Create(opts.cpuProfile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			exitcode = 1
			return
		}
		defer f.Close()

		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	if opts.fileListPath == "" {
		for i, input := range flag.Args() {
			if i != 0 {
				fmt.Println()
			}

			if len(flag.Args()) != 1 {
				fmt.Println("File:", input)
			}

			if !processInput(input, &opts) {
				exitcode = 1
			}
		}
	} else {
		f, err := os.Open(opts.fileListPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer f.Close()

		s := bufio.NewScanner(f)
		for s.Scan() {
			if !processInput(s.Text(), &opts) {
				exitcode = 1
			}
		}
	}
}

func processInput(input string, opts *optsType) bool {
	var r io.Reader

	if !opts.isApk && !opts.isManifest && !opts.isResources {
		if strings.HasSuffix(input, ".apk") {
			opts.isApk = true
		} else if strings.HasSuffix(input, ".arsc") {
			opts.isResources = true
		} else {
			opts.isManifest = true
		}
	}

	if opts.isApk {
		return processApk(input, opts)
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
		if opts.isManifest {
			enc := xml.NewEncoder(os.Stdout)
			enc.Indent("", "    ")

			err = apkparser.ParseXml(r, enc, nil)
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

func processApk(input string, opts *optsType) bool {
	enc := xml.NewEncoder(os.Stdout)
	enc.Indent("", "    ")

	apkReader, err := apkparser.OpenZip(input)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return false
	}
	defer apkReader.Close()

	if opts.dumpManifest {
		parser, reserr := apkparser.NewParser(apkReader, enc)
		if reserr != nil {
			fmt.Fprintf(os.Stderr, "\nFailed to parse resources: %s", reserr.Error())
		}

		err := parser.ParseXml(opts.xmlFileName)

		fmt.Println()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return false
		}
	}

	if !opts.verifyApk && !opts.extractCert {
		return true
	}

	if opts.dumpManifest {
		fmt.Print("\n=====================================\n")
	}

	if opts.verifyAllSignatureVersions {
		ok := true
		for _, s := range allSigsSdks {
			fmt.Printf("\nVerifying for SDK range <%s;%s>", apilevel.String(s.min), apilevel.String(s.max))
			fmt.Print("\n=====================================\n")
			if !verifyApkWithSdkLevels(input, apkReader, opts, s.min, s.max) {
				ok = false
			}
		}

		if ok {
			fmt.Println("\nAll signatures are okay.")
		}

	} else if opts.verifyApk {
		return verifyApk(input, apkReader, opts)
	} else if opts.extractCert {
		certs, err := apkverifier.ExtractCerts(input, apkReader)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			return false
		}
		printCerts(certs)
	}

	return true
}

func verifyApk(input string, apkReader *apkparser.ZipReader, opts *optsType) bool {
	return verifyApkWithSdkLevels(input, apkReader, opts, -1, math.MaxInt32)
}

func verifyApkWithSdkLevels(input string, apkReader *apkparser.ZipReader, opts *optsType, minSdk, maxSdk int32) bool {
	res, err := apkverifier.VerifyWithSdkVersion(input, apkReader, minSdk, maxSdk)

	fmt.Printf("Verification scheme used: v%d\n", res.SigningSchemeId)

	printCerts(res.SignerCerts)

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

			if opts.dumpFrostingProto != "" {
				if err := ioutil.WriteFile(opts.dumpFrostingProto, blk.Frosting.ProtobufInfo, 0644); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to dump Google Play Frosting protobuf: %s", err.Error())
				}
			}
		} else {
			fmt.Println("missing")
		}
		fmt.Println()

		fmt.Printf("Source stamp: ")
		if st := blk.SourceStamp; st != nil {
			fmt.Println("present")
			if len(st.Errors) == 0 {
				fmt.Printf("  verification: ok\n")
			} else {
				fmt.Printf("  verification: FAILED\n")
				for _, e := range st.Errors {
					fmt.Printf("    %s\n", e.Error())
				}
			}

			fmt.Printf("  certificate:")
			if st.Cert == nil {
				fmt.Printf(" none extracted\n")
			} else {
				fmt.Println()
				printCert("    ", st.Cert)
			}

			fmt.Printf("  lineage: %d\n", len(st.Lineage))
			for i, l := range st.Lineage {
				fmt.Printf("    %d: 0x%x %s (parent %s)\n", i, l.Flags, l.Algo, l.ParentAlgo)
				printCert("      ", l.Cert)
			}

			fmt.Printf("  warnings:\n")
			for _, e := range st.Warnings {
				fmt.Printf("    %s\n", e)
			}
		} else {
			fmt.Println("missing")
		}
		fmt.Println()

		fmt.Printf("Extra signing blocks: %d\n", len(blk.ExtraBlocks))
		for id, block := range blk.ExtraBlocks {
			fmt.Printf("    0x%08x: %s (%d bytes)\n", uint32(id), id.String(), len(block))
		}
		fmt.Println()

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

func printCerts(certs [][]*x509.Certificate) {
	_, picked := apkverifier.PickBestApkCert(certs)

	var x int
	var cert *x509.Certificate
	for i, ca := range certs {
		for x, cert = range ca {
			fmt.Println()
			if picked == cert {
				fmt.Printf("Chain %d, cert %d [PICKED AS BEST]:\n", i, x)
			} else {
				fmt.Printf("Chain %d, cert %d:\n", i, x)
			}

			printCert("", cert)
		}
	}
}

func printCert(prefix string, cert *x509.Certificate) {
	var cinfo apkverifier.CertInfo
	cinfo.Fill(cert)

	fmt.Printf(prefix+"algo: %s\n", cert.SignatureAlgorithm)
	fmt.Printf(prefix+"validfrom: %s\n", cinfo.ValidFrom)
	fmt.Printf(prefix+"validto: %s\n", cinfo.ValidTo)
	fmt.Printf(prefix+"serialnumber: %s\n", hex.EncodeToString(cert.SerialNumber.Bytes()))
	fmt.Printf(prefix+"thumbprint-md5: %s\n", cinfo.Md5)
	fmt.Printf(prefix+"thumbprint-sha1: %s\n", cinfo.Sha1)
	fmt.Printf(prefix+"thumbprint-sha256: %s\n", cinfo.Sha256)
	fmt.Printf(prefix+"Subject:\n  %s%s\n", prefix, cinfo.Subject)
	fmt.Printf(prefix+"Issuer:\n  %s%s\n", prefix, cinfo.Issuer)
}
