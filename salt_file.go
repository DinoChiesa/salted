package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"

	salted "github.com/DinoChiesa/salted/lib"
	"golang.org/x/term"
)

func usage() {
	fmt.Fprintf(os.Stderr, "salt_file -in infilename [-passphrase 'passphrase here'] [-decrypt] [-out outfilename]\n")
	fmt.Fprintf(os.Stderr, "The passphrase may also be supplied via the SALT_FILE_PASSPHRASE environment variable.\n\n")
}

func main() {
	var passphrase string  // = "some passphrase"
	var infilename string  // example:  data.txt
	var outfilename string // example:  data.txt.salted

	verbosePtr := flag.Bool("verbose", false, "")
	decryptPtr := flag.Bool("decrypt", false, "decrypt rather than encrypt")
	infilePtr := flag.String("in", "", "name of file to read to encrypt or decrypt")
	passphrasePtr := flag.String("passphrase", "", "string passphrase (or set SALT_FILE_PASSPHRASE)")
	outfilePtr := flag.String("out", "", "output file")
	flag.Parse()

	if *infilePtr == "" {
		usage()
		os.Exit(1)
	}
	infilename = *infilePtr

	if *passphrasePtr != "" {
		passphrase = *passphrasePtr
	} else if envPass := os.Getenv("SALT_FILE_PASSPHRASE"); envPass != "" {
		passphrase = envPass
	} else {
		// read from terminal without echo
		fmt.Fprint(os.Stderr, "Passphrase: ")
		bytepw, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		passphrase = string(bytepw)
		fmt.Fprint(os.Stderr, "\n")
	}

	if *outfilePtr == "" {
		// select a default output filename based on the desired action
		outfilename = salted.DeriveOutputFilename(infilename, *decryptPtr)
		if *verbosePtr {
			fmt.Printf("using output file: %s\n", outfilename)
		}
	} else {
		outfilename = *outfilePtr
	}

	var ef *salted.EncryptedFile
	var e error
	if *decryptPtr {
		ef, e = salted.ReadAndDecrypt(infilename, outfilename, passphrase, *verbosePtr)
	} else {
		ef, e = salted.ReadAndEncrypt(infilename, outfilename, passphrase, *verbosePtr)
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	if *verbosePtr {
		fmt.Printf("number of chunks: %d\n", ef.NumChunks)
		fmt.Printf("output file: %s\n", ef.OutputFilename)
	}
}
