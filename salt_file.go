package main

import (
  "fmt"
  "flag"
	"github.com/DinoChiesa/salted/lib"
)


func usage() {
  fmt.Printf("salt_file -in infilename -passphrase 'I love APIs' [-decrypt] [-out outfilename]\n\n")
}

func main() {
  var passphrase string // = "some passphrase"
  var infilename string  // example:  data.txt
  var outfilename string  // example:  data.txt.salted

  verbosePtr := flag.Bool("verbose", false, "")
  decryptPtr := flag.Bool("decrypt", false, "decrypt rather than encrypt")
  infilePtr := flag.String("in", "", "name of file to read to encrypt or decrypt")
  passphrasePtr := flag.String("passphrase", "", "string passphrase")
  outfilePtr := flag.String("out", "", "output file")
  flag.Parse()

  if *infilePtr == "" || *passphrasePtr == "" {
    usage()
    return
  }

  infilename = *infilePtr
  passphrase = *passphrasePtr

  if *outfilePtr == "" {
		// select a default output filename based on the desired action
		outfilename = lib.DeriveOutputFilename(infilename, *decryptPtr)
		if *verbosePtr {
			fmt.Printf("using output file: %s\n", outfilename)
		}
  } else {
		outfilename = *outfilePtr
	}

	var ef *lib.EncryptedFile
	var e error
  if *decryptPtr {
    ef, e = lib.ReadAndDecrypt(infilename, outfilename, passphrase, *verbosePtr)
  } else {
    ef, e = lib.ReadAndEncrypt(infilename, outfilename, passphrase, *verbosePtr)
  }
  if e != nil {
		fmt.Println(e)
		return
	}
	if *verbosePtr {
		fmt.Printf("number of chunks: %d\n", ef.NumChunks)
		fmt.Printf("output file: %s\n", ef.OutputFilename)
	}
}
