package main

import (
  "fmt"
  "flag"
	"syscall"
	salted "github.com/DinoChiesa/salted/lib"
	"golang.org/x/term"
)


func usage() {
  fmt.Printf("salt_file -in infilename [-passphrase 'passphrase here'] [-decrypt] [-out outfilename]\n\n")
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

  if *infilePtr == "" {
    usage()
    return
  }
  infilename = *infilePtr

  if *passphrasePtr == "" {
		// read from terminal without echo
		fmt.Print("Passphrase: ")
    bytepw, err := term.ReadPassword(int(syscall.Stdin))
    if err != nil {
			return
		}
		passphrase = string(bytepw)
		fmt.Print("\n")
  }	else {
		passphrase = *passphrasePtr
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
		fmt.Println(e)
		return
	}
	if *verbosePtr {
		fmt.Printf("number of chunks: %d\n", ef.NumChunks)
		fmt.Printf("output file: %s\n", ef.OutputFilename)
	}
}
