package main

import (
  "fmt"
  "strings" 
  "flag"
	"github.com/DinoChiesa/salted/lib"
)


func usage() {
  fmt.Printf("salt_file -filename something -passphrase 'I love APIs'\n\n")
}

func main() {
  var passphrase string // = "some passphrase"
  var filename string  // = "encrypt_file.go"

  boolPtr := flag.Bool("verbose", false, "")
  filenamePtr := flag.String("filename", "", "name of file to encrypt")
  passphrasePtr := flag.String("passphrase", "", "string passphrase")
  flag.Parse()

  if *filenamePtr == "" || *passphrasePtr == "" {
    usage()
    return
  }

  filename = *filenamePtr
  passphrase = *passphrasePtr

  if strings.HasSuffix(filename, "salted") {
    ef, e := lib.Read(filename, passphrase, *boolPtr)
    if e != nil {
      fmt.Println(e)
      return
    }
    fmt.Printf("decrypted chunks: %d\n", ef.NumChunks)
    fmt.Printf("output file: %s\n", ef.DecryptedFilename)
  } else {
    ef := lib.New(filename, passphrase, *boolPtr)
    ef.Encrypt()
    fmt.Printf("encrypted chunks: %d\n", ef.NumChunks)
    fmt.Printf("output file: %s\n", ef.EncryptedFilename)
  }
}
