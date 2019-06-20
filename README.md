# golang NaCl secretbox command-line tool

Use this class to encrypt large files with secretbox.
See https://godoc.org/golang.org/x/crypto/nacl/secretbox

## Details

This class uses secretbox for the storage.
It generates keys from passphrases using Argon2id.

## Building

```
go build salt_file.go

```

## Bugs

* The encrypter always rounds up the size of the output to the nearest 4k boundary.

* This has not been tested with very large files.

