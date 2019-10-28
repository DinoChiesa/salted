# golang NaCl secretbox command-line tool

Use this class to encrypt large files with secretbox.
See https://godoc.org/golang.org/x/crypto/nacl/secretbox

## Motivation

Inspired by [this post](https://blog.gtank.cc/modern-alternatives-to-pgp/) which
I saw on Hackernews, I wanted to write a command-line tool to act as an
alternative to PGP for encrypting files.

## Building

You need to build the tool before using it.

```
go build salt_file.go

```

## Using the tool

To encrypt:

```
./salt_file -filename whatever.txt  -passphrase "passphrase goes here"

```

The output will be placed in <filename>.salted.  For the above, `whatever.txt.salted`

To decrypt:

```
./salt_file -filename whatever.txt.salted  -passphrase "passphrase goes here"

```

The output will be placed in <filename>.decrypted.  For the above, `whatever.txt.salted.decrypted`


## Details

This class uses secretbox for the storage.
It generates keys from passphrases using Argon2id.

When encrypting:

* It encrypts in ~4k blocks, and adds a header and footer block to the encrypted output file .
* It randomly generates a nonce base for each file, and a salt for generating keys
* it uses one generated key for encryption, and another for hmac-sha256
* encrypts each block with a sequentially incremented nonce
* sums the encrypted text into the hmac
* the final Hmac sha256 is stored in the footer

When decrypting:

* it reads the nonce and salt in the header
* uses a sequential nonce for each block
* generates keys from the salt and provided passphrase
* decrypts each block and checks the size of the block, and the nonce used
* verifies the hmac

## Structure of Encrypted File

The structure of the encrypted File is:

    [header]
    [data block 0]
    [data block 1]
     ...
    [data block n]
    [footer]

header:

    00 - 01  magic bytes (0x44 0x43)
    02 - 03  header version  (0x00 0x01)
    04 - 27  generated (random) 24-byte nonce base for this file
    28 - 43  16-bytes of salt for the crypto (random)
    44 - 63  zeros (ignored)

footer:

    00 - 01  magic bytes (0x44 0x44)
    02 - 03  footer version (0x00 0x01)
    04 - 11  number of data blocks (8 byte ulong)
    12 - 43  32 byte hmac-sha256 signature of header and all data blocks
    44 - 63  zeroes (ignored)

data block:

    00 - 24  nonce
    24 - 28  size of plaintext data in chunk
    28 - 4k  ciphertext including trailing poly1305 tag (16 bytes)


## Bugs

* The encrypter always rounds up the size of the output to the nearest 4k boundary.

* This has not been tested with very large files.

* The passphrase is always and only accepted as a command-line option.  No silent input is possible.

* The handling of filename is naive.

* there is no option to direct the encrypted or decrypted data to stdout; there
  is no option to accept input from stdin

* There's no option to compress the data.
