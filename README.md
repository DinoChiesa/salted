# golang NaCl secretbox command-line tool

Use this class to encrypt large files with secretbox.
See https://godoc.org/golang.org/x/crypto/nacl/secretbox

## Motivation

Inspired by [this post](https://blog.gtank.cc/modern-alternatives-to-pgp/) which
I saw on Hackernews, I wanted to write a command-line tool to act as an
alternative to PGP for encrypting files.

## Building

You need to build the tool before using it. To do that, you need to install Go v1.16 or later. Get help on that [here](https://go.dev/doc/install).

Then,

```
go build  salt_file.go

```

You should get an executable for your platform.

## Tests

There are no tests for the command-line utility.  There is one test for the library.
```
cd lib
go test

```


## Using the tool

To encrypt:

On a *nix system:
```
./salt_file -in whatever.txt  -passphrase "passphrase goes here"

```

On a Windows system:
```
.\salt_file.exe -in whatever.txt  -passphrase "passphrase goes here"

```

The output will be placed in <filename>.salted.  For the above,
`whatever.txt.salted`. You can specify the output file with the `-out` option.

```
./salt_file -in myfile.txt  -passphrase "passphrase goes here" -out myfile.salted

```

If you specify `-in -` the tool will read from Stdin:

```
cat myfile.txt | salt_file -in -  -passphrase "passphrase goes here" -out myfile.salted

```

And with `-out -`, the tool can write to Stdout:

```
cat myfile.txt | salt_file -in -  -passphrase "passphrase goes here" -out - > ./myfile.salted

```


To decrypt:

```
./salt_file -in whatever.txt.salted  -passphrase "passphrase goes here" -decrypt

```

The output will be placed in <filename>.decrypted.  For the above,
`whatever.txt.salted.decrypted`. Again, you can specify the `-out` option for an
output file.

```
./salt_file -in file1.txt.salted  -passphrase "passphrase goes here" -decrypt -out file1.txt

```

If you omit the `-passphrase`  option, you will be prompted at the terminal.


## Details

This tool uses [secretbox](https://pkg.go.dev/golang.org/x/crypto/nacl/secretbox) for the storage. Secretbox uses XSalsa20 and Poly1305 to encrypt and authenticate messages with secret-key cryptography.

The tool generates secret keys from passphrases using Argon2id via the [argon2](https://pkg.go.dev/golang.org/x/crypto/argon2#pkg-overview) package, which implements Argon2 as described in [IETF RFC 9106](https://datatracker.ietf.org/doc/html/rfc9106). The argon parameters are: lanes: 4, memoryLimit 2GiB, timeLimit: 1. This makes it sort of slow to encrypt - specifically during key generation.

When encrypting:

* It encrypts in ~4k blocks, and adds a header and footer block to the encrypted output file .
* It randomly generates a nonce base for each file, and a salt for generating keys
* it uses one generated key for encryption, and another for HMAC-SHA256
* encrypts each block with a sequentially incremented nonce
* sums the encrypted text into the HMAC
* the final HMAC SHA256 is stored in the footer

When decrypting:

* it reads the nonce and salt in the header
* uses a sequential nonce for each block
* generates keys from the salt and provided passphrase
* decrypts each block and checks the size of the block, and the nonce used
* verifies the HMAC

## Structure of Encrypted File

The structure of the encrypted File is:

    [header]
    [data block 0]
    [data block 1]
     ...
    [data block n]
    [footer]

header v1:

    00 - 01  magic bytes (0x44 0x43)
    02 - 03  header version  (0x00 0x01)
    04 - 27  generated (random) 24-byte nonce base for this file
    28 - 43  16-bytes of salt for the crypto (random)
    44 - 63  zeros (20 bytes, must be zero, though not used)

header v2:

    00 - 01  magic bytes (0x44 0x43)
    02 - 03  header version  (0x00 0x02)
    04 - 27  generated (random) 24-byte nonce base for this file
    28 - 43  16-bytes of salt for the crypto (random)
    44 - 47  argon2 time cost (4 bytes)
    48 - 51  argon2 memory cost (4 bytes)
    52 - 52  argon2 lanes/threads (1 byte)
    53 - 63  zeros (11 bytes, must be zero, though not used)

footer:

    00 - 01  magic bytes (0x44 0x44)
    02 - 03  footer version (0x00 0x01)
    04 - 11  number of data blocks (8 byte ulong)
    12 - 43  32 byte HMAC-SHA256 signature of header and all data blocks
    44 - 63  zeroes (ignored)

data block:

    00 - 24  nonce
    24 - 28  size of plaintext data in chunk
    28 - 4k  ciphertext including trailing 16 byte poly1305 tag


## Extras

There's [an emacs generic mode](./salted.el) for opening and editing salted files.
Kinda like epa for PGP-encrypted files.

## Bugs

* The encrypter always rounds up the size of the output to the nearest 4k
  boundary. It's not very space-efficient for smaller files. There's no way
  to modify this block size.

* This has not been tested with very large files.

* When encrypting, there is no way to specify the argon2 parameters for key
  generation. They're fixed at the RFC 9106 recommendation.

* When decrypting, the tool does not check the argon2 parameters for sanity.

* There's no option to compress the data before encrypting.

* There's no option to specify the Argon2id parameters for generating keys.

* When redirecting the output to stdout, the prompt for passphrase will appear in the output.
