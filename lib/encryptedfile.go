package saltedlib

import (
  "golang.org/x/crypto/nacl/secretbox"
  "golang.org/x/crypto/argon2"
  "math/rand"
  "crypto/hmac"
  "crypto/sha256"
  "encoding/binary"
  "encoding/base64"
  "time"
  "bytes"
  "errors"
  "hash"
  "fmt"
  "io"
  "os"
)

const (
  ChunkSize = 4096
  HeaderSize = 64
)

type Argon2Params struct {
	timeCost	uint32
	memoryCost uint32 // kibibytes
	lanes 	  uint8
}

type EncryptedFile struct {
  hmacsha256 hash.Hash
  sourceFilename string
  OutputFilename string
  InputFilename string
  infile *os.File
  outfile *os.File
  NumChunks int64
  nonceBase [24]byte
  currentNonce [24]byte
  salt [16]byte
  encryptionKey [32]byte
  signingKey [32]byte
  Verbose bool
	argon2params Argon2Params
}

func randomBytes(len int) ([]byte) {
  bytes := make([]byte, len)
  rand.Read(bytes)
  return bytes
}

func ReadAndEncrypt(sourceFilename string, destFilename string, passphrase string, verbose bool) (*EncryptedFile, error) {
  ef := new(EncryptedFile)
  ef.InputFilename = sourceFilename
  ef.OutputFilename = destFilename
  ef.NumChunks = 0
  ef.Verbose = verbose

	ef.argon2params = Argon2Params {
		// as per recommendations in RFC 9106
		timeCost: 1,
		memoryCost: 2048*1024,
		lanes: 4,
	}

  rand.Seed(time.Now().UnixNano())
  copy(ef.nonceBase[:], randomBytes(24))
  if ef.Verbose {
    fmt.Printf("nonce: [% x]\n", ef.nonceBase)
  }
  copy(ef.currentNonce[:], ef.nonceBase[:])

  copy(ef.salt[:], randomBytes(16))
  if ef.Verbose {
    fmt.Printf("salt: [% x]\n", ef.salt)
  }
  encryptionKey, signingKey := generateKeys(ef.argon2params, passphrase, ef.salt)
  ef.encryptionKey = encryptionKey

  if ef.Verbose {
    fmt.Printf("key1: [% x]\n", encryptionKey)
    fmt.Printf("key2: [% x]\n", signingKey)
  }

  ef.hmacsha256 = hmac.New(sha256.New, signingKey[:])
  // h.Write([]byte(message))
  // return base64.StdEncoding.EncodeToString(h.Sum(nil))
  return ef, ef.encrypt()
}


func DeriveOutputFilename(sourceFilename string, decrypt bool) (string) {
  if decrypt {
		if sourceFilename == "-" {
			return "out.decrypted"
		} else {
			return sourceFilename + ".decrypted"
		}
	}	else {
    fmt.Printf("deriving name for Encrypt...\n")
		if sourceFilename == "-" {
			return "out.salted"
		} else {
			return sourceFilename + ".salted"
		}
	}
}

func ReadAndDecrypt(sourceFilename string, destFilename string, passphrase string, verbose bool) (*EncryptedFile, error) {
  ef := new(EncryptedFile)
  ef.InputFilename = sourceFilename
  ef.OutputFilename = destFilename
  ef.NumChunks = 0
  ef.Verbose = verbose

 	if ef.InputFilename == "-" {
		ef.infile = os.Stdin
	}	else {
		encryptedFile, e := os.Open(ef.InputFilename)
		if e != nil {
			return nil, e
		}
		defer encryptedFile.Close()
		ef.infile = encryptedFile
	}

  e := ef.readHeader()
  if e != nil {
    return ef, e
  }
  if ef.Verbose {
    fmt.Printf("nonce: [% x]\n", ef.nonceBase)
    fmt.Printf("salt: [% x]\n", ef.salt)
  }
  copy(ef.currentNonce[:], ef.nonceBase[:])

  encryptionKey, signingKey := generateKeys(ef.argon2params, passphrase, ef.salt)

  if ef.Verbose {
    fmt.Printf("key1: [% x]\n", encryptionKey)
    fmt.Printf("key2: [% x]\n", signingKey)
  }

  ef.encryptionKey = encryptionKey
  ef.hmacsha256 = hmac.New(sha256.New, signingKey[:])

 	if ef.OutputFilename == "-" {
		ef.outfile = os.Stdout
	}	else {
		decryptedFile, e := os.Create(ef.OutputFilename)
		if e != nil {
			return ef, e
		}
		defer decryptedFile.Close()
		ef.outfile = decryptedFile
	}

  footer, e := ef.readAndDecryptChunks()
  if e != nil {
    return ef, e
  }

  if ef.Verbose {
    fmt.Printf("footer: [% x]\n", footer[:64])
  }

  // check NumChunks
  b := footer[4:12]
  assertedNumChunks := int64(binary.LittleEndian.Uint64(b))
  if assertedNumChunks != ef.NumChunks {
    return ef, errors.New("chunk count mismatch")
  }

  // check hmac here
  assertedHmac := footer[12:44]
  computedHmac := ef.hmacsha256.Sum(nil)
  if ef.Verbose {
    fmt.Printf("hmacs:\n")
    fmt.Printf("  asserted: %s\n", base64.StdEncoding.EncodeToString(assertedHmac))
    fmt.Printf("  computed: %s\n", base64.StdEncoding.EncodeToString(assertedHmac))
  }
  if bytes.Compare(assertedHmac, computedHmac) != 0 {
    // base64.StdEncoding.EncodeToString([]byte)
    return ef, errors.New("invalid hmac")
  }

  return ef, nil
}

func generateKeys(params Argon2Params, passphrase string, salt [16]byte) ([32]byte, [32]byte) {
  // var timeCost uint32 = 1
  // var threads uint8 = 4
  // var memoryCostInKibibytes uint32 = 2048*1024 // 2 GiB
  var desiredKeyBits uint32 = 64
  key := argon2.IDKey([]byte(passphrase), salt[:],
		params.timeCost,
		params.memoryCost,
		params.lanes, desiredKeyBits)
  var key1 [32]byte
  copy(key1[:], key[:32])
  var key2 [32]byte
  copy(key2[:], key[32:])
  return key1, key2
}


func (ef *EncryptedFile) readHeader() (error) {

  headerchunk := make([]byte, HeaderSize)
  _, e := ef.infile.Read(headerchunk)

  if e != nil {
    return e
  }

  // magic number
  magic := headerchunk[0:2]
  expected := []byte{ 0x44, 0x43 }
  if bytes.Compare(magic, expected) != 0 {
    return errors.New("invalid magic number")
  }

  // check version number
  assertedVersion := headerchunk[2:4]
  version1bytes := []byte{0x00, 0x01 }
  version2bytes := []byte{0x00, 0x02 }
  if bytes.Compare(assertedVersion, version1bytes) == 0 {
		if ef.Verbose {
			fmt.Print("version 1 header\n")
		}
		// 24-byte nonce base for this file
		copy(ef.nonceBase[:], headerchunk[4:28])

		// 28 - 43  16-bytes of salt for the crypto key generation
		copy(ef.salt[:], headerchunk[28:44])

		// zero padding to 64 bytes
		expected = make([]byte, 20)
		zeros := headerchunk[44:]
		if bytes.Compare(zeros, expected) != 0 {
			return errors.New("corrupted v1 header")
		}

		ef.argon2params = Argon2Params {
			timeCost: 1,
			memoryCost: 64*1024,
			lanes: 4,
		}
		return nil

  } else if bytes.Compare(assertedVersion, version2bytes) == 0 {
		if ef.Verbose {
			fmt.Print("version 2 header\n")
		}
		// 24-byte nonce base for this file
		copy(ef.nonceBase[:], headerchunk[4:28])

		// 28 - 43  16-bytes of salt for the crypto key generation
		copy(ef.salt[:], headerchunk[28:44])

		// read argon params
		ef.argon2params = Argon2Params {
			timeCost: binary.LittleEndian.Uint32(headerchunk[44:]),
			memoryCost: binary.LittleEndian.Uint32(headerchunk[48:]),
			lanes: headerchunk[52],
		}

		// zero padding to 64 bytes
		expected = make([]byte, 11)
		zeros := headerchunk[53:]
		if bytes.Compare(zeros, expected) != 0 {
			return errors.New("corrupted v2 header")
		}
		return nil

	} else	{
    return errors.New(fmt.Sprintf("invalid version number [% x]", assertedVersion))
  }
}


func isFooter(chunk []byte) bool {
  expected := []byte{ 0x44, 0x44, 0x00, 0x01 }
  return bytes.Compare(chunk[:4], expected[:]) == 0
}

func (ef *EncryptedFile) readAndDecryptChunks() ([]byte,error) {
  chunk := make([]byte, ChunkSize)
  var chunkNumber int64 = 0
  for {
    zero(chunk)
    _, e := ef.infile.Read(chunk)

    if e != nil {
      if e == io.EOF {
        break
      }
      return nil, e
    }

    if isFooter(chunk) {
      break
    }

    ef.hmacsha256.Write(chunk)
    decrypted, e := ef.decryptChunk(chunk, chunkNumber)
    if e != nil {
      if e == io.EOF {
        break
      }
      return nil, e
    }

    // len(decrypted) == ChunkSize - secretbox.overhead
    _, e = ef.outfile.Write(decrypted)
    if e != nil {
      fmt.Printf("writing chunk %d, error:\n%#v\n", chunkNumber, e)
      return nil,e
    }
    chunkNumber += 1
  }
  ef.NumChunks = chunkNumber
  return chunk, nil
}


func (ef *EncryptedFile) WriteHeader() {

  // magic number and version number (currently always v2)
  magicAndVersion := []byte{ 0x44, 0x43, 0x00, 0x02 }

  _, e := ef.outfile.Write(magicAndVersion)
  if e != nil {
    fmt.Printf("writing magic, error:\n%#v\n", e)
    return
  }

  // 24-byte nonce base for this file
  _, e = ef.outfile.Write(ef.nonceBase[:])
  if e != nil {
    fmt.Printf("writing nonce, error:\n%#v\n", e)
    return
  }

  // 28 - 43  16-bytes of salt for the crypto key generation
  _, e = ef.outfile.Write(ef.salt[:])
  if e != nil {
    fmt.Printf("writing salt, error:\n%#v\n", e)
    return
  }

  // 44 - 47  4-bytes of time cost for argon2
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b[0:], ef.argon2params.timeCost)
  _, e = ef.outfile.Write(b[:])
  if e != nil {
    fmt.Printf("writing time cost, error:\n%#v\n", e)
    return
  }

  // 48 - 52  4-bytes of memory cost for argon2
	binary.LittleEndian.PutUint32(b[0:], ef.argon2params.memoryCost)
  _, e = ef.outfile.Write(b[:])
  if e != nil {
    fmt.Printf("writing memory cost, error:\n%#v\n", e)
    return
  }

  // 53  1-byte of lanes/threads
  lanes := []byte{ ef.argon2params.lanes }
  _, e = ef.outfile.Write(lanes[:])
  if e != nil {
    fmt.Printf("writing lanes, error:\n%#v\n", e)
    return
  }

  // zero padding to 64 bytes
  zeros := make([]byte, 11)
  _, e = ef.outfile.Write(zeros)
  if e != nil {
    fmt.Printf("writing zeros, error:\n%#v\n", e)
    return
  }
}


func (ef *EncryptedFile) WriteFooter() {
  magicAndVersion := []byte{ 0x44, 0x44, 0x00, 0x01 }
  _, e := ef.outfile.Write(magicAndVersion)
  if e != nil {
    fmt.Printf("writing magic, error:\n%#v\n", e)
    return
  }

  // number of chunks written
  b := make([]byte, 8)
  binary.LittleEndian.PutUint64(b, uint64(ef.NumChunks))
  _, e = ef.outfile.Write(b)
  if e != nil {
    fmt.Printf("writing number of chunks, error:\n%#v\n", e)
    return
  }

  // 32 byte hmac-sha256 signature of header and all data blocks
  hmacSum := ef.hmacsha256.Sum(nil)
  _, e = ef.outfile.Write(hmacSum)
  if e != nil {
    fmt.Printf("writing hmacsha256, error:\n%#v\n", e)
    return
  }

  // zero padding to 64 bytes
  zeros := make([]byte, 20)
  _, e = ef.outfile.Write(zeros)
  if e != nil {
    fmt.Printf("writing zeros, error:\n%#v\n", e)
    return
  }
}

// treats the final 8 bytes as a little-endian value and
// increments it
func incrementNonce(nonce *[24]byte) {
  ctr := nonce[len(nonce)-8:]
  binary.LittleEndian.PutUint64(ctr, binary.LittleEndian.Uint64(ctr)+1)
}


func (ef *EncryptedFile) encryptChunk(blob []byte, nbytes int, chunkNumber int64) []byte {
  // Seal appends an encrypted and authenticated copy of message to out, which
  // must not overlap message. The key and nonce pair must be unique for each
  // distinct message and the output will be Overhead bytes longer than message.
  if ef.Verbose {
    fmt.Printf("encrypting (%d bytes): [% x ...]\n", len(blob), blob[:32])
  }

  nonceAndChunkSize := make([]byte, 28)
  copy(nonceAndChunkSize[:], ef.currentNonce[:])
  binary.LittleEndian.PutUint32(nonceAndChunkSize[24:], uint32(nbytes))

  encrypted := secretbox.Seal(nonceAndChunkSize, blob, &ef.currentNonce, &ef.encryptionKey)
  incrementNonce(&ef.currentNonce)
  if ef.Verbose {
    fmt.Printf("result (%d bytes): [% x ...]\n", len(encrypted), encrypted[:32])
  }
  return encrypted
}

func (ef *EncryptedFile) decryptChunk(blob []byte, chunkNumber int64) ([]byte, error) {

  // Open authenticates and decrypts a box produced by Seal and appends the
  // message to out, which must not overlap box. The output will be Overhead
  // bytes smaller than box.

  if ef.Verbose {
    fmt.Printf("decrypting (%d bytes): [% x ...]\n", len(blob), blob[:32])
  }
  // check nonce
  if bytes.Compare(ef.currentNonce[:], blob[:24]) != 0 {
    return nil, errors.New("incorrect nonce")
  }

  decrypted, ok := secretbox.Open(nil, blob[28:], &ef.currentNonce, &ef.encryptionKey)
  if !ok {
    return nil, errors.New("failed to decrypt")
  }

  if ef.Verbose {
    fmt.Printf("result (%d bytes): [% x ...]\n", len(decrypted), decrypted[:32])
  }
  incrementNonce(&ef.currentNonce)

  // check size
  b := make([]byte, 4)
  copy(b[:], blob[24:28]);
  sizeOfThisChunk := int32(binary.LittleEndian.Uint32(b))

  if sizeOfThisChunk > ChunkSize {
    return nil, errors.New("Invalid chunk size");
  }

  return decrypted[:sizeOfThisChunk], nil
}


func zero(a []byte) {
  // zero the array
  for index, _ := range a {
    a[index] = 0
  }
}

func (ef *EncryptedFile) encrypt() error {

 	if ef.InputFilename == "-" {
		ef.infile = os.Stdin
	}	else {
		plaintextFile, e := os.Open(ef.InputFilename)
		if e != nil {
			fmt.Println(e)
			return e
		}
		defer plaintextFile.Close()
		ef.infile = plaintextFile
	}

 	if ef.OutputFilename == "-" {
		ef.outfile = os.Stdout
	} else {
		fmt.Printf("creating ciphertext file...(%s)\n", ef.OutputFilename)
		ciphertextFile, e := os.Create(ef.OutputFilename)
		if e != nil {
			fmt.Printf("while creating ciphertext file, error:\n%#v\n", e)
			return e
		}
		defer ciphertextFile.Close()
		ef.outfile = ciphertextFile
	}

  ef.WriteHeader()

  // overhead for each chunk is
  //   nonce (24 bytes)
  //   poly1305 signature (16 bytes)
  //   chunksize (4 bytes)
  chunk := make([]byte, ChunkSize - 24 - 4 - 16)
  var chunkNumber int64 = 0
  for {
    zero(chunk)
    nbytes, e := ef.infile.Read(chunk)

    if e != nil {
      if e != io.EOF {
        fmt.Printf("while reading plaintext file, error:\n%#v\n", e)
      }
      break
    }

    encrypted := ef.encryptChunk(chunk, nbytes, chunkNumber)
    // len(encrypted) == ChunkSize
    ef.hmacsha256.Write(encrypted)
    _, e = ef.outfile.Write(encrypted)
    if e != nil {
      fmt.Printf("writing chunk %d, error:\n%#v\n", chunkNumber, e)
      return e
    }
    chunkNumber += 1
  }
  ef.NumChunks = chunkNumber
  ef.WriteFooter()
  return nil
}
