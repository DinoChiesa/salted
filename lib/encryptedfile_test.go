package saltedlib

import (
	//"crypto/sha256"
	//"io"
	"os"
	"fmt"
	"testing"
	"github.com/sergi/go-diff/diffmatchpatch"
)

func TestEncryptBasic(t *testing.T) {

	var ef *EncryptedFile
	var e error
	wantVerbose := true
  plaintextFilename := "../testresources/testfile.txt";
  encryptedFilename := plaintextFilename + ".salted";
  passphrase := "golang-2023-FTW";

	outfile, e := os.CreateTemp("", "salted-test")
  if e != nil {
		t.Errorf("Could not create temporary file: %q", e)
	}

	fmt.Println("Temp output file name:", outfile.Name())

	defer os.Remove(outfile.Name())

	ef, e = ReadAndDecrypt(encryptedFilename, outfile.Name(), passphrase, wantVerbose)

  if e != nil {
		t.Errorf("Could not decrypt (%q): %q", encryptedFilename, e)
	}

  if ef.NumChunks < 1 || ef.NumChunks > 10 {
		t.Errorf("Seems like the wrong number of chunks: %q", ef.NumChunks)
	}
	fmt.Printf("number of chunks: %d\n", ef.NumChunks)


	// compare files here
	text1, e := os.ReadFile(outfile.Name());
  if e != nil {
		t.Errorf("Could not open 1st plain file: %q", e)
  }

	text2, e := os.ReadFile(plaintextFilename);
  if e != nil {
		t.Errorf("Could not open 2nd plain file: %q", e)
  }

	dmp := diffmatchpatch.New()
	diffs := dmp.DiffMain(string(text1), string(text2), true)

	//fmt.Printf("%q", diffs)
  if len(diffs) != 1 {
		t.Errorf("unexpected diff result: %q", len(diffs))
  }

  if fmt.Sprintf("%s", diffs[0].Type) != "Equal" {
		t.Errorf("unexpected diff result: %q", diffs[0].Type)
  }


	//fmt.Println(dmp.DiffPrettyText(diffs))

	// // check message digest here
  // h1 := sha256.New()
  // if _, e := io.Copy(h1, outfile); e != nil {
	// 	t.Errorf("Could not calc 1st SHA256: %q", e)
  // }
	//
	// sha256_1 := fmt.Sprintf("%x", h1.Sum(nil))
	// fmt.Printf("%s\n", sha256_1)
	//
	// plainfile, e := os.Open(plaintextFilename)
  // if e != nil {
	// 	t.Errorf("Could not open plain file: %q", e)
  // }
  // defer plainfile.Close()
	//
  // h2 := sha256.New()
  // if _, e := io.Copy(h1, plainfile); e != nil {
	// 	t.Errorf("Could not calc 2nd SHA256: %q", e)
  // }
	//
	// sha256_2 := fmt.Sprintf("%x", h2.Sum(nil))
	// fmt.Printf("%s\n", sha256_2)
	//
	// if sha256_1 != sha256_2 {
	// 	t.Errorf("SHA256 mismatch, the decryption seems to have failed.")
	// }

}
