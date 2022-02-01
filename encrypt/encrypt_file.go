package main

import (
	"fmt"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"io"
	"log"
	"os"
)

//set your public key path
const pubKey = "/Users/example/public"
//set the path of file which you are going to encrypt
const fileToEnc = "/Users/example/pgp_file"

func main() {
	log.Println("Public key:", pubKey)

	// Read in public key
	recipient, err := readEntity(pubKey)
	if err != nil {
		panic(err)
	}

	//open the file which need to be encrypted
	f, err := os.Open(fileToEnc)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()

	//create a file that the encrypted bytes go to
	dst, err := os.Create(fileToEnc + ".pgp")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer dst.Close()

	//encrypt
	err = encrypt([]*openpgp.Entity{recipient}, nil, f, dst)
	if err != nil {
		panic(err)
	}
}

func encrypt(recip []*openpgp.Entity, signer *openpgp.Entity, r io.Reader, w io.Writer) error {
	wc, err := openpgp.Encrypt(w, recip, signer, &openpgp.FileHints{IsBinary: true}, nil)
	if err != nil {
		return err
	}
	if _, err := io.Copy(wc, r); err != nil {
		return err
	}
	return wc.Close()
}

func readEntity(name string) (*openpgp.Entity, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	block, err := armor.Decode(f)
	if err != nil {
		return nil, err
	}
	return openpgp.ReadEntity(packet.NewReader(block.Body))
}