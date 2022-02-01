package main

import (
	"bytes"
	"fmt"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"io"
	"os"
)

//set your private key here
const priKey = ""
//set the path of file which you are going to decrypt
const fileToDec = "/Users/example/pgp_file.pgp"

func main() {
	// Read in  key
	entity, err := readEntity(priKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	f, err := os.Open(fileToDec)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()

	dst, err := os.Create(fileToDec + ".decrypt")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer dst.Close()
	err = decrypt([]*openpgp.Entity{entity}, f, dst)
	if err != nil {
		panic(err)
	}
}

func decrypt(entities []*openpgp.Entity, r io.Reader, w io.Writer) error {
	var entityList openpgp.EntityList = entities
	md, err := openpgp.ReadMessage(r, entityList, nil, nil)
	if err != nil {
		panic(err)
	}
	if _, err := io.Copy(w, md.UnverifiedBody); err != nil {
		return err
	}
	return nil
}

func readEntity(name string) (*openpgp.Entity, error) {
	//if your private key is stored in a file, use the code below instead
	/*f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	block, err := armor.Decode(f)*/
	block, err := armor.Decode(bytes.NewReader([]byte(name)))
	if err != nil {
		return nil, err
	}
	return openpgp.ReadEntity(packet.NewReader(block.Body))
}