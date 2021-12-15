package main

import (
	"fmt"
	"io/ioutil"

	"github.com/jncss/easyaes"
)

func chkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	// Encrypt / Decrypt file
	key := "This is the key"

	encryptedData, err := easyaes.EncryptFile(key, "/etc/hosts")
	chkErr(err)
	fmt.Println("Encrypted file: ", *encryptedData)

	// Save encrypted data to new file
	err = ioutil.WriteFile("./hosts.crypto", []byte(*encryptedData), 0644)
	chkErr(err)

	// Decrypt from file
	decryptedData, err := easyaes.DecryptFile(key, "./hosts.crypto")
	chkErr(err)

	fmt.Println(string(*decryptedData))
}
