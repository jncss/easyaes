package main

import (
	"fmt"

	"github.com/jncss/easyaes"
)

func main() {

	key := "This is the key"
	text := "This is the text to encrypt"

	encryptedText, _ := easyaes.EncryptString(key, text)
	fmt.Println("Encrypted text: ", encryptedText)

	decryptedText, _ := easyaes.DecryptString(key, encryptedText)
	fmt.Println("Decrypted text: ", decryptedText)
}
