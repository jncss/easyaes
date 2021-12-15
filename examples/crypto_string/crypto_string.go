package main

import (
	"fmt"

	"github.com/jncss/easyaes"
)

func main() {
	/*
		key := "This is the key"
		text := "This is the text to encrypt"

		encryptedText, _ := easyaes.EncryptString(key, text)
		fmt.Println("Encrypted text: ", encryptedText)

		decryptedText, _ := easyaes.DecryptString(key, encryptedText)
		fmt.Println("Decrypted text: ", decryptedText)
	*/

	key := "Aixo es la clau"

	decryptedText, _ := easyaes.DecryptString(key, "Wwaf/AL7dxfyPHUGMMl5mqUniyhkKYg66ZZNXPTuvD7eAe9AWT3LirKtb66TJafmxuaOLKA87t6AinuLMW3k7Q==")
	fmt.Println("Decrypted text: ", decryptedText)
}
