// Based on https://gist.github.com/manishtpatel/8222606

package easyaes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"io/ioutil"
)

func adjustKey(key string) []byte {
	var k []byte

	if len(key) <= 16 {
		k = make([]byte, 16)
	} else if len(key) <= 24 {
		k = make([]byte, 24)
	} else {
		k = make([]byte, 32)
	}

	copy(k, []byte(key))

	return k
}

// UseIV Use random initialization vector or not
var UseIV = true

// encrypt Encrypt using AES
func encrypt(key string, data []byte, b64 bool) (string, error) {
	k := adjustKey(key)

	block, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}

	var cipheredData []byte
	if UseIV {
		cipheredData = make([]byte, aes.BlockSize+len(data))
		iv := cipheredData[:aes.BlockSize]
		if _, err = io.ReadFull(rand.Reader, iv); err != nil {
			return "", err
		}

		stream := cipher.NewCFBEncrypter(block, iv)
		stream.XORKeyStream(cipheredData[aes.BlockSize:], data)

	} else {
		cipheredData = make([]byte, len(data))
		iv := make([]byte, aes.BlockSize)
		stream := cipher.NewCFBEncrypter(block, iv)
		stream.XORKeyStream(cipheredData, data)
	}

	if b64 {
		return base64.URLEncoding.EncodeToString(cipheredData), nil
	}

	return hex.EncodeToString(cipheredData), nil
}

// EncryptString Encrypt string to AES/Base64 string
func EncryptString(key string, text string) (string, error) {
	return encrypt(key, []byte(text), true)
}

// EncryptStringB64 Encrypt string to AES/Base64 string
func EncryptStringB64(key string, text string) (string, error) {
	return encrypt(key, []byte(text), true)
}

// EncryptStringHex Encrypt string to AES/Hex string
func EncryptStringHex(key string, text string) (string, error) {
	return encrypt(key, []byte(text), false)
}

// EncryptFile Encrypt file to AES/Base64 string
func EncryptFile(key string, filename string) (*string, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	b64, err := encrypt(key, []byte(data), true)

	return &b64, err
}

// EncryptFileB64 Encrypt file to AES/Base64 string
func EncryptFileB64(key string, filename string) (*string, error) {
	return EncryptFile(key, filename)
}

// EncryptFileHex Encrypt file to AES/Hex string
func EncryptFileHex(key string, filename string) (*string, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	b64, err := encrypt(key, []byte(data), false)

	return &b64, err
}

// Decrypt Decrypt AES
func Decrypt(key string, cryptoText string, b64 bool) ([]byte, error) {
	var ciphertext []byte

	if b64 {
		ciphertext, _ = base64.URLEncoding.DecodeString(cryptoText)
	} else {
		ciphertext, _ = hex.DecodeString(cryptoText)
	}

	k := adjustKey(key)

	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		panic("Ciphertext too short")
	}
	var iv []byte
	if UseIV {
		iv = ciphertext[:aes.BlockSize]
		ciphertext = ciphertext[aes.BlockSize:]
	} else {
		iv = make([]byte, aes.BlockSize)
	}

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// DecryptString Decrypt from Base64/AES to decrypted string
func DecryptString(key string, cryptoText string) (string, error) {
	decryptedData, err := Decrypt(key, cryptoText, true)
	return string(decryptedData), err
}

// DecryptStringB64 Decrypt from Base64/AES to decrypted string
func DecryptStringB64(key string, cryptoText string) (string, error) {
	decryptedData, err := Decrypt(key, cryptoText, true)
	return string(decryptedData), err
}

// DecryptStringHex Decrypt from Hex/AES to decrypted string
func DecryptStringHex(key string, cryptoText string) (string, error) {
	decryptedData, err := Decrypt(key, cryptoText, false)
	return string(decryptedData), err
}

// DecryptFile Decrypt from Base64/AES file to decrypted byte array
func DecryptFile(key string, filename string) (*[]byte, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	bytes, err := Decrypt(key, string(data), true)

	return &bytes, err
}

// DecryptFileB64 Decrypt from Base64/AES file to decrypted byte array
func DecryptFileB64(key string, filename string) (*[]byte, error) {
	return DecryptFile(key, filename)
}

// DecryptFileHex Decrypt from Hex/AES file to decrypted byte array
func DecryptFileHex(key string, filename string) (*[]byte, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	bytes, err := Decrypt(key, string(data), false)

	return &bytes, err
}
