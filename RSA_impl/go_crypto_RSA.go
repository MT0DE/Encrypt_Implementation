package main

import (
	// "bytes"
	// "errors"
	// "crypto/rsa"
	// "bufio"
	// "crypto/rand"
	//"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadPrivate loads an (unencrypted) RSA private key from PEM data
func load_pr_key(filepath string) *rsa.PrivateKey {
	// Read the bytes of the PEM file
	pemData, err := os.ReadFile(filepath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from loading key: %s\n", err)
	}

	// Use the PEM decoder and parse the private key
	pemBlock, _ := pem.Decode(pemData)
	parseResult, _ := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	key := parseResult.(*rsa.PrivateKey)

	return key
}

func encrypt_message(plaintext []byte, pu_key *rsa.PublicKey) []byte {

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pu_key, plaintext, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from encryption: %s\n", err)
	}

	return ciphertext
}

func decrypt_message(ciphertext []byte, pr_key *rsa.PrivateKey) []byte {
	plaintext, err := rsa.DecryptOAEP(sha256.New(), nil, pr_key, ciphertext, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from decryption: %s\n", err)
	}

	return plaintext
}

func main() {

	pr_key := load_pr_key("4096_private_key.pem")
	pu_key := pr_key.PublicKey

	plaintext := "hello"
	ciphertext := encrypt_message([]byte(plaintext), &pu_key)
	result := decrypt_message(ciphertext, pr_key)

	fmt.Printf("plaintext: %s\n", plaintext)

	fmt.Printf("ciphertext: %b\n", ciphertext)
	fmt.Printf("result: %s\n", result)

}
