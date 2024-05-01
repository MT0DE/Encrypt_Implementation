package main

import (
	"fmt"
	"os"
	"path"
	"sort"
	"time"

	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
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

func get_plaintext_files() [][]byte {
	curr_dir, err := os.Getwd()
	if err != nil{
		fmt.Println(err)
	}
	defer os.Chdir(curr_dir)

	//Change directory and save the path
	plain_text_path := "../plaintext_files/RSA"
	os.Chdir(plain_text_path)
	new_curr_dir, b_err := os.Getwd()
	if b_err != nil{
		fmt.Println(err)
	}
	
	files, err := os.ReadDir("./")
	if err != nil{
		fmt.Println(err)
	}

	plain_text := make([][]byte, 0)
	for _, file := range files{

		file_byte, err := os.ReadFile(path.Join(new_curr_dir, file.Name()))

		if err != nil{
			fmt.Println(err)
		}else{
			plain_text = append(plain_text, file_byte)
		}
	}
	return plain_text
}

func benchmark(){
	//array of bytes
	plaintext_files := get_plaintext_files()
	sort.Slice(plaintext_files, func(i, j int) bool {
		return len(plaintext_files[i]) < len(plaintext_files[j]) 
	})
	//load key
	pr_key := load_pr_key("4096_private_key.pem")
	pu_key := pr_key.PublicKey

	iterations := 500.0
	acc_time := 0.0
	var text_as_byte []byte
	fmt.Printf("Encrypting with RSA %d times\n", int(iterations))
	for file_index := 0; file_index < len(plaintext_files); file_index++{
		text_as_byte = plaintext_files[file_index]
		size_of_text := len(text_as_byte)
		for i := 0; i < int(iterations); i++ {
			fmt.Printf("\r [%d] filesize %d bytes", i+1, size_of_text)
			start := time.Now()
			encrypt_message(text_as_byte, &pu_key)
			end := time.Now()

			acc_time += float64(end.Sub(start).Nanoseconds())
		}
		tot_time := (acc_time) / (iterations*1000000)
		fmt.Printf("	%.3fms\n", tot_time)
		acc_time = 0
	}
}

func main() {
	benchmark()
	// pr_key := load_pr_key("4096_private_key.pem")
	// pu_key := pr_key.PublicKey

	// plaintext := "hello"
	// ciphertext := encrypt_message([]byte(plaintext), &pu_key)
	// result := decrypt_message(ciphertext, pr_key)

	// fmt.Printf("plaintext: %s\n", plaintext)

	// fmt.Printf("ciphertext: %b\n", ciphertext)
	// fmt.Printf("result: %s\n", result)

}
