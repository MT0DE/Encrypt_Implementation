package main

import (
	"bufio"
	"io/fs"
	"sort"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"io"
	"os"
	"time"
	"encoding/hex"
)

//key size: 128bit
const KEY_SIZE_IN_BYTES = 16

func generate_key_and_save_to(filename string){
	// create the 128bit key for AES128
	byte_arr := make([]byte, KEY_SIZE_IN_BYTES)

	//reads random bytes into byte_arr
	read_bytes, err := rand.Read(byte_arr)
	if read_bytes != len(byte_arr){
		fmt.Println("KeyGeneratorLog: Not enough bytes were read\nSpecific issue: ", err)
		os.Exit(1)
	}
	fmt.Println("KeyGeneratorLog: Generated", KEY_SIZE_IN_BYTES, "cryptographically secure bytes")
	
	//create file and write the key to it
	//from https://stackoverflow.com/questions/12518876/how-to-check-if-a-file-exists-in-go
	if _, err := os.Stat(filename); errors.Is(err, os.ErrNotExist){
		fmt.Println("KeyGeneratorLog: File does not exist, but will be created")
	}else{
		fmt.Println("KeyGeneratorLog: Files exist, but its contents will be truncated/removed")
	}
	outputfile, err := os.Create(filename)
	if(err != nil){
		fmt.Println(err)
		os.Exit(1)
	} else{
		fmt.Printf("KeyGeneratorLog: Opened \"%s\" for writing\n", filename)
	}

	//defer will execute the supplied function BEFORE the fucntions exists
	defer outputfile.Close()

	writer := bufio.NewWriter(outputfile)
	defer writer.Flush()
	bytes_written, err := writer.Write(byte_arr)
	if err != nil{
		fmt.Println("KeyGeneratorLog: ",err,"\nOnly", bytes_written, "were written to file")
	}
	fmt.Printf("KeyGeneratorLog: \"%s\" was succesfully created and wrote %d bytes\n", filename, bytes_written)
}

func get_plaintext_files() [][]byte {
	curr_dir, err := os.Getwd()
	if err != nil{
		fmt.Println(err)
	}
	defer os.Chdir(curr_dir)

	//Change directory and save the path
	plain_text_path := "../plaintext_files/AES"
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

		file_byte, err := os.ReadFile(new_curr_dir + "\\" + file.Name())

		if err != nil{
			fmt.Println(err)
		}else{
			plain_text = append(plain_text, file_byte)
		}
	}
	return plain_text
}

func load_key(file string) []byte{
	key, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrExist){
		fmt.Println(err)
		
	}else if err != nil{
		fmt.Fprintf(os.Stderr, "Error from loading key: %s\n", err)
	}
	return key
}

func padding(text []byte, blocksize int32) []byte{
	print("padding was done")
	return text
}

func encrypt(text []byte, key []byte) []byte{
	//check if text is a multiple of the block size
	if(len(text) % aes.BlockSize != 0){
		text = padding(text, aes.BlockSize)
		// fmt.Fprint(os.Stderr, "Error: CBC works on blocks (AES Block Size) and the text was not of this size\nNeed padding")
		// os.Exit(1)
	}
	
	plaintext := text

	//taken from https://pkg.go.dev/crypto/cipher#example-NewCBCEncrypter
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	
	//create iv with random bytes
	iv := ciphertext[:aes.BlockSize] //16 byte array
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		fmt.Fprintf(os.Stderr, "Error from reading random bytes: %s\n", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil{
		fmt.Fprintf(os.Stderr, "Error while creating the cipher: %s\n", err)
	}

	CBCmode := cipher.NewCBCEncrypter(block, iv)
	CBCmode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext
}

func decrypt(ciphertext []byte, key []byte) []byte{
	//taken from https://pkg.go.dev/crypto/cipher#NewCBCDecrypter
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	return ciphertext
}

func benchmark(files_to_encrypt [][]byte, key []byte){
	iterations := 500.0
	acc_time := 0.0
	var text_as_byte []byte
	fmt.Println("Encrypting with AES128 {iterations} times")
	for file_index := 0; 0 < len(files_to_encrypt); file_index++{
		text_as_byte = files_to_encrypt[file_index]
		size_of_text := len(text_as_byte)
		for i := 0; i < int(iterations); i++ {
			fmt.Printf("\r [%d] filesize %d bytes", i+1, size_of_text)
			start := time.Now()
			encrypt(text_as_byte, key)
			end := time.Now()

			acc_time += float64(end.Sub(start).Nanoseconds())
		}
		tot_time := (acc_time) / (iterations*1000000)
		fmt.Printf("	%.3fms\n", tot_time)
		acc_time = 0
	}
}

func test_aes_no_padding_but_correct_lenght(){
	filename := "secret.key"
	key := load_key(filename)

	text, err := hex.DecodeString("73c86d43a9d700a253a96c85b0f6b03ac9792e0e757f869cca306bd3cba1c62b")
	if err != nil{

	}
	fmt.Println(text)
	encrypt := encrypt(text, key)

	decrypted := decrypt(encrypt, key)

	fmt.Println(decrypted)
}

func main() {
	filename := "secret.key"
	// generate_key_and_save_to(filename)

	//array of bytes
	plaintext_files := get_plaintext_files()
	sort.Slice(plaintext_files, func(i, j int) bool {
		return len(plaintext_files[i]) < len(plaintext_files[j]) 
	})

	//load key
	key := load_key(filename)
	// stringify_key := string(key)
	// fmt.Printf("key in utf-8: %s\n", stringify_key)

	benchmark(plaintext_files, key)

	// test_aes_no_padding_but_correct_lenght()
}
