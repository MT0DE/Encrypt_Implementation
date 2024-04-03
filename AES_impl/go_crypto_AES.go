package main

import (
	"bytes"
	"errors"
	// "crypto/aes"
	"bufio"
	"crypto/rand"
	"fmt"
	"os"
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

func encrypt(text bytes.Buffer){
	
}

func main() {
	filename := "secret.key"
	generate_key_and_save_to(filename)
	
}
