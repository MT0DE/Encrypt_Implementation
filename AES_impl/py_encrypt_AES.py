from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os


def pad(content, size) -> bytes:
    padder = padding.PKCS7(size).padder()

    #After finalize has been issued, .update will raise AlreadyFinalized exception
    padded_data = padder.update(content)+ padder.finalize()

    return padded_data

def unpad(content, size):
    unpadder = padding.PKCS7(128).unpadder()
    
    data = unpadder.update(content) + unpadder.finalize()

    return data 

def main():
    salt = os.urandom(32)
    
    message = "hello, secret world!" # Using standard "utf-8" and "strict"
    print(message)
    padded_data = pad(message.encode(), algorithms.AES.block_size)

    unpadded_data = unpad(padded_data, algorithms.AES.block_size)

    print(unpadded_data.decode())

if __name__ == "__main__":
    main()
    






