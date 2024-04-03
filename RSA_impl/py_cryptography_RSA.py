import os
import sys
import time
import glob

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

TEXT = "It's over, I have the high ground"

def generate_keys():
    pr_key = rsa.generate_private_key(65537, 3072) # Key size could also be tested for 4096
    pr_pem = pr_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
   
    # REMOVE LATER
    # pu_key = pr_key.public_key()
    # pu_pem = pu_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)

    with open("3072_private_key.pem", "wb") as key_file:
        key_file.write(pr_pem)
        print('Private key generated')

    # REMOVE LATER
    # with open("3072_public_key.pem", "wb") as key_file:
    #     key_file.write(pu_pem)
    #     print('Public key generated')

def load_pr_key():
    pr_pem = open("4096_private_key.pem", "rb").read()
    pr_key = serialization.load_pem_private_key(pr_pem, None)
    return pr_key

### REMOVE LATER
# def load_pu_key():
#     pu_pem = open("4096_public_key.pem", "rb").read()
#     pu_key = serialization.load_pem_public_key(pu_pem, None)
#     return pu_key

# def encrypt_message(plaintext_bytes: bytes):
def encrypt_message(plaintext: bytes, pu_key):
    ciphertext = pu_key.encrypt(
        plaintext, 
        padding.OAEP(
            padding.MGF1(hashes.SHA256()), 
            hashes.SHA256(), 
            None
        )  
    )
    return ciphertext

def decrypt_message(ciphertext: bytes, pr_key):
    plaintext = pr_key.decrypt(
        ciphertext, 
        padding.OAEP(
            padding.MGF1(hashes.SHA256()), 
            hashes.SHA256(), 
            None
        )
    )
    return plaintext

def load_files_fifo():
   print("loading files into memory")
   # print(f"I am at {os.getcwd()}")
   
   # Save current directory and change to select directory
   curr_dir = os.getcwd()
   os.chdir('../plaintext_files/RSA')
   # print(f"I am now at {os.getcwd()}")

   data_from_files = []
   
   #Select all .txt files    
   txtfiles = [f for f in glob.glob("*.txt")]
   for filename in txtfiles:
        # print(filename)
        # Open the file as binary file and read all of its content
        with open(os.path.join(os.curdir, filename), 'rb') as df:
            data_from_files.append(df.read())
   
   #Return to original directory
   os.chdir(curr_dir)
   return data_from_files


def benchmark():
    data = load_files_fifo()
    data.sort(key=sys.getsizeof, reverse=True)
    pr_key = load_pr_key()
    pu_key = pr_key.public_key()


    acc_time = 0
    iterations = 500
    text = ""
    print(f"Encrypting with RSA {iterations} times")
    for _ in range(len(data)):
        full_text = bytes(data.pop())
        size_of_text = len(bytes(text, "utf-8"))
        for x in range(iterations):
            print("\r" + f'   [{x+1}] filesize {size_of_text} bytes, key-size of 4096 bit', end='')
            time_x1 = time.perf_counter()
            encrypt_message(full_text, pu_key)
            time_x2 = time.perf_counter()
            acc_time += time_x2 - time_x1
        tot_time = acc_time * 1000 / (iterations)
        print(f'    {tot_time:.3f} ms')
        acc_time = 0



#generate_keys()
benchmark()