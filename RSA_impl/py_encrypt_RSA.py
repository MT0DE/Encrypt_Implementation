import os
import sys
import time

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

TEXT = "It's over, I have the high ground"

def generate_keys():
    pr_key = rsa.generate_private_key(65537, 3072) # Key size could also be tested for 4096
    pr_pem = pr_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
   
    pu_key = pr_key.public_key()
    pu_pem = pu_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)

    with open("3072_private_key.pem", "wb") as key_file:
        key_file.write(pr_pem)
        print('Private key generated')

    with open("3072_public_key.pem", "wb") as key_file:
        key_file.write(pu_pem)
        print('Public key generated')

def load_pr_key():
    pr_pem = open("private_key.pem", "rb").read()
    pr_key = serialization.load_pem_private_key(pr_pem, None)
    return pr_key


def load_pu_key():
    pu_pem = open("public_key.pem", "rb").read()
    pu_key = serialization.load_pem_public_key(pu_pem, None)
    return pu_key

def encrypt_message(plaintext):
    plaintext = plaintext.encode()
    pu_key = load_pu_key()
    ciphertext = pu_key.encrypt(
        plaintext, 
        padding.OAEP(
            padding.MGF1(hashes.SHA256()), 
            hashes.SHA256(), 
            None
        )  
    )
    return ciphertext

def decrypt_message(ciphertext):
    pr_key = load_pr_key()
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
   curr_dir = os.getcwd()
   os.chdir('../AES_plaintext_files')
   # print(f"I am now at {os.getcwd()}")

   data_from_files = []
   for _, _, files in os.walk(os.getcwd()):
      # print(files)
      for filename in files:
         # print(filename)
         with open(os.path.join(os.curdir, filename), 'r') as df:
            data_from_files.append(df.read().encode())
   os.chdir(curr_dir)
   return data_from_files

def benchmark():
   data = load_files_fifo()
   acc_time = 0
   iterations = 500
   text: str = ""
   print(f"Encrypting with RSA {iterations} times")
   for _ in range(11):
      text = data.pop()
      size_of_text = sys.getsizeof(text)
      for x in range(iterations):
         print("\r" + f'   [{x+1}] filesize {size_of_text} bytes', end='')
         time_x1 = time.perf_counter()
         encrypt_message(text.encode())
         time_x2 = time.perf_counter()
         acc_time += time_x2 - time_x1
      tot_time = acc_time * 1000 / (iterations)
      print(f'    {tot_time:.3f} ms')
      acc_time = 0



#generate_keys()
benchmark()

