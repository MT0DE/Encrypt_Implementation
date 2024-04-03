import os
import sys
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

TEXT = "It's over, I have the high ground"

def generate_128bitkey():
   key = os.urandom(16)
   with open("secret.key", "wb") as key_file:
      key_file.write(key)
      print('key generated')

def load_key():
   return open("secret.key", "rb").read() 

def padds_message(message):
   padder = padding.PKCS7(128).padder()
   padded_data = padder.update(message.encode())
   padded_data += padder.finalize()
   return padded_data

def unpadds_message(message):
   unpadder = padding.PKCS7(128).unpadder()
   unpadded_data = unpadder.update(message)
   unpadded_data += unpadder.finalize()
   return unpadded_data

def encrypt_message(message, key):
   iv = os.urandom(16)
   cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

   padded_message = padds_message(message)
   # print("Padded message:", padded_message)
   # print()
   encryptor = cipher.encryptor()
   ct = encryptor.update(padded_message) + encryptor.finalize()
   # print("Cipher Text: ", ct)
   # print()
   return ct, iv

def decrypt_message(ct, iv, key):
   cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

   decryptor = cipher.decryptor()
   pt = decryptor.update(ct) + decryptor.finalize()
   # print("Plain text", pt)
   # print()

   decrypted_message = unpadds_message(pt)
   # print("Decrypted Message:", decrypted_message)
   # print()


def load_files_fifo():
   print("loading files into memory")
   # print(f"I am at {os.getcwd()}")
   curr_dir = os.getcwd()
   os.chdir('../plaintext_files/AES')
   # print(f"I am now at {os.getcwd()}")

   data_from_files = []
   for _, _, files in os.walk(os.getcwd()):
      # print(files)
      for filename in files:
         # print(filename)
         with open(os.path.join(os.curdir, filename), 'r') as df:
            data_from_files.append(df.read())
   os.chdir(curr_dir)
   return data_from_files

def benchmark():
   data = load_files_fifo()
   key = load_key()
   data.sort(key=sys.getsizeof, reverse=True)
   acc_time = 0
   iterations = 500
   text = ""
   print(f"Encrypting with AES128 {iterations} times")
   for _ in range(11):
      text = data.pop()
      size_of_text = sys.getsizeof(text)
      for x in range(iterations):
         print("\r" + f'   [{x+1}] filesize {size_of_text} bytes', end='')
         time_x1 = time.perf_counter()
         encrypt_message(text, key)
         time_x2 = time.perf_counter()
         acc_time += time_x2 - time_x1
      tot_time = acc_time * 1000 / (iterations)
      print(f'    {tot_time:.3f} ms')
      acc_time = 0

if os.access(os.path.join(os.curdir, "secret.key"), os.F_OK) is not True:
   print("generating new key...")
   generate_128bitkey()


# ct, iv = encrypt_message(TEXT)
# decrypt_message(ct, iv)
benchmark()
