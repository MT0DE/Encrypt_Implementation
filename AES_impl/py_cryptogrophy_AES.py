import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

TEXT = "It's over, I have the high ground"

def generate_key():
   key = os.urandom(32)
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

def encrypt_message(message):
   key = load_key()
   iv = os.urandom(16)
   cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

   padded_message = padds_message(message)
   print("Padded message:", padded_message)
   print()
   encryptor = cipher.encryptor()
   ct = encryptor.update(padded_message) + encryptor.finalize()
   print("Cipher Text: ", ct)
   print()
   return ct, iv

def decrypt_message(ct, iv):
   key = load_key()
   cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

   decryptor = cipher.decryptor()
   pt = decryptor.update(ct) + decryptor.finalize()
   print("Plain text", pt)
   print()

   decrypted_message = unpadds_message(pt)
   print("Decrypted Message:", decrypted_message)
   print()

ct, iv = encrypt_message(TEXT)
decrypt_message(ct, iv)
