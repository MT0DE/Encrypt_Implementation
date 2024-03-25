import os
import time
import timeit
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

TEXT = "It's over, I have the high ground"

def generate_keys():
    pr_key = rsa.generate_private_key(65537, 2048) # Key size could also be tested for 4096
    pr_pem = pr_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
   
    pu_key = pr_key.public_key()
    pu_pem = pu_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)

    with open("private_key.pem", "wb") as key_file:
        key_file.write(pr_pem)
        print('Private key generated')

    with open("public_key.pem", "wb") as key_file:
        key_file.write(pu_pem)
        print('Public key generated')

def load_pr_key():
    pr_pem = open("private_key.pem", "rb").read()
    pr_key = serialization.load_pem_private_key(pr_pem, None)
    return pr_key


def load_pu_key():
    pu_pem = open("public_key.pem", "rb").read()
    pu_key = serialization.load_pem_private_key(pu_pem, None)
    return pu_key

generate_keys()


# priv_k = load_pr_key
# pr_pem = pr_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

# print(pr_key)   
# print(load_pu_key)