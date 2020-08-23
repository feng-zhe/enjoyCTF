#!/usr/bin/env python3
import sys
import hashlib

password_file = sys.argv[1]
salt = sys.argv[2]
hash_value = sys.argv[3]

def CalcSha1(password, salt):
    hash_object = hashlib.sha1((password + salt).encode())
    return hash_object.hexdigest()

passwords = []
with open(password_file, 'r') as f:
    for cnt, password in enumerate(f):
        password = password.strip() # important!
        print("[*] Trying", password)
        if CalcSha1(password, salt) == hash_value:
            print("[+] Found password:", password)
            break
