#!/usr/bin/env python3
import string
import sys

def encrypt(text, key):
    keylen = len(key)
    keyPos = 0
    encrypted = ""
    for x in text:
        keyChr = key[keyPos]
        newChr = ord(x)
        newChr = chr((newChr + ord(keyChr)) % 255)
        encrypted += newChr
        keyPos += 1
        keyPos = keyPos % keylen
    return encrypted

with open('out.txt', 'r', encoding='UTF-8') as f:
    out_data = f.read()

with open('check.txt', 'r', encoding='UTF-8') as f:
    in_data = f.read()

passwd = ''
for out_c, in_c in zip(out_data, in_data):
    for passwd_c in string.printable:
        newChr = ord(in_c)
        newChr = chr((newChr + ord(passwd_c)) % 255)
        if (newChr == out_c):
            passwd += passwd_c
            break
    sys.stdout.write('\033[2K\033[1G')
    print(passwd)
