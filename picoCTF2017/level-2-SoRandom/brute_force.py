#!/usr/bin/python -u
import random,string

def enc(plain_txt):
    random.seed("random")
    enc_txt = ""
    for c in plain_txt:
        if c.islower():
            enc_txt += chr((ord(c)-ord('a')+random.randrange(0,26))%26 + ord('a'))
        elif c.isupper():
            enc_txt += chr((ord(c)-ord('A')+random.randrange(0,26))%26 + ord('A'))
        elif c.isdigit():
            enc_txt += chr((ord(c)-ord('0')+random.randrange(0,10))%10 + ord('0'))
        else:
            enc_txt += c
    return enc_txt

flag = "FLAG:"
target = "BNZQ:3o8b2bgl0689u4aj640407963277k0fc"
for i in range(0,32):
    for j in range(1,256):
        if enc(flag+chr(j)) == target[:len(flag)+1]:
            flag += chr(j)
            break

print flag
