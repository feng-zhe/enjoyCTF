from pwn import *
import sys

HOST = 'chall.pwnable.tw'
PORT = 10100

def exploit(p):
    pass

if __name__=='__main__':
    if len(sys.argv)==1:        # local
        p = process(['./calc'])
    elif sys.argv[1]=='remote':
        p = remote(HOST, PORT)
    pause()
    exploit(p)
