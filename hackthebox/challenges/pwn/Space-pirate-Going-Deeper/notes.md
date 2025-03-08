TL;DR: one-byte overwrite of the return address

ghidra => The key can be found easily. We need to overwrite the params to pass the check.
There is a bof in admin_panel.

via gdb debugging:

- buffer 0x00007fffffffdc20
- 0xdeadbeef 0x7fffffffdc18
- 0x1337c0de 0x7fffffffdc10
- 0x1337beef 0x7fffffffdc08

Looks like these are above the buffer we can overflow. So we cannot change their value for now.

before calling admin_panel,
- the return address is 0x0000000000400b94
- return address is on stack 0x00007fffffffdc58
- the buffer is 0x00007fffffffdc20
- diff 0x38
- buffer size 0x39
=> we can overwrite one byte of the return address.

pwn cyclic 57 => aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaao
=> overwrite the return address to 0x0000000000400b6f
=> confirmed, we can overwrite the lowest byte of the return address

The binary doesn't enable PIE, so its own loading address is fixed.
=> maybe we can change the return address directly to the code reading the flag.
=> the system() call is at 0x0000000000400b19, (but we need to jump to 0x0000000000400b12 which prepares the params to it
=> this looks feasible.

