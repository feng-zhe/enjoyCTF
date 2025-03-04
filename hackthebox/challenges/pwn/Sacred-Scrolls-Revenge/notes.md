Tips: not cmdi, but ret2lib

TODO: Do it again. Learned a lot from the write-ups. Unfortunately, the challenge seems to have some updates now and it always rejects the `/` in base64. This always fails the payload.

pwn checksec =>
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'./glibc/'
    Stripped:   No


Following code issues:

1. In main(), "read(0,input_buff,0x5ff)" will overwrite 7 bytes.
2. The for loop allows us to overwrite 25 bytes to 0. We can partially control the step.
3. spell_save() do "memcpy(local_28,param_1,600)" but the local_28 only has 28 bytes.
