# Initial

[*] '/root/projects/tmp/r0bob1rd'
Arch: amd64-64-little
RELRO: Partial RELRO
Stack: Canary found
NX: NX enabled
PIE: No PIE (0x400000)
RUNPATH: b'./glibc/'
Stripped: No

=> possible return to binary

# Test Input

if I enter `Select a R0bob1rd > zhe0ops`, I got a segmentfault

if I enter the long description:

```
Enter bird's little description
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Crafting..
   \\
   (*>
\\_//)
 \_/_)
  _|_
[Description]
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA*** stack smashing detected ***: terminated
zsh: IOT instruction  ./r0bob1rd
```

# reveng

According to the ghidra, the operation() has a bug to read abitrary data:

```
  if ((local_7c < 0) || (9 < local_7c)) {
    printf("\nYou\'ve chosen: %s",robobirdNames + (long)local_7c * 8);
  }
  else {
    printf("\nYou\'ve chosen: %s",*(undefined8 *)(robobirdNames + (long)local_7c * 8));
  }
```

In operation():

- there is a 2-byte overflow by fgets()
- and an unprotected printf string: printf(local_78).
  - The local_78 is our input. So we can leak some info or write some bytes by printf, just like Space-pirate-Entrypoint challenge.

Q: how to trigger system()?
A: I assume we have to ret2libc. We either
   - Use the `printRobobirds()` to find out the libc base and then use the `printf()` to overwrite the return address and redirect to the system(), or
   - Use the printf() and make a loop so we can keep triggering the FSB.

TODO: libc, FSB, __stack_chk_fail() instead.
