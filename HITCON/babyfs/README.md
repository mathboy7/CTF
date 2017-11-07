babyfs - Pwn 315 (Solver 13)
-------------
### Description
Baby or not baby is up to you.
nc 52.198.183.186 50216
(link to binary and libc)

### Overview
babyfs is a x86-64 ELF(NX, SSP, PIE, Full RELRO) binary implementing a simple file stream open/read/write/close functions.
It's a CTF-style menu challenge, easy to reversing, hard to exploit.

### Reversing
Okay, so lets check out how each functions are working.

#### Open
