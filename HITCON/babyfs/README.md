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

First, we have to know how program manage each file stream and its data.
In binary, it uses next structure to manage file stream, structures are global variable so it allocated in .bss section.
And sadly, there is PIE in binary so maybe we cant use this metadata in exploit without PIE leak XD

```c
struct __attribute__((aligned(8))) simpleFs
{
  char *streamPtr;
  char *fileData;
  char fileName[64];
  __int64 fileLen;
  __int32 isWrite;
  __int32 padding;
};
```
