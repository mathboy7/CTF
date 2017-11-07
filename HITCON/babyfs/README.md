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

First we have to know how program manage each file stream and its data.
In binary, it uses structure 1 to manage file stream and it allocated in .bss section (its global variable!).
And sadly, there is PIE in binary so we cant use this metadata in exploit without PIE leak XD

```c
// Structure 1
struct __attribute__((aligned(8))) simpleFs
{
  char *streamPtr;
  char *fileData;
  char fileName[64];
  unsigned __int64 fileLen;
  __int32 isWrite;
  __int32 padding;
};
```

We can open maximum 3 files at the same time in open menu. Function get file name at .bss section (global variable structure)and try to open file. If file name invalid, function opens error log file and write file name which we try to open. After open the file successfully get file length using fseek() and allocate data buffer (size fileLen+1) for read file.

#### Read
In read menu, program take index we opened from user. If index is invalid then get size to read. After comparing size with filesize call fread() to read data from file. Data is stored at **char \*fileData**.

#### Write
Take index and progress validation check same as read menu. We can write file data only one time because it sets write flag when write menu called. Menu returns "It have been writed !" strings if structure's isWrite flag != 0. If isWrite flag unsetted, function writes only one byte of file data to stdout stream.

#### Close
If index and streamPtr is not NULL, it frees **char \*fileData** and nullify other region without **char \*streamPtr**. **char \*streamPtr** nullified after fclose(streamPtr) called.

### Vulnerability

So where does the vulnerability occurs? It occurs at open menu. The size will return -1 and stored at **fileLen** if we give "/dev/fd/0" or "/dev/stdin" for file name, but buffer allocates size+1 so it will normally allocate heap buffer by malloc(0). **unsigned __int64 fileLen** is **unsigned int**, so heap overflow will occur if we give size bigger than 0x20 in read menu.

### Exploit
