from pwn import *
from gmpy2 import *
from Crypto.Util.number import *
from mt import untemper
import libnum, decimal

r = remote("crypto.chal.ctf.westerns.tokyo", 5643)
#r = process(["python", "mixed.py"])

def encrypt(plain):
	r.sendline("1")
	print r.recvuntil("text: ")
	r.sendline(plain)
	print r.recvuntil("RSA: ")
	rsa = int(r.recvuntil("\n")[:-1], 16)
	print r.recvuntil("AES: ")
	aes = r.recvuntil("\n")[:-1]
	print r.recvuntil("key")
	return (rsa, aes)

def oracle(cip):
	r.sendline("2")
	print r.recvuntil("cipher text: ")
	r.sendline(cip)
	print r.recvuntil("RSA: ")
	rv = r.recvuntil("\n")[:-1]
	print r.recvuntil("key")
	return int(rv[-2:], 16)

def enckey():
	r.sendline("4")
	print r.recvuntil(":)\n")
#	print r.recvuntil("key: ")
#	print r.recvuntil("\n")
	rv = r.recvuntil("\n")[:-1]
	print r.recvuntil("key")
	return int(rv, 16)

def partial(c, n):
	k = n.bit_length()
	decimal.getcontext().prec = k
	lower = decimal.Decimal(0)
	upper = decimal.Decimal(n)
	print "Shit"
	for i in range(0, k-1):
		possible_plaintext = (lower + upper)/2
		ora = oracle(hex(c)[2:].zfill(256))
		print "ora: " + hex(ora&1)
		if not (ora & 1):
			upper = possible_plaintext
		else:
			lower = possible_plaintext
		c = (c * c_of_2) % n
		if i % 100 == 0:
			print "sex " + str(i)
	print "lower: " + hex(int(lower))
	print "upper: " + hex(int(upper))
	raw_input("$")

	return int(lower)

print r.recvuntil("key")

values = []
for i in range(0, 624/4):
	rs, a = encrypt("a")
	a = a[:32].decode("hex")
	a = bytes_to_long(a)
	for j in range(4):
		values.append(a & (2**32-1))
		a = a>>32

mt_state = tuple(map(untemper, values)+[0])
random.setstate((3, mt_state, None))

for i in range(624):
	random.getrandbits(32)
random.getrandbits(128)
random.getrandbits(128)
random.getrandbits(128)

iv = random.getrandbits(128)

raw_input("$")

key = int(enckey())

rsa1 = encrypt("\x02")
rsa2 = encrypt("\x03")
rsa3 = encrypt("\x04")

fuck = pow(2, 65537)-rsa1[0]
fuck2 = pow(3, 65537)-rsa2[0]
fuck3 = pow(4, 65537)-rsa3[0]

n = gcd(fuck, fuck2)
n = gcd(n, fuck3)
n = int(n)

e = 65537

print "n: " + hex(n)
print "key: " + hex(key)
print hex(key)
print hex(oracle(hex(key)[2:]))

raw_input("$")
c_of_2 = pow(2, e, n)

print "key: " + str(key)

fuck = partial(key*c_of_2%n, n)

for i in range(fuck, fuck+10):
	if pow(i, e, n) == key:
		print "find!"
		key = i

print "key: " + hex(key)
print "iv: " + hex(iv)

r.interactive()
