#!/usr/bin/python

import random
import signal
import sys

def terminate(msg):
	print msg
	exit(-1)

def load_firmware(firm_name):
	data = open(firm_name, 'rb').read()
	firmware = [ord(byte) for byte in data]
	return firmware

def bit_concat(bit_list):
	res = 0
	for bit in bit_list:
		res <<= 7
		res += bit & 0b1111111
	return res

def read_memory_tri(firmware, addr, count):
	if not count:
		return []

	res = []
	for i in range(count):
		tri = 0
		tri |= firmware[addr + i*3]
		tri |= firmware[addr + i*3 + 1] << 14
		tri |= firmware[addr + i*3 + 2] << 7
		res.append(tri)
	return res

def dispatch(firmware, pc):
	opcode = bit_concat(firmware[pc:pc+2])
	op = (opcode & 0b11111000000000) >> 9
	op_type = (opcode & 0b00000100000000) >> 8
	opers = []
	
	if op_type == 0: # Register, TYPE_R
		opers.append((opcode & 0b11110000) >> 4)
		opers.append((opcode & 0b00001111))
		op_size = 2

	elif op_type == 1: # I, TYPE_I
		opers.append((opcode & 0b11110000) >> 4)
		opers.append((read_memory_tri(firmware, pc+2, 1)[0]))
		op_size = 5
	else:
		print "[VM] Invalid!"

	return op, op_type, opers, op_size

def op_x0(op_type, opers):
	if op_type == 0:
		print "mov " + reg_list[opers[0]] + ", [" + reg_list[opers[1]] + "]"
	else:
		terminate("[VM] Invalid instruction - op0")

def op_x1(op_type, opers):
	if op_type == 0:
		print "movb " + reg_list[opers[0]] + ", [" + reg_list[opers[1]] + "]"
	else:
		terminate("[VM] Invalid instruction - op1")

def op_x2(op_type, opers):
	if op_type == 0:
		print "mov [" + reg_list[opers[0]] + "], " + reg_list[opers[1]]
	else:
		terminate("[VM] Invalid instruction - op2")

def op_x3(op_type, opers):
	if op_type == 0:
		print "movb [" + reg_list[opers[0]] + "], " + reg_list[opers[1]]
	else:
		terminate("[VM] Invalid instruction - op3")

def op_x4(op_type, opers):
	if op_type == 0:
		print "mov " + reg_list[opers[0]] + ", " + reg_list[opers[1]]
	elif op_type == 1:
		print "mov " + reg_list[opers[0]] + ", " + hex(opers[1])
	else:
		terminate("[VM] Invalid instruction - op4")

def op_x5(op_type, opers):
	if op_type == 0:
		print "xchg " + reg_list[opers[0]] + ", " + reg_list[opers[1]]
	else:
		terminate("[VM] Invalid instruction - op5")

def op_x6(op_type, opers):
	if op_type == 0:
		print "push " + reg_list[opers[0]]
	elif op_type == 1:
		print "push " + hex(opers[0])
	else:
		terminate("[VM] Invalid Instruction - op6")

def op_x7(op_type, opers):
	if op_type == 0:
		print "pop " + reg_list[opers[0]]
	else:
		terminate("[VM] Invalid instruction - op7")

def op_x8(op_type, opers):
	print "syscall"

def op_x9(op_type, opers):
	if op_type == 0:
		print "add " + reg_list[opers[0]] + ", " + reg_list[opers[1]]
	elif op_type == 1:
		print "add " + reg_list[opers[0]] + ", " + hex(opers[1])
	else:
		terminate("[VM] Invalid instruction - op9")

def op_x10(op_type, opers):
	if op_type == 0:
		print "addb " + reg_list[opers[0]] + ", " + reg_list[opers[1]]
	elif op_type == 1:
		print "addb " + reg_list[opers[0]] + ", " + hex(opers[1])
	else:
		terminate("[VM] Invalid instruction - op10")

def op_x11(op_type, opers):
	if op_type == 0:
		print "sub " + reg_list[opers[0]] + ", " + reg_list[opers[1]]
	elif op_type == 1:
		print "sub " + reg_list[opers[0]] + ", " + hex(opers[1])
	else:
		terminate("[VM] Invalid instruction - op11")

def op_x12(op_type, opers):
	if op_type == 0:
		print "subb " + reg_list[opers[0]] + ", " + reg_list[opers[1]]
	elif op_type == 1:
		print "subb " + reg_list[opers[0]] + ", " + hex(opers[1])
	else:
		terminate("[VM] Invalid instruction - op12")

def op_x13(op_type, opers):
	if op_type == 0:
		print "shr " + reg_list[opers[0]] + ", " + reg_list[opers[1]]
	elif op_type == 1:
		print "shr " + reg_list[opers[0]] + ", " + hex(opers[1])
	else:
		terminate("[VM] Invalid instruction - op13")

def op_x14(op_type, opers):
	if op_type == 0:
		print "shl " + reg_list[opers[0]] + ", " + reg_list[opers[1]]
	elif op_type == 1:
		print "shl " + reg_list[opers[0]] + ", " + hex(opers[1])
	else:
		terminate("[VM] Invalid instruction - op14")

def op_x15(op_type, opers):
	if op_type == 0:
		print "mul " + reg_list[opers[0]] + ", " + reg_list[opers[1]]
	elif op_type == 1:
		print "mul " + reg_list[opers[0]] + ", " + hex(opers[1])
	else:
		terminate("[VM] Invalid instruction - op15")

def op_x16(op_type, opers):
	if op_type == 0:
		print "div " + reg_list[opers[0]] + ", " + reg_list[opers[1]]
	elif op_type == 1:
		print "div " + reg_list[opers[0]] + ", " + hex(opers[1])
	else:
		terminate("[VM] Invalid instruction - op16")

def op_x17(op_type, opers):
	if op_type == 0:
		print "inc " + reg_list[opers[0]]
	else:
		terminate("[VM] Invalid instruction - op17")

def op_x18(op_type, opers):
	if op_type == 0:
		print "dec " + reg_list[opers[0]]
	else:
		terminate("[VM] Invalid instruction - op18")

def op_x19(op_type, opers):
	if op_type == 0:
		print "and " + reg_list[opers[0]] + ", " + reg_list[opers[1]]
	elif op_type == 1:
		print "and " + reg_list[opers[0]] + ", " + hex(opers[1])
	else:
		terminate("[VM] Invalid instruction - op19")

def op_x20(op_type, opers):
	if op_type == 0:
		print "or " + reg_list[opers[0]] + ", " + reg_list[opers[1]]
	elif op_type == 1:
		print "or " + reg_list[opers[0]] + ", " + hex(opers[1])
	else:
		terminate("[VM] Invalid instruction - op20")

def op_x21(op_type, opers):
	if op_type == 0:
		print "xor " + reg_list[opers[0]] + ", " + reg_list[opers[1]]
	elif op_type == 1:
		print "xor " + reg_list[opers[0]] + ", " + hex(opers[1])
	else:
		terminate("[VM] Invalid instruction - op21")

def op_x22(op_type, opers):
	if op_type == 0:
		print "mod " + reg_list[opers[0]] + ", " + reg_list[opers[1]]
	elif op_type == 1:
		print "mod " + reg_list[opers[0]] + ", " + hex(opers[1])
	else:
		terminate("[VM] Invalid instruction - op22")

def op_x23(op_type, opers):
	if op_type == 0:
		print "cmp " + reg_list[opers[0]] + ", " + reg_list[opers[1]]
	elif op_type == 1:
		print "cmp " + reg_list[opers[0]] + ", " + hex(opers[1])
	else:
		terminate("[VM] Invalid instruction - op23")

def op_x24(op_type, opers):
	if op_type == 0:
		print "cmpb " + reg_list[opers[0]] + ", " + reg_list[opers[1]]
	elif op_type == 1:
		print "cmpb " + reg_list[opers[0]] + ", " + hex(opers[1])
	else:
		terminate("[VM] Invalid instruction - op24")

def op_x25(op_type, opers):
	if op_type == 0:
		print "!N!Zjmp (" + reg_list[opers[0]] + "+" + reg_list[opers[1]] + ")"
	elif op_type == 1:
		print "!N!Zjmp (" + reg_list[opers[0]] + "+" + hex(opers[1]) + ")"
	else:
		terminate("[VM] Invalid instruction - op25")

def op_x26(op_type, opers):
	if op_type == 0:
		print "N!Zjmp (" + reg_list[opers[0]] + "+" + reg_list[opers[1]] + ")"
	elif op_type == 1:
		print "N!Zjmp (" + reg_list[opers[0]] + "+" + hex(opers[1]) + ")"
	else:
		terminate("[VM] Invalid instruction - op25")

def op_x27(op_type, opers):
	if op_type == 0:
		print "jz (" + reg_list[opers[0]] + "+" + reg_list[opers[1]] + ")"
	elif op_type == 1:
		print "jz (" + reg_list[opers[0]] + "+" + hex(opers[1]) + ")"
	else:
		terminate("[VM] Invalid instruction - op27")

def op_x28(op_type, opers):
	if op_type == 0:
		print "jnz (" + reg_list[opers[0]] + "+" + reg_list[opers[1]] + ")"
	elif op_type == 1:
		print "jnz (" + reg_list[opers[0]] + "+" + hex(opers[1]) + ")"
	else:
		terminate("[VM] Invalid instruction - op28")

def op_x29(op_type, opers):
	if op_type == 0:
		print "jmp (" + reg_list[opers[0]] + "+" + reg_list[opers[1]] + ")"
	elif op_type == 1:
		print "jmp (" + reg_list[opers[0]] + "+" + hex(opers[1]) + ")"
	else:
		terminate("[VM] Invalid instruction - op29")

def op_x30(op_type, opers):
	if op_type == 0:
		print "call (" + reg_list[opers[0]] + "+" + reg_list[opers[1]] + ")"
	elif op_type == 1:
		print "call (" + reg_list[opers[0]] + "+" + hex(opers[1]) + ")"
	else:
		terminate("[VM] Invalid instruction - op30")


def emulate(firmware, pc, op_handler_table):
	try:
		while True:
			op, op_type, opers, op_size = dispatch(firmware, pc)
			sys.stdout.write(hex(pc)[2:].zfill(8) + " ")
			op_handler = op_handler_table[op]
			op_handler(op_type, opers)
			pc += op_size
	except:
		print "[VM] Unknown error"
		exit(-1)

def hello(a, b):
	print "hello"

firmware = load_firmware("mic_check.firm")
pc = 0
reg_list = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "bp", "sp", "pc", "eflags", "zero"]

print len(firmware)

op_handler_table = [op_x0, op_x1, op_x2, op_x3, op_x4, op_x5,
			op_x6, op_x7, op_x8, op_x9, op_x10, op_x11,
			op_x12, op_x13, op_x14, op_x15, op_x16, op_x17,
			op_x18, op_x19, op_x20, op_x21, op_x22, op_x23,
			op_x24, op_x25, op_x26, op_x27, op_x28, op_x29, op_x30]

for i in range(31-len(op_handler_table)):
	op_handler_table.append(hello)

raw = read_memory_tri(firmware, 0xcd, 3) 
print raw

emulate(firmware, pc, op_handler_table)
