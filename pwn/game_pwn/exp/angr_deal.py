import angr
from angr import *
#from simuvex.procedures.stubs.UserHook import UserHook

binary_path = "./tmp_file.bin"

stack_addr = 0


def get_mem(state, addr, size):
	mem = state.memory.load(addr, size)
	#print mem
	return state.se.eval(mem)

def gen_cond(state, index):
	"""Returns a symbolic BitVector and contrains it to printable chars for a given state."""
	bitvec = state.se.BVS('c%d'%index, 8, explicit_name=True)
	return bitvec, state.se.And(bitvec >= 0x0, bitvec <= 0xff)


def read_file(filename, mode = "rb"):
	file_r = open(filename, mode)
	data = file_r.read()
	file_r.close()
	return data

def write_file(filename, data, mode = "wb"):
	file_w = open(filename, mode)
	file_w.write(data)
	file_w.close()

def run_angr():

	#proj = angr.Project(binary_path,  load_options={'auto_load_libs': False})
	proj = angr.Project(binary_path)#,  load_options={'auto_load_libs': False})
	
	
	data = read_file("angr_deal.conf")
	if len(data) > 0:
		items = data.split('\n')
		start_addr = int(items[0], 16)
		success = (int(items[1], 16), )
		fail = (int(items[2], 16), )

		print (start_addr)
		print (success)
		print (fail)

		print hex(start_addr)
		print hex(success[0])
		print hex(fail[0])

	else:
		start_addr = 0x400B57
		success = (0x400C45, )
		fail = (0x400C6C, )

		#"""
	initial_state = proj.factory.blank_state(addr = start_addr)

	r_edi = initial_state.se.BVS('edi', 32)
	initial_state.regs.edi = r_edi

	pg = proj.factory.simgr(initial_state, immutable=False)
	pg.explore(find=success, avoid=fail)
	found_state = pg.found[0]
	result = found_state.se.eval(r_edi)
	print hex(result)
	write_file("passcode.conf", "%d"%result)
	exit(0)

run_angr()