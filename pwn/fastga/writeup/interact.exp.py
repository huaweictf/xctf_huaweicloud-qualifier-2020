from pwn import *

local=0
aslr=True
pc = ""
context.log_level="debug"
context.terminal = ["deepin-terminal","-x","sh","-c"]

libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

if local==1:
    #p = process(pc,aslr=aslr,env={'LD_PRELOAD': './libc.so.6'})
    p = process(pc,aslr=aslr)
    gdb.attach(p)
else:
    remote_addr=['127.0.0.1', 10006]
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

def proof():
    ru("hashlib.sha256(skr).hexdigest()=")
    aim_hex = rl().strip()
    ru("[+]skr[0:5].encode('hex')=")
    skr = rl().strip().decode("hex")
    ru("[-]skr.encode('hex')=")
    for a in range(0, 0x100):
        for b in range(0, 0x100):
            for c in range(0, 0x100):
                tmp = skr + chr(a) + chr(b) + chr(c)
                if hashlib.sha256(tmp).hexdigest() == aim_hex:
                    sl(tmp.encode("hex"))
                    return

if __name__ == '__main__':
    proof()
    context.log_level="info"
    p.interactive()

