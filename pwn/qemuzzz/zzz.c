#include "qemu/osdep.h"
#include "hw/pci/pci.h"
#include "hw/pci/msi.h"
#include "qemu/timer.h"
#include "qemu/main-loop.h" 
#include "qapi/visitor.h"

#define DMA_SIZE 0x1000

typedef struct {
    void * obj;
    void (* dma_rw)(hwaddr addr, void *buf,
                            hwaddr len, bool is_write);
} zzzDMA;

typedef struct {
    PCIDevice pdev;
    MemoryRegion mmio;
    dma_addr_t addr;
    uint16_t cnt;
    uint16_t idx;
    uint32_t reserved;
    uint8_t dma_buf[DMA_SIZE];
    zzzDMA dma_op;
} zzzState;


static void dev_dma_op(void *opaque)
{
    zzzDMA * dma_obj = (zzzDMA *)opaque;
    zzzState * obj = (zzzState *)dma_obj->obj;
    
    uint16_t cnt = obj->cnt & ~0x8001;
    bool is_write = obj->cnt & 1;
    
    if (obj->addr & 0xfff)
    {
        return ;
    }
    
    if ( obj->idx + cnt - 1 > DMA_SIZE )
    {
        return ;
    }

    if ( is_write )
    {
        dma_obj->dma_rw(obj->addr,obj->dma_buf + obj->idx,cnt,1);
    }
    else
    {
        dma_obj->dma_rw(obj->addr,obj->dma_buf + obj->idx,cnt,0);
    }
     
    if ( obj->cnt & 0x8000 ) { 
        pci_set_irq(&obj->pdev, 1);
    }
}

static uint64_t zzz_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    zzzState *obj = opaque;

    if (addr >= DMA_SIZE )
        return 0;
    
    return obj->dma_buf[addr];
}


static void xor_crypt( zzzState * obj)
{
    int i = obj->idx;
    int cnt = obj->cnt & ~0x8001;
    if ( cnt + i >= DMA_SIZE )
        cnt = DMA_SIZE - i - 1;
    
    for ( ; i < cnt/2 ; i +=2 )
    {
        *(uint16_t *)(obj->dma_buf+i) ^= 521 ;
    }
}

static void zzz_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    zzzState *obj = opaque;

    switch (addr) {
    case 0x10:
        if ( val < DMA_SIZE )
            obj->idx = val;
        if (obj->idx >= DMA_SIZE)
            obj->idx = 0;
        break;
    
    case 0x18:
        obj->cnt = val ;
        break;
    
    case 0x20:
        obj->addr = val << 12;
        break;
        
    case 0x50:
        xor_crypt(obj);
        break;

    case 0x60:
        dev_dma_op(&obj->dma_op);
        break;
        
    default:
        break;
    }
}

static const MemoryRegionOps zzz_mmio_ops = {
    .read = zzz_mmio_read,
    .write = zzz_mmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void pci_zzz_realize(PCIDevice *pdev, Error **errp)
{
    zzzState *obj = DO_UPCAST(zzzState, pdev, pdev);
    uint8_t *pci_conf = pdev->config;
    pci_config_set_interrupt_pin(pci_conf, 1);
    
    memory_region_init_io(&obj->mmio, OBJECT(obj), &zzz_mmio_ops, obj, "zzz-mmio",0x100000);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &obj->mmio);
}

static void zzz_instance_init(Object *opaque)
{
    zzzState *obj = OBJECT_CHECK(zzzState, opaque, "zzz");
    obj->dma_op.obj = obj;
    obj->dma_op.dma_rw = cpu_physical_memory_rw;
}

static void pci_zzz_uninit(PCIDevice *dev)
{
}

static void zzz_class_init(ObjectClass *class, void *data)
{
    PCIDeviceClass *k = PCI_DEVICE_CLASS(class);

    k->realize = pci_zzz_realize;
    k->exit = pci_zzz_uninit;
    k->vendor_id = PCI_VENDOR_ID_QEMU;
    k->device_id = 0x2333;
    k->revision = 0x10;
    k->class_id = PCI_CLASS_OTHERS;
}

static void pci_zzz_register_types(void)
{  
    static InterfaceInfo interfaces[] = {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    };
    
    static const TypeInfo zzz_info = {
        .name          = "zzz",
        .parent        = TYPE_PCI_DEVICE,
        .instance_size = sizeof(zzzState),
        .instance_init = zzz_instance_init,
        .class_init    = zzz_class_init,
        .interfaces = interfaces,
    };

    type_register_static(&zzz_info);
}

type_init(pci_zzz_register_types)