---
layout: post
title: Seabios 筆記
date: 2020-05-18
Author: LJP-TW
tags: [BIOS]
comments: true
toc: true
excerpt_separator: <!--more-->
---
# Intro
分析 [seabios](https://github.com/qemu/seabios) 的實作

將持續更新

# Trace
- reset_vector
    - 位於 0xfffffff0，機器上電後的進入點
    - 直接跳到 entry_post
- entry_post
    - 跳到 handle_post()
- handle_post()
    - POST (Power On Self Test)
- dopost()
- reloc_preinit(maininit(), NULL)
    - 將位於 0xf0000 的 BIOS code relocate 到其他地方，並且執行
- maininit()
    - interface_init()
        - 初始化各種東西，包含 IVT、BDA、Device hardware

# Interrupt Vector Table
在 interface_init() 中呼叫到 ivt_init() 進行 IVT 初始化

<!--more-->

```c
    // Initialize all vectors to the default handler.
    int i;
    for (i=0; i<256; i++)
        SET_IVT(i, FUNC16(entry_iret_official));

    // Initialize all hw vectors to a default hw handler.
    for (i=BIOS_HWIRQ0_VECTOR; i<BIOS_HWIRQ0_VECTOR+8; i++)
        SET_IVT(i, FUNC16(entry_hwpic1));
    for (i=BIOS_HWIRQ8_VECTOR; i<BIOS_HWIRQ8_VECTOR+8; i++)
        SET_IVT(i, FUNC16(entry_hwpic2));

    // Initialize software handlers.
    SET_IVT(0x02, FUNC16(entry_02));
    SET_IVT(0x05, FUNC16(entry_05));
    SET_IVT(0x10, FUNC16(entry_10));
    SET_IVT(0x11, FUNC16(entry_11));
    SET_IVT(0x12, FUNC16(entry_12));
    SET_IVT(0x13, FUNC16(entry_13_official));
    SET_IVT(0x14, FUNC16(entry_14));
    SET_IVT(0x15, FUNC16(entry_15_official));
    SET_IVT(0x16, FUNC16(entry_16));
    SET_IVT(0x17, FUNC16(entry_17));
    SET_IVT(0x18, FUNC16(entry_18));
    SET_IVT(0x19, FUNC16(entry_19_official));
    SET_IVT(0x1a, FUNC16(entry_1a_official));
    SET_IVT(0x40, FUNC16(entry_40));

    // INT 60h-66h reserved for user interrupt
    for (i=0x60; i<=0x66; i++)
        SET_IVT(i, SEGOFF(0, 0));

    // set vector 0x79 to zero
    // this is used by 'gardian angel' protection system
    SET_IVT(0x79, SEGOFF(0, 0));
```

SET_IVT 兩個參數為 Interrupt 編號，以及其對應的 function address
```c
#define SET_IVT(vector, segoff)                                         \
    SET_FARVAR(SEG_IVT, ((struct rmode_IVT *)0)->ivec[vector], segoff)
```

SET_FARVAR 三個參數為 Segment、要設定的 Variable、要設定的 Value
SEG_IVT 為 0
```c
// Important real-mode segments
#define SEG_IVT      0x0000
```

struct rmode_IVT 長相為
```c
/****************************************************************
 * Interrupt vector table
 ****************************************************************/

struct rmode_IVT {
    struct segoff_s ivec[256];
};
```

```c
// Definition for common 16bit segment/offset pointers.
struct segoff_s {
    union {
        struct {
            u16 offset;
            u16 seg;
        };
        u32 segoff;
    };
};
```

GET_FARVAR 是 MAKE_FLATPTR 的 Wrapper，而 MAKE_FLATPTR 是將 Real mode 下的 Segment:Offset 轉換成 Address，就只是簡單的把 Segment 右移 4 bits 後加上 Offset
```c
// In 32-bit flat mode there is no need to mess with the segments.
#define GET_FARVAR(seg, var) \
    (*((typeof(&(var)))MAKE_FLATPTR((seg), &(var))))
#define SET_FARVAR(seg, var, val) \
    do { GET_FARVAR((seg), (var)) = (val); } while (0)
```

```c
// Macros for converting to/from 32bit flat mode pointers to their
// equivalent 16bit segment/offset values.
#define MAKE_FLATPTR(seg,off) ((void*)(((u32)(seg)<<4)+(u32)(off)))
```

而 FUNC16 定義請看 [General Macro](#general-macro)

ivt_init() 的技術總結就是
- IVT 位置從 Memory 0x00000000 開始，想成是一個 Array
- 每個 Element 為 4 Bytes，Index 表示 Interrupt 編號，Value 表示對應此 Interrupt 的 Function address

# INT 13
加減看一下 [wiki](https://en.wikipedia.org/wiki/INT_13H)

作用是讀寫 Disk

# Floppy
## 補充資料
1. https://0cch.com/2013/09/21/floppy-disk-controllere7bc96e7a88b/
2. https://wiki.qemu.org/images/f/f0/29047403.pdf
3. https://www.isdaman.com/alsos/hardware/fdc/floppy.htm
## Setup
### Function 路徑
- maininit()
- device_hardware_setup()
- block_setup()
- floppy_setup()

### floppy_setup()
```c
SET_IVT(0x1E, SEGOFF(SEG_BIOS
                         , (u32)&diskette_param_table2 - BUILD_BIOS_ADDR));
```
int 0x1E 根據 [wiki](https://zh.wikipedia.org/wiki/BIOS%E4%B8%AD%E6%96%B7%E5%91%BC%E5%8F%AB) 的描述:
> 不可呼叫：指向軟碟模式表（包含關於軟碟機的大量資訊）的指標。
> 

全域變數 diskette_param_table2 如下
```c
// New diskette parameter table adding 3 parameters from IBM
// Since no provisions are made for multiple drive types, most
// values in this table are ignored.  I set parameters for 1.44M
// floppy here
struct floppy_ext_dbt_s diskette_param_table2 VARFSEG = {
    .dbt = {
        .specify1       = FLOPPY_SPECIFY1,
        .specify2       = FLOPPY_SPECIFY2,
        .shutoff_ticks  = FLOPPY_MOTOR_TICKS, // ~2 seconds
        .bps_code       = FLOPPY_SIZE_CODE,
        .sectors        = 18,
        .interblock_len = FLOPPY_GAPLEN,
        .data_len       = FLOPPY_DATALEN,
        .gap_len        = FLOPPY_FORMAT_GAPLEN,
        .fill_byte      = FLOPPY_FILLBYTE,
        .settle_time    = 0x0F, // 15ms
        .startup_time   = FLOPPY_STARTUP_TIME,
    },
    .max_track      = 79,   // maximum track
    .data_rate      = 0,    // data transfer rate
    .drive_type     = 4,    // drive type in cmos
};
```

後半部假設 CONFIG_QEMU 不是 NULL，則會繼續執行:
```c
        u8 type = rtc_read(CMOS_FLOPPY_DRIVE_TYPE);
        if (type & 0xf0)
            addFloppy(0, type >> 4);
        if (type & 0x0f)
            addFloppy(1, type & 0x0f);
```

CMOS_FLOPPY_DRIVE_TYPE 定義 Floppy 在 CMOS 的編號:
```c
// QEMU cmos config fields.  DO NOT ADD MORE.  (All new content should
// be passed via the fw_cfg "file" interface.)
#define CMOS_FLOPPY_DRIVE_TYPE   0x10
```

[rtc_read 解釋在此](#rtc_readu8-index)

這一小部分的 code 可以參考 [補充資料1](https://0cch.com/2013/09/21/floppy-disk-controllere7bc96e7a88b/)
> 我们需要知道，到底PC上有没有软驱。要获得这个信息，我们需要读取CMOS，然后解析读取的信息即可。
> 
> 要从CMOS中获得软盘信息，我们需要先给对应的端口设置正确的索引，然后再去数据端口读取数据。具体做法是设置0x70端口为0x10，然后读取0x71端口。读取到的信息都放在一个字节中，需要把字节分为两个部分，高四位是驱动器A的类型索引号，低四位是驱动器B的类型索引号。索引号与软盘类型的对应关系如下图所示：
> 
![](https://0cch.com/uploads/2013/09/cmos_floppytype.png)

所以可以猜測 addFloppy 第一個參數是 drive 編號，第二個參數是從 CMOS 得到的 Type of drive

TBD.

### addFloppy(int floppyid, int ftype)
```c
static void
addFloppy(int floppyid, int ftype)
{
    struct drive_s *drive = init_floppy(floppyid, ftype);
    if (!drive)
        return;
    char *desc = znprintf(MAXDESCSIZE, "Floppy [drive %c]", 'A' + floppyid);
    struct pci_device *pci = pci_find_class(PCI_CLASS_BRIDGE_ISA); /* isa-to-pci bridge */
    int prio = bootprio_find_fdc_device(pci, PORT_FD_BASE, floppyid);
    boot_add_floppy(drive, desc, prio);
}
```

struct drive_s 請見[這裡](#drive_s)

init_floppy 建立 drive_s 的記憶體空間後初始化，詳情見下一小節

TBD.


### init_floppy
```c
struct drive_s *
init_floppy(int floppyid, int ftype)
{
    if (ftype <= 0 || ftype >= ARRAY_SIZE(FloppyInfo)) {
        dprintf(1, "Bad floppy type %d\n", ftype);
        return NULL;
    }

    struct drive_s *drive = malloc_fseg(sizeof(*drive));
    if (!drive) {
        warn_noalloc();
        return NULL;
    }
    memset(drive, 0, sizeof(*drive));
    drive->cntl_id = floppyid;
    drive->type = DTYPE_FLOPPY;
    drive->blksize = DISK_SECTOR_SIZE;
    drive->floppy_type = ftype;
    drive->sectors = (u64)-1;

    memcpy(&drive->lchs, &FloppyInfo[ftype].chs
           , sizeof(FloppyInfo[ftype].chs));
    return drive;
}
```

FloppyInfo 如下
```c
struct chs_s {
    u16 head;
    u16 cylinder;
    u16 sector;
    u16 pad;
};

struct floppyinfo_s {
    struct chs_s chs;
    u8 floppy_size;
    u8 data_rate;
};

struct floppyinfo_s FloppyInfo[] VARFSEG = {
    // Unknown
    { {0, 0, 0}, 0x00, 0x00},
    // 1 - 360KB, 5.25" - 2 heads, 40 tracks, 9 sectors
    { {2, 40, 9}, FLOPPY_SIZE_525, FLOPPY_RATE_300K},
    // 2 - 1.2MB, 5.25" - 2 heads, 80 tracks, 15 sectors
    { {2, 80, 15}, FLOPPY_SIZE_525, FLOPPY_RATE_500K},
    // 3 - 720KB, 3.5"  - 2 heads, 80 tracks, 9 sectors
    { {2, 80, 9}, FLOPPY_SIZE_350, FLOPPY_RATE_250K},
    // 4 - 1.44MB, 3.5" - 2 heads, 80 tracks, 18 sectors
    { {2, 80, 18}, FLOPPY_SIZE_350, FLOPPY_RATE_500K},
    // 5 - 2.88MB, 3.5" - 2 heads, 80 tracks, 36 sectors
    { {2, 80, 36}, FLOPPY_SIZE_350, FLOPPY_RATE_1M},
    // 6 - 160k, 5.25"  - 1 heads, 40 tracks, 8 sectors
    { {1, 40, 8}, FLOPPY_SIZE_525, FLOPPY_RATE_250K},
    // 7 - 180k, 5.25"  - 1 heads, 40 tracks, 9 sectors
    { {1, 40, 9}, FLOPPY_SIZE_525, FLOPPY_RATE_300K},
    // 8 - 320k, 5.25"  - 2 heads, 40 tracks, 8 sectors
    { {2, 40, 8}, FLOPPY_SIZE_525, FLOPPY_RATE_250K},
};
```

# General Struct
## drive_s
```c
struct drive_s {
    u8 type;            // Driver type (DTYPE_*)
    u8 floppy_type;     // Type of floppy (only for floppy drives).
    struct chs_s lchs;  // Logical CHS
    u64 sectors;        // Total sectors count
    u32 cntl_id;        // Unique id for a given driver type.
    u8 removable;       // Is media removable (currently unused)

    // Info for EDD calls
    u8 translation;     // type of translation
    u16 blksize;        // block size
    struct chs_s pchs;  // Physical CHS
};
```

# General Function
## rtc_read(u8 index)
```c
u8
rtc_read(u8 index)
{
    index |= NMI_DISABLE_BIT;
    outb(index, PORT_CMOS_INDEX);
    return inb(PORT_CMOS_DATA);
}
```

直接用 PIO 讀 CMOS 第 index 個資料，至於 CMOS 上第 i 個資料代表什麼則是另外一個故事。

```c
// PORT_CMOS_INDEX nmi disable bit
#define NMI_DISABLE_BIT 0x80
```

```c
#define PORT_CMOS_INDEX        0x0070
#define PORT_CMOS_DATA         0x0071
```

```c
static inline void outb(u8 value, u16 port) {
    __asm__ __volatile__("outb %b0, %w1" : : "a"(value), "Nd"(port));
}
```

```c
static inline u8 inb(u16 port) {
    u8 value;
    __asm__ __volatile__("inb %w1, %b0" : "=a"(value) : "Nd"(port));
    return value;
}
```


# General Macro
## FUNC16
```c
#define FUNC16(func) ({                                 \
        ASSERT32FLAT();                                 \
        extern void func (void);                        \
        SEGOFF(SEG_BIOS, (u32)func - BUILD_BIOS_ADDR);  \
    })
```
作用是將 func 換成 Segment:Offset 的形式，且 Segment 為 SEG_BIOS

ASSERT32FLAT 在不同參數下做不一樣的事情
```c
#if MODE16 == 1
# define ASSERT32FLAT() __force_link_error__only_in_32bit_flat()
#elif MODESEGMENT == 1
# define ASSERT32FLAT() __force_link_error__only_in_32bit_flat()
#else
# define ASSERT32FLAT() do { } while (0)
#endif
```

BIOS 的 Segment 為 0xf000，BIOS code 從 0xf0000 開始
```c
#define SEG_BIOS     0xf000
```

```c
#define BUILD_BIOS_ADDR           0xf0000
```

## SEGOFF
```c
#define SEGOFF(s,o) ({struct segoff_s __so; \
__so.offset=(o);\
__so.seg=(s);\
__so;})
```

```c
// Definition for common 16bit segment/offset pointers.
struct segoff_s {
    union {
        struct {
            u16 offset;
            u16 seg;
        };
        u32 segoff;
    };
};
```

## ARRAY_SIZE
```c
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
```

# 術語
- BDA: Bios Data Area
- CMOS: Complementary Metal-Oxide-Semiconductor
    - 硬體元件名稱
- INT: INTerrupt
- IVT: Interrupt Vector Table
- NMI: Non-Maskable Interrupt
    - 根據 [Wiki](https://zh.wikipedia.org/wiki/%E4%B8%AD%E6%96%B7)
        > 非可封鎖中斷（non-maskable interrupt，NMI）。硬體中斷的一類，無法通過在中斷封鎖暫存器中設定位遮罩來關閉。典型例子是時鐘中斷（一個硬體時鐘以恆定頻率—如50Hz—發出的中斷）。
        > 
- PIO: Programmed Input/Output
- RTC: Real-Time Clock
