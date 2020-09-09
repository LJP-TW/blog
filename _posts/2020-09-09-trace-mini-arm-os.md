---
layout: post
title: 學習 Jserv mini-arm-os 筆記
date: 2020-09-09
Author: LJP-TW
tags: [OS, Arm]
comments: true
toc: true
---

# Intro
這是一份學習 [Jserv](https://github.com/jserv) [mini-arm-os](https://github.com/jserv/mini-arm-os) 的筆記, 簡單來說, 他將在 `stm32-p103` 開發板上實作 OS! 配合以下幾篇文章, 我想將 trace code 的過程紀錄下來

- [stm32-prog.pdf](http://wiki.csie.ncku.edu.tw/embedded/Lab19/stm32-prog.pdf)
    - Jserv 寫的教材, 可以先配這個看 00-HelloWorld 入門
- [STM32-P103.pdf](https://www.olimex.com/Products/ARM/ST/STM32-P103/resources/STM32-P103.pdf)
    - `stm32-p103` 的開發手冊, 比較重要的資訊就是他用的 CPU
        - CPU: STM32F103RBT6 ARM 32 bit CORTEX M3
- [stm32f103xx manual](https://www.st.com/resource/en/reference_manual/cd00171190-stm32f101xx-stm32f102xx-stm32f103xx-stm32f105xx-and-stm32f107xx-advanced-arm-based-32-bit-mcus-stmicroelectronics.pdf)
    - 開發板上的 CPU 開發手冊, 主要會一直來查這邊

# 00-HelloWorld
## Makefile
```
CROSS_COMPILE ?= arm-none-eabi-
CC := $(CROSS_COMPILE)gcc
CFLAGS = -fno-common -O0 \
     -mcpu=cortex-m3 -mthumb \
     -T hello.ld -nostartfiles \

TARGET = hello.bin
all: $(TARGET)

$(TARGET): hello.c startup.c
    $(CC) $(CFLAGS) $^ -o hello.elf
    $(CROSS_COMPILE)objcopy -Obinary hello.elf hello.bin
    $(CROSS_COMPILE)objdump -S hello.elf > hello.list

qemu: $(TARGET)
    @qemu-system-arm -M ? | grep stm32-p103 >/dev/null || exit
    @echo "Press Ctrl-A and then X to exit QEMU"
    @echo
    qemu-system-arm -M stm32-p103 -nographic -kernel hello.bin

clean:
    rm -f *.o *.bin *.elf *.list
```
* ?= 是什麼

    ?= 的意思為若使用 make 指令沒有指定變數的值

    (單純只 make, 而不是 make CROSS_COMPILE=blablabla)

    則此變數預設使用此值 (arm-none-eabi-)
* 編譯參數 CFLAGS
    * -fno-common
        手冊是這樣寫的
        > The `-fno-common` option specifies that the compiler should instead place uninitialized global variables in the BSS section of the object file.
        >
 
        目前無法體會為何要加這個參數
    * -mcpu=cortex-m3 -mthumb

        指定 CPU, 且 cortex-m3 只能執行 thumb mode, 所以也要加 -mthumb

        這個就需要爬 cortex-m3 的 manual 了, 這邊先直接給結論而不找為什麼了
    * -T hello.ld

        使用 `hello.ld` 作為 linker script, 這怎寫可以爬 [stm32-prog.pdf](http://wiki.csie.ncku.edu.tw/embedded/Lab19/stm32-prog.pdf)

        給我的感覺就是能自訂產出的咚咚怎麼配置, 能做出非 elf 格式的咚咚
    * -nostartfiles

        正常的 elf, main 其實不是第一個執行的函數, 而是有其他的函數先準備好一些事情後, 才呼叫 main, 加了 -nostartfiles 後, 就是直接 main 了

## hello.ld
```
ENTRY(reset_handler)

MEMORY
{
    FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 128K
}

SECTIONS
{
    .text :
    {
        KEEP(*(.isr_vector))
        *(.text)
    } >FLASH
}
```
* 大部分可以看 [stm32-prog.pdf](http://wiki.csie.ncku.edu.tw/embedded/Lab19/stm32-prog.pdf) 來學習
* 在整份 bin 的 offset 0 開始, 是 isr_vector
* 開機時
    * offset 0 會作為 MSP (Main Stack Pointer)
    * offset 4 會作為 PC (Program Counter)
    * 這邊先偷看 .isr_vector 是什麼
        ```c
        __attribute((section(".isr_vector")))
        uint32_t *isr_vectors[] = {
            0,
            (uint32_t *) reset_handler, /* code entry point */
        };
        ```
    * 所以能知道 MSP 會為 0, PC 會是 reset_handler
* ENTRY
    * 設定其為進入點, 不過按照以上的理解, 有加這行跟沒加應該一樣, 不影響執行
    * 實際實驗後 (將這行 /\*\*/ comment 掉), 的確也不影響執行

## startup.c
```c
#include <stdint.h>

extern void main(void);
void reset_handler(void)
{
    /* jump to C entry point */
    main();
}

__attribute((section(".isr_vector")))
uint32_t *isr_vectors[] = {
    0,
    (uint32_t *) reset_handler, /* code entry point */
};
```
* 照上一 part 理解, PC 變成 reset_handler 後, 就執行 main() 了

## hello.c
```c
#include <stdint.h>
#include "reg.h"

#define USART_FLAG_TXE  ((uint16_t) 0x0080)

int puts(const char *str)
{
    while (*str) {
        while (!(*(USART2_SR) & USART_FLAG_TXE));
        *(USART2_DR) = *str++ & 0xFF;
    }
    return 0;
}

void main(void)
{
    *(RCC_APB2ENR) |= (uint32_t) (0x00000001 | 0x00000004);
    *(RCC_APB1ENR) |= (uint32_t) (0x00020000);

    /* USART2 Configuration */
    *(GPIOA_CRL) = 0x00004B00;
    *(GPIOA_CRH) = 0x44444444;

    *(USART2_CR1) = 0x0000000C;
    *(USART2_CR1) |= 0x2000;

    puts("Hello World!\n");

    while (1);
}
```
* 這邊要先理解 reg.h 在寫什麼, 可以先跳到下一 part 看再回來
    * 理解後會發現, code 裡面用到的 `RCC_xxx` `GPIOA_xxx` 之類的其實就是一個記憶體位址
    * 要理解會發生什麼事情, 就要翻 [stm32f103xx manual](https://www.st.com/resource/en/reference_manual/cd00171190-stm32f101xx-stm32f102xx-stm32f103xx-stm32f105xx-and-stm32f107xx-advanced-arm-based-32-bit-mcus-stmicroelectronics.pdf), 以下 bit 代表什麼都要翻手冊
* `*(RCC_APB2ENR) |= (uint32_t) (0x00000001 | 0x00000004);`
    * `AFIOEN`
        啟用 alternate function IO 時鐘
    * `IOPAEN`
        啟用 GPIOA 時鐘
* `*(RCC_APB1ENR) |= (uint32_t) (0x00020000);`
    * `USART2EN`
        啟用 USART2 時鐘
* `*(GPIOA_CRL) = 0x00004B00;`
    * `CNF3`: 0b01
    * `CNF2`: 0b10
    * `MODE2`: 0b11
    * > 另外還需要注意的是，要像前面的例子設 IO 口輸入輸出模式那樣，設定序列通訊線對應管腳的工作模
      > 式。如下面的原理圖所示，Tx 腳復用 GPIOA 的 9 腳，Rx 腳復用 GPIOA 的 10 腳。我們必須像設定
      > GPIO 口輸入輸出模式那樣，設定Tx和Rx腳的工作模式。需要注意的是，Rx 腳為輸入模式，與 GPIO
      > 口設定的可選模式相同，而對Tx腳這樣的輸出管腳，需要設定專門的工作模式(Alternate function
      > output Push­pull 或 Alternate function output Open­ drain)，而不能設定為 General purpose output 模
      > 式。對序列通訊輸出而言，需要選擇 Alternate function output Push­pull，據此可確定 GPIOA_CRH 暫
      > 存器的值。
      > 
        參考自 [stm32-prog.pdf](http://wiki.csie.ncku.edu.tw/embedded/Lab19/stm32-prog.pdf)
    * 從 [STM32-P103.pdf](https://www.olimex.com/Products/ARM/ST/STM32-P103/resources/STM32-P103.pdf) 電路圖可以看到, PA2 和 PA3 跟 USART2_TX/RX 是重疊的, 而 PA9 和 PA10 跟 USART1_TX/RX 是重疊的
    * 本例子是想使用 USART2, 故我們要設定 PA2 (TX) 是輸出模式, PA3 (RX) 是輸入模式
    * 設 Port 3 為 Input Mode, reset state
    * 設 Port 2 為 Output Mode (max speed 50 MHz), Alternate function output Push-pull
* `*(GPIOA_CRH) = 0x44444444;`
    * 保留 Reset value, 反正我們主要只要有設定好 PA2 和 PA3 就好
* `*(USART2_CR1) = 0x0000000C;`
    * `TE`
    * `RE`
    * 啟用 USART2 收發功能
* `*(USART2_CR1) |= 0x2000;`
    * `UE`
        啟用 USART2
* puts 分析
    * `USART_SR` 的 `TXE` 位為 1 才繼續寫字
        `TXE` 為 1 表示資料成功傳送至 shift register
    * `USART_DR`\[8:0] 存著要傳送的資料
* 至此 00-HelloWorld 分析結束!

## reg.h
```c
#ifndef __REG_H_
#define __REG_H_

#define __REG_TYPE  volatile uint32_t
#define __REG       __REG_TYPE *

/* RCC Memory Map */
#define RCC     ((__REG_TYPE) 0x40021000)
#define RCC_APB2ENR ((__REG) (RCC + 0x18))
#define RCC_APB1ENR ((__REG) (RCC + 0x1C))

/* GPIO Memory Map */
#define GPIOA       ((__REG_TYPE) 0x40010800)
#define GPIOA_CRL   ((__REG) (GPIOA + 0x00))
#define GPIOA_CRH   ((__REG) (GPIOA + 0x04))

/* USART2 Memory Map */
#define USART2      ((__REG_TYPE) 0x40004400)
#define USART2_SR   ((__REG) (USART2 + 0x00))
#define USART2_DR   ((__REG) (USART2 + 0x04))
#define USART2_CR1  ((__REG) (USART2 + 0x0C))

#endif
```
* `#define __REG_TYPE   volatile uint32_t`
    * 因其加上 volatile, 表示其是易揮發、易變動的, 加上 volatile 能保證就算 compiler 在進行優化時, 對此變數能還是會再取值一次, 減少出 bug 的機會
* `#define RCC      ((__REG_TYPE) 0x40021000)`
    * 為啥是 0x40021000 勒, 這個就要翻翻 [STM32-P103.pdf](https://www.olimex.com/Products/ARM/ST/STM32-P103/resources/STM32-P103.pdf), 可以在 Memory Map 中找到, RCC 位置為 0x40021000 ~ 0x40021400
    * 阿 RCC (Reset & Clock Control) 有什麼用, 就要翻翻 [stm32f103xx manual](https://www.st.com/resource/en/reference_manual/cd00171190-stm32f101xx-stm32f102xx-stm32f103xx-stm32f105xx-and-stm32f107xx-advanced-arm-based-32-bit-mcus-stmicroelectronics.pdf) (7.3 章 RCC Registers)
    * 顧名思義, 大概就跟設定時鐘之類的有關
* `#define RCC_APB2ENR  ((__REG) (RCC + 0x18))`
    * 直接在手冊搜尋 `RCC_APB2ENR`, 來到了 7.3.7 章, 能夠看到 address 就是在 RCC 的 +0x18
    * `RCC_APB1ENR` 類推
* `#define GPIOA        ((__REG_TYPE) 0x40010800)`
    * 從 [STM32-P103.pdf](https://www.olimex.com/Products/ARM/ST/STM32-P103/resources/STM32-P103.pdf) 找到第 5 頁的圖 (STM32F103xx performance line block diagram)
        * 可以看到有 GPIOA ~ E, 對應著 PA~E\[15:0]
        * 背後連到 APB2 (Advanced Peripheral Bus)
        * 經過 APB2/AHB2 橋後, 進到 AHB (Advanced High-performance Bus), 再跟內部主要元件連接
    * 再從第 4 頁硬體線路圖可以看到 PA\[15:0] 每個腳位用來幹嘛
    * 並在 Memory Map 找到 PortA 對應到記憶體 0x40010800 ~ 0x40010c00
* `#define GPIOA_CRL    ((__REG) (GPIOA + 0x00))`
    * 在 [stm32f103xx manual](https://www.st.com/resource/en/reference_manual/cd00171190-stm32f101xx-stm32f102xx-stm32f103xx-stm32f105xx-and-stm32f107xx-advanced-arm-based-32-bit-mcus-stmicroelectronics.pdf) 搜尋 `GPIOx_CRL` 就能找到他是幹嘛的, `GPIOx_CRH` 也是
* 小總結就是, CPU 手冊定義了 Registers 的 offset xx 代表什麼含意, 但沒有定義 Registers 一定要 mapping 到 memory 的特定地方, 這部分就是廠商定義, 所以看 Registers Memory Map 要查廠商手冊, 查 Registers 用來幹嘛要找 CPU 手冊
