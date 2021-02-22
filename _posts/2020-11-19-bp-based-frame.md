---
layout: post
title: IDA 解析區域變數 offset 錯誤
date: 2020-11-19
Author: LJP-TW
tags: [Reverse]
comments: true
excerpt_separator: <!--more-->
---

紀錄一下遇到的問題：IDA 解析區域變數 offset 錯誤

# 問題描述

以下附上截圖

首先可以看到呼叫 read 的第二個傳參 offset 為 rbp-0x30

![](/blog/images/post/2020-11-19-bp-based-frame/1.png)

但 decompiler 解析後卻是 rbp-0x38

![](/blog/images/post/2020-11-19-bp-based-frame/2.png)

# 解法

<!--more-->

在 function scope 中按下 `Alt` + `P` 編輯函數屬性

把 BP based frame 開起來

![](/blog/images/post/2020-11-19-bp-based-frame/3.png)

再 decompile 回去看看, 就正確了

![](/blog/images/post/2020-11-19-bp-based-frame/4.png)

看來是 IDA 預設以 sp 來推算區域變數, 遇到是以 bp 來推算的函數就出了問題

# Reference

* [Is there a way to adjust local variables when a function doesn't utilize ebp?](https://reverseengineering.stackexchange.com/questions/4213/is-there-a-way-to-adjust-local-variables-when-a-function-doesnt-utilize-ebp)

