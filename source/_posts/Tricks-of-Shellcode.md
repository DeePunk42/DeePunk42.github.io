---
title: Tricks of Shellcode
date: 2023-08-29 21:56:08
tags:
  - PWN
categories:
  - CS
---

> 最近打了挺多比赛，碰到一些比较有意思的题和方法

shellcode的题挺多，往往都是加了一些乱七八糟的限制。一般要么限制字符，要么开沙箱。限制字符基本上就通过手搓~~我不会~~或者alpha3之类的工具实现，这里讲一些绕过沙箱的办法。

# 切换架构

题目不仅禁止getshell，甚至限制了orw，如果沙箱没有对系统架构进行检查，就可以使用切换架构的方式。

原理是沙箱通过检测系统调用号判断是否放行，而64位和32位架构下的系统调用号又不相同，切换到另一种架构，就能实现绕过黑名单检查

这种手法听起来很炫酷，操作却相当简单

程序运行时的架构，是由`cs`寄存器控制的。`cs=0x23`为32位模式，`cs=0x33`为64位模式。而`retfq`指令就能实现对`cs`的赋值

`retfq`包含`ret`和`pop cs`两步，也就是先后pop `rip`和`cs`，所以一般可以像这样写：

```assembly
mov rsp, 0x40404040 #arbitrary stack
push 0x23 #or 0x33
push 0x401145 #next shellcode
retfq
```

注意这里需要设置`rsp`，这是因为切换到32位时，寄存器也会被切成32位，所以需要预先调整栈顶的指针

另外我在操作时发现`ret`后的地址似乎有一定要求。起初我直接跳到下一条shellcode上，但会在retfq时崩溃，后来我`ret`到代码段里调用shellcode的地址，再提前设置好寄存器，顺利解决了这个问题

# 者行孙

~~你就说是不是一个东西吧~~

没有open的可以用openat代替

没有read的可以用pread64/writev代替

[read, pread64, readv, preadv, preadv2系统调用](https://evian-zhang.github.io/introduction-to-linux-x86_64-syscall/src/filesystem/read-pread64-readv-preadv-preadv2.html)

这么玩就没意思了

# 使用socket

有空看看

[EX大佬的博客](http://blog.eonew.cn/2019-06-03.%E5%8F%8D%E5%90%91shellcode.html)

# 盲注

挺有趣的做法，找时间再详细研究下

[m1ku大佬的博客](https://m1ku.in/archives/737)

