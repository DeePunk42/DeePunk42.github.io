---
title: PWN从入门到出入平安（零）——工具篇
date: 2023-04-20 11:17:17
tags: 
- CTF
- PWN
categories: 
- CS
---

> 有些人喜欢摸鱼，摸上瘾了，就什么都不记得了

#### 连接&分析命令

`nc` ：脑残的缩写

`file` `checksec` ：检查文件

#### ROP工具

###### 查找可存储寄存器的代码（rop表示二进制文件名）

```shell
$ ROPgadget --binary rop --only 'pop|ret' | grep 'eax'
```

###### 查找字符串

```shell
$ ROPgadget --binary rop --string "/bin/sh"
```

###### 查找有int 0x80的地址

```shell
$ ROPgadget --binary rop --only 'int'
```

###### 生成rop链

``` shell
$ ROPgadget --binary rop --ropchain
```

###### 用法

```shell
usage: ROPgadget.py [-h] [-v] [-c] [--binary <binary>] [--opcode <opcodes>]
                    [--string <string>] [--memstr <string>] [--depth <nbyte>]
                    [--only <key>] [--filter <key>] [--range <start-end>]
                    [--badbytes <byte>] [--rawArch <arch>] [--rawMode <mode>]
                    [--rawEndian <endian>] [--re <re>] [--offset <hexaddr>]
                    [--ropchain] [--thumb] [--console] [--norop] [--nojop]
                    [--callPreceded] [--nosys] [--multibr] [--all] [--noinstr]
                    [--dump]

    -h, --help           显示帮助文档
    -v, --version        版本号
    -c, --checkUpdate    检测新版本是否可用
    --binary <binary>    指定二进制文件进行分析
    --opcode <opcodes>   在可执行段中查找opcode
    --string <string>    在可读的段中查找字符串
    --memstr <string>    查找单个byte在所有的可执行段中
    --depth <nbyte>      搜索引擎的深度
    --only <key>         只显示特别的指令
    --filter <key>       过滤特定指令
    --range <start-end>  在地址之间寻找(0x...-0x...)
    --badbytes <byte>    拒绝特定指令在gadget的地址下
    --rawArch <arch>     指定文件架构
    --rawMode <mode>     指定源文件的mode
    --rawEndian <endian> 指定源文件的endianness
    --re <re>            正则表达式
    --offset <hexaddr>   指定gadget的地址偏移
    --ropchain           ROP chain的生成
    --thumb              在ARM架构下使用搜索引擎thumb 模式
    --console            使用交互终端对于搜索引擎
    --norop              禁止ROP搜索引擎
    --nojop              禁止JOP搜索引擎
    --callPreceded       仅显示call-preceded的gadgets
    --nosys              禁止SYS搜索引擎
    --multibr            允许多分枝gadgets
    --all                禁止删除重复的gadgets，即显示所有
    --noinstr            禁止gadget指令终端打印
    --dump               输出gadget bytes
```

#### One_gadget



#### 静态分析工具

`strace` : trace all system call

`ltrace` : trace all library call

#### lib查找工具

###### LibSearcher

``` python
from LibcSearcher import *
 
#第二个参数，为已泄露的实际地址,或最后12位(比如：d90)，int类型
obj = LibcSearcher("fgets", 0X7ff39014bd90)
 
obj.dump("system")        #system 偏移
obj.dump("str_bin_sh")    #/bin/sh 偏移
obj.dump("__libc_start_main_ret") 
 
# sys_addr = libc_base + obj.dump("system")
```

###### 在线查找

https://libc.rip/



#### Payload编写

``` python
<snippet>
	<content><![CDATA[
#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import*

context(os = 'linux', arch = 'amd64', log_level = 'debug', terminal = ['tmux', 'new-window'])
def debug(cmd=''):
	cmd += "b main\n"
	gdb.attach(p, cmd)
	pause()

host = ""
port = 0
p = process("./")
#p = remote(host, port)

pt.interactive()
]]></content>
	<!-- Optional: Set a tabTrigger to define how to trigger the snippet -->
	<tabTrigger>pwn</tabTrigger>
	<!-- Optional: Set a scope to limit where the snippet will trigger -->
	<scope>source.shell.bash</scope> 
</snippet>

```

```python
send(payload) #发送payload
sendline(payload) #发送payload，并进行换行（末尾\n）
sendafter(some_string, payload) #接收到 some_string 后, 发送你的 payload
recvn(N) #接受 N(数字) 字符
recvline() #接收一行输出
recvlines(N) #接收 N(数字) 行输出
recvuntil(some_string) #接收到 some_string 为止
```

``` python
base = int(p.recvn(12),16) #接受十六进制数
p64()
p32()

context.arch = "i386"#amd64
context(arch='amd64', os='linux', log_level = 'DEBUG')
flat([0x114514,0x191980,...])
p32(0x114514)+p32(0x191980)+...
#需设置好架构
```

```
elf = ELF('./pwn')
libc = ELF('./libc-2.27.so')

elf.symbols['_start']
libc.symbols['__libc_start_main']5
```



#### Pwntools

`cyclic 114`生成

`cyclic -l laaa`检索(检索出数字为填到ret之前的数字)

#### gdb使用

- 启动：`start`
- 断点：
  - `b *0x114514`
  - `b 符号名`
  - `d`删除，带数字第几个断点
- 单步
  - 步入`si`
  - 步过`so`
  - 源码\汇编单步`n`
  - 直到下一个断点`c`
- 查看内存
  - `x/20gx 0x114514`
    - g：8byte，w：4byte，b：1byte
    - 寄存器：`$esp`
  - `hexdump 0x114514` 可查看内存及字符串
  - `dsp` 自动解引用
- 查看段的地址 范围
  - `vmmap`
- 查找地址
  - `printf system` 查找函数地址
  - `find 0xf7df4d90,+2200000,"/bin/sh"` 起始地址+搜索长度+字符串
- info
  - `info breakpoint`
  - `info register`
- elf
- plt
- fmtarg
- arch使用pwndbgheap
  - https://gist.github.com/nbulischeck/bda4397a59b77822703f98f6aeb2cb20
- disassemble

.gdbinit

```sh
source /home/deepunk/Public/pwndbg/gdbinit.py
source /home/deepunk/Public/Pwngdb/pwngdb.py
source /home/deepunk/Public/Pwngdb/angelheap/gdbinit.py
source /home/deepunk/Public/splitmind/gdbinit.py

define hook-run
python
import angelheap
angelheap.init_angelheap()
end
end

set context-clear-screen on
set follow-fork-mode parent

python
import splitmind
(splitmind.Mind()
.tell_splitter(show_titles=False)
.left(display="regs", size="40%")
.below(display="disasm", size="40%")
.above(of="main", display="stack", size="45%")
.right(display="backtrace", size="25%")
.below(cmd="cmatrix", size="40%")
.right(of="main", cmd="ipython", size="32%")
.show("legend", on="stack")
).build(nobanner=True)
end

set context-stack-lines 7


```




#### peda

`pattc xx`

`crashoff`

#### IDA使用

###### 快捷键：

`U`：取消已有数据类型定义

`D`：变数据，1(byte/db),2(word/dw),3(dword/dd),4(qword/dq)

`C`：变指令

`A`：ASCII码，该位置起点，\0结尾字符串

`*`：数组

`O`：地址偏移

`Y`：改为正确类型

`H`：16进制

`M`：转为枚举中的值

`_`：按补码解析为负数

`~`：按位取反

###### COLOR

黑色：代码

灰色：数据

黄色：未定义

#### patchelf&glibc-all-in-one

##### 安装

```shell
sudo apt-get install patchelf
git clone https://github.com/matrix1001/glibc-all-in-one
```

##### 更新

```shell
./update_list
```

##### 下载库

```shell
cat list
./download xxx
```

##### 查看libc同版本连接器

```shell
strings xxx.so | grep ubuntu
```

##### 查看libc

```shell
ldd -v pwn
```

##### 修改

```shell
patchelf --set-interpreter 你的文件目录/ld-linux-x86-64.so.2 ./pwn
patchelf --add-needed 你的文件目录/libc.so.6 ./pwn
```



#### sha256爆破脚本

```python
import hashlib
import itertools
from string import digits, ascii_letters, punctuation
alpha_bet=digits+ascii_letters+punctuation
strlist = itertools.product(alpha_bet, repeat=4)

sha256="a645e3deef85766e43c8a1aa63d1f69eed55e7cb94f10973bd76a9ace57c7311"
tail="amLSvne0g1ypVG5J"

xxxx=''

for i in strlist:
    data=i[0]+i[1]+i[2]+i[3]
    data_sha=hashlib.sha256((data+str(tail,encoding='utf-8')).encode('utf-8')).hexdigest()
    if(data_sha==str(sha256,encoding='utf-8')):
        xxxx=data
        break

print(xxxx)
```

```python
import hashlib

for num in range(10000,9999999999):
    res = hashlib.sha1(str(num).encode()).hexdigest() #sha1改为题目需要的算法
    if res[0:5] == "903ed":   #对hash的前五位为"903ed"的数字进行碰撞
        print(str(num)) #等待执行结束 输出结果
        break
```

#### tricks

if .plt adress endup with null byte

adress+=6(32bit)
