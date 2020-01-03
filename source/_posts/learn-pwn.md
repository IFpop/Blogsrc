---
title: learn_pwn
date: 2019-10-16 12:57:40
tags:
- pwn
- learn
categories: 
- CTF
mathjax: true
---

# Checksec

> 这是`pwntools`附带的一个工具，检测elf运行于哪个平台，开启了什么安全措施，如果用gcc的编译后，默认会开启所有的安全措施

```bash
Arch:     amd64-64-little                                                             	 RELRO:    Full RELRO                                                                     Stack:    No canary found                                                                 NX:       NX enabled                                                                     PIE:      No PIE (0x400000)
```

+ `RELRO`

  > `RELRO`会有`Partial RELRO`和`FULL RELRO`，如果开启`FULL RELRO`，意味着我们无法修改got表

+ `Stack`

  > 如果栈中开启`Canary found`，那么就不能用直接用溢出的方法覆盖栈中返回地址，而且要通过改写指针与局部变量、`leak canary`、`overwrite canary`的方法来绕过

+ `NX`

  > `NX enabled`如果这个保护开启就是意味着栈中数据没有执行权限，以前的经常用的`call esp`或者`jmp esp`的方法就不能使用，但是可以利用`rop`这种方法绕过

+ `PIE`

  > `PIE enabled`如果程序开启这个地址随机化选项就意味着程序每次运行的时候地址都会变化，而如果没有开`PIE`的话那么`No PIE (0x400000)`，括号内的数据就是程序的基地址 

+ `FORTIFY`

  > `FORTIFY_SOURCE`机制对格式化字符串有两个限制
  >
  > (1)包含%n的格式化字符串不能位于程序内存中的可写地址。
  >
  > (2)当使用位置参数时，必须使用范围内的所有参数。所以如果要使用%7$x，你必须同时使用1,2,3,4,5和6。

+ 