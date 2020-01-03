---
title: HITCON-train
date: 2019-07-11 10:48:30
tags: 
- CTF
- pwn
categories: CTF
mathjax: true
---

## lab1

先看看保护机制

![1562811133517](1562811133517.png)

打开了部分可读，而就是可以进行溢出覆盖，打开了栈溢出保护，而且NX打开，不可执行，地址随机化没有打开



现在可以用ida打开看看文件，是32位的，所以就可以直接在ida.exe里面打开

找到mian函数，反编译以下：

![1562813207401](1562813207401.png)

看到关键函数`get_flag()`:

```c
v67 = __readgsdword(0x14u);
  v54 = 'y_oD';
  v55 = 'k_uo';
  v56 = '_won';
  v57 = '_yhw';
  v58 = 't_ym';
  v59 = 'mmae';
  v60 = '_eta';
  v61 = 'narO';
  v62 = 'i_eg';
  v63 = 'os_s';
  v64 = 'gna_';
  v65 = '??yr';
  v66 = '?';
  v5 = 7;
  v6 = 59;
  v7 = 25;
  v8 = 2;
  v9 = 11;
  v10 = 16;
  v11 = 61;
  v12 = 30;
  v13 = 9;
  v14 = 8;
  v15 = 18;
  v16 = 45;
  v17 = 40;
  v18 = 89;
  v19 = 10;
  v20 = 0;
  v21 = 30;
  v22 = 22;
  v23 = 0;
  v24 = 4;
  v25 = 85;
  v26 = 22;
  v27 = 8;
  v28 = 31;
  v29 = 7;
  v30 = 1;
  v31 = 9;
  v32 = 0;
  v33 = 126;
  v34 = 28;
  v35 = 62;
  v36 = 10;
  v37 = 30;
  v38 = 11;
  v39 = 107;
  v40 = 4;
  v41 = 66;
  v42 = 60;
  v43 = 44;
  v44 = 91;
  v45 = 49;
  v46 = 85;
  v47 = 2;
  v48 = 30;
  v49 = 33;
  v50 = 16;
  v51 = 76;
  v52 = 30;
  v53 = 66;
  fd = open("/dev/urandom", 0);
  read(fd, &buf, 4u);
  printf("Give me maigc :");
  __isoc99_scanf("%d", &v2);
  if ( buf == v2 )
  {
    for ( i = 0; i <= 0x30; ++i )
      putchar((char)(*(&v5 + i) ^ *((_BYTE *)&v54 + i)));
  }
  return __readgsdword(0x14u) ^ v67;
}
```

根据这个可以直接进行逆向：

```python
#-*-encoding=utf-8-*-
K = "Do_you_know_why_my_teammate_Orange_is_so_angry???"
C = [7, 59, 25, 2, 11, 16, 61, 30, 9, 8, 18, 45, 40, 89, 10, 0, 30, 22, 0, 4, 85, 22, 8, 31, 7, 1, 9, 0, 126, 28, 62, 10, 30, 11, 107, 4, 66, 60, 44, 91, 49, 85, 2, 30, 33, 16, 76, 30, 66]
print("sizeof(C):",len(C))
print("sizeof(K):",len(K))
for i in range(len(K)):
    print(chr(C[i]^ord(K[i])),end="")
```



## lab2

