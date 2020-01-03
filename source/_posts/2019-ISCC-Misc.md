---
title: 2019_ISCC
date: 2019-05-19 01:42:21
tags: 
- ISCC
- CTF
categories: CTF
---

### 隐藏的信息

打开文件是一堆八进制码

```txt
0126 062 0126 0163 0142 0103 0102 0153 0142 062 065 0154 0111 0121 0157 0113 0111 0105 0132 0163 0131 0127 0143 066 0111 0105 0154 0124 0121 060 0116 067 0124 0152 0102 0146 0115 0107 065 0154 0130 062 0116 0150 0142 0154 071 0172 0144 0104 0102 0167 0130 063 0153 0167 0144 0130 060 0113 
```

直接用python转成十进制，然后变为ASCII字符,脚本如下：

```python
import re
#open
with open('message.txt', 'r') as f1:
    s1 = f1.read()
    s1 = re.split(' ',s1)
    for i in s1[0:-1]:
        print(chr(int(i,8)),end='')
    f1.close()
#V2VsbCBkb25lIQoKIEZsYWc6IElTQ0N7TjBfMG5lX2Nhbl9zdDBwX3kwdX0K
#base64解码：ISCC{N0_0ne_can_st0p_y0u}
```



### Welcome

下载得到一个名为zip的文件，不可打开，看看文件类型

![1558066372410](1558066372410.png)

是一个压缩包文件，然后可以解压出50张二维码，发现一个jpg为其他都是png，查看文件二进制信息即可得到flag

```python
#flag{15cC9012}   提交格式应该是 15cC9012
```



### 碎纸机

下载得到一个压缩包文件，可以直接解压，得到一个图片

![碎纸机](平平无奇的碎纸机.jpg)

真的是一个碎纸机，先看看文件类型

![1558197131121](1558197131121.png)

用`binwalk`查看一下是否图片里藏有其他文件：

![1558197231431](1558197231431.png)

用`binwalk -e 平平无奇的碎纸机.jpg`分离出文件，得到一些拼图和一个文档

![1558197306018](1558197306018.png)

再看看文本里的内容：

> 碎纸机中居然是一堆黑色和白色的碎片，但是这些碎片之中到底会有什么样的宝藏呢？
> 我去问了欧鹏·曦文同学，他说他有办法恢复拼图原貌，但是前提是要我把真正有用的东西给他。

看起来是需要我们去里面得到相应的信息，可以需要拼图，对二进制进行操作，用`winhex`打开

![1558197932052](1558197932052.png)



现在就看有没有什么规律啥的，翻到最后，发现一个乱码是独立的而且就是由0和F组成，所以将其复制出来，在vscode中打开，然后查找0，可以得到

![1558198553243](1558198553243.png)

![1558200582298](1558200582298.png)

其他几个文件也是类似，这里就不做赘述，所以flag为：`Flag={ISCC_is_so_interesting_!}`



### 解密成绩单

`ISCC{Y0u_F0UnD_ThE_P4SSW0RD!}`



### REV02

`flag{ST0RING_STAT1C_PA55WORDS_1N_FIL3S_1S_N0T_S3CUR3}`



### REV03

`FLAG{I_LOVE_FONZY}`



### Web5

`flag{1SCC_2OI9}`



### Mobile

`1234567836275184`



### pwn02

`flag{2c9c6bd8-c285-43b7-ac8a-f74eb9a7cb2f}`



### pwn01

`flag{f530c5ef-3a8a-4271-91f7-3c5ebd87fbe4}`



### rev4

`http://ISCC2019{url_seems_rotten_with}ctf.com`


