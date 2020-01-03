---
title: Jarvisoj-wp
mathjax: true
date: 2019-11-08 00:17:47
tags:
- Jarvisoj
categories:
- wp
- CTF
---

# Crypto

## Xgm

[RSA-集锦](<https://ifpop.github.io/2019/10/21/RSA-%E9%9B%86%E9%94%A6/#more>)

## xbk

[RSA-集锦](<https://ifpop.github.io/2019/10/21/RSA-%E9%9B%86%E9%94%A6/#more>)

## xyf

加密结构使用的是`Feistel结构`

加密过程如下：

```python
0,L,R
1,R,L^R^K1
2,L^R^K1,L^K1^K2
3,L^K1^K2,R^K2^K3
4,R^K2^K3,L^R^K1^K3^K4
5,L^R^K1^K3^K4,L^K1^K2^K4^K5
6,L^K1^K2^K4^K5,R^K2^K3^K5^K6
7,R^K2^K3^K5^K6,L^R^K1^K3^K4^K6^K7

```

那么逻辑就很清楚了

```python
test = "50543fc0bca1bb4f21300f0074990f846a8009febded0b2198324c1b31d2e2563c908dcabbc461f194e70527e03a807e9a478f9a56f7"
R_test^K2^K3^K5^K6     L_test^R_test^K1^K3^K4^K6^K7
R_flag^K2^K3^K5^K6     L_flag^R_flag^K1^K3^K4^K6^K7

```

然后解密脚本如下：

```python
#!/usr/bin/python
#coding=utf-8
#owner: IFpop
#time: 2019/10/29

#这里本来想着用python3实现这个过程，但是关于hex解码，在python3上貌似不能解码奇数，但可能是我代码写错了，希望解决了的大神可以告诉我怎么实现
test = '50543fc0bca1bb4f21300f0074990f846a8009febded0b2198324c1b31d2e2563c908dcabbc461f194e70527e03a807e9a478f9a56f7'
test_out = '66bbd551d9847c1a10755987b43f8b214ee9c6ec2949eef01321b0bc42cffce6bdbd604924e5cbd99b7c56cf461561186921087fa1e9'
flag_out = '44fc6f82bdd0dff9aca3e0e82cbb9d6683516524c245494b89c272a83d2b88452ec0bfa0a73ffb42e304fe3748896111b9bdf4171903'

L_tesd = test.decode('hex')[0:27]
R_test = test.decode('hex')[27:54]

L_Ktest = test_out.decode('hex')[0:27]
R_Ktest = test_out.decode('hex')[27:54]

def xor(a,b):
    assert len(a)==len(b)
    c=""
    for i in range(len(a)):
        c+=chr(ord(a[i])^ord(b[i]))
    return c

L_Kflag = flag_out.decode('hex')[0:27]
R_Kflag = flag_out.decode('hex')[27:54]

R_flag = xor(L_Kflag,xor(L_Ktest,R_test))
L_flag = xor(xor(xor(xor(L_tesd,R_test), R_Ktest),R_Kflag), R_flag)
print(L_flag+R_flag)
#flag{festel_weak_666_10fjid9vh12h3nvm}

```



## xcaesar

```python
def caesar_encrypt(m,k):
    r=""
    for i in m:
        r+=chr((ord(i)+k)%128)
    return r

from secret import m,k
print caesar_encrypt(m,k).encode("base64")
#output:bXNobgJyaHB6aHRwdGgE

```

程序很明显，先将明文进行凯撒加密，随后对其进行base64编码，所以脚本如下：

```python
#!/usr/bin/python
#coding=utf-8
#owner: IFpop
#time: 2019/10/29

import string
import base64
import sys

str = "bXNobgJyaHB6aHRwdGgE"
str = base64.b64decode(str)
print(str)
for i in range(26):
    ans = ""
    for c in str:
        if c >= 'A' and c <= 'Z':
            if c.isalpha():
                ans += chr((ord(c) + i-65)%26+65)
            else:
                ans += c
        else:
            if c.isalpha():
                ans += chr((ord(c) + i-97)%26+97)
            else:
                ans += c
    print(ans)
# flag{kaisamima}

```



## xbase64

```python
# /usr/bin/python
# encoding: utf-8
base64_table = ['=','A', 'B', 'C', 'D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                'a', 'b', 'c', 'd','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
                '0', '1', '2', '3','4','5','6','7','8','9',
                '+', '/'][::-1]

def encode_b64(s):
    l = len(s)
    i = 0
    result = ''
    while i < l:
        # 将字符转换为二进制编码，然后对齐
        s1 = s[i]
        b1 = bin(ord(s1))[2:]
        cb1 = b1.rjust(8, '0'
        i += 1
        if i >= l:
            cb2 = '00000000'
        else:
            s2 = s[i]
            b2 = bin(ord(s2))[2:]
            cb2 = b2.rjust(8, '0')
        i += 1
        if i >= l:
            cb3 = '00000000'
        else:
            s3 = s[i]
            b3 = bin(ord(s3))[2:]
            cb3 = b3.rjust(8, '0')
        # 将三字节转换为四字节
        cb = cb1 + cb2 + cb3
        rb1 = cb[:6]
        rb2 = cb[6:12]
        rb3 = cb[12:18]
        rb4 = cb[18:]
        # 转换后的编码转为十进制备用
        ri1 = int(rb1, 2)
        ri2 = int(rb2, 2)
        ri3 = int(rb3, 2)
        ri4 = int(rb4, 2)
        # 处理末尾为０的情况，以＇＝＇填充
        if i - 1 >= l and ri3 == 0:
            ri3 = -1
        if i >= l and ri4 == 0:
            ri4 = -1
        result += base64_table[ri1] + base64_table[ri2] + base64_table[ri3] + base64_table[ri4]
        i += 1
    return result
print encode_b64(open("flag","r").read())

#output: mZOemISXmpOTkKCHkp6Rgv==

```

乍一看，以为直接是，直接解码，发现是失败的，看看上面的base64_table，发现跟本来的不太一样，现在采取的策略是将原本的base64表与现在的base64表进行一个映射，然后就可以用base64进行解码了。脚本：

```python
#!/usr/bin/python
#coding=utf-8
#owner: IFpop
#time: 2019/10/29

import string
xbase64=['/', '+', '9', '8', '7', '6', '5', '4', '3', '2', '1', '0', 'z', 'y', 'x', 'w', 'v', 'u', 't', 's', 'r', 'q', 'p', 'o', 'n', 'm', 'l', 'k', 'j', 'i', 'h', 'g', 'f', 'e', 'd', 'c', 'b', 'a', 'Z', 'Y', 'X', 'W', 'V', 'U', 'T', 'S', 'R', 'Q', 'P', 'O', 'N', 'M', 'L', 'K', 'J', 'I', 'H', 'G', 'F', 'E', 'D', 'C', 'B', 'A', '=']
base64= ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', '=']

str='mZOemISXmpOTkKCHkp6Rgv=='
s=''
for i in str:
    s+=base64[xbase64.index(i)]
print(s)
# ZmxhZ3toZWxsb194bWFufQ==
print(s.decode('base64'))
# flag{hello_xman}

```



## Cry

[RSA-集锦](<https://ifpop.github.io/2019/10/21/RSA-%E9%9B%86%E9%94%A6/#more>)



## rsa





## rsappend

[RSA-集锦](<https://ifpop.github.io/2019/10/21/RSA-%E9%9B%86%E9%94%A6/#more>)



## bbencode

下载下来是一个python文件：

```python
flag = open("flag", "r").read().strip()
assert len(flag) == 32
def str2num(s):
    return int(s.encode('hex'), 16)
def bbencode(n):
    a = 0
    for i in bin(n)[2:]:
        a = a << 1
        if (int(i)):
            a = a ^ n
        if a >> 256:
            a = a ^ 0x10000000000000000000000000000000000000000000000000000000000000223L
    return a

print bbencode(str2num(flag))
#result:61406787709715709430385495960238216763226399960658358000016620560764164045692

```

这个加密先将flag转成二进制，然后根据每一位二进制数，对a进行操作，也就是一直对其循环加密就能得到`flag`(这里为什么我也没想明白)

```python
#coding=utf-8
#owner:IFpop
#time:2019/10/29

from Crypto.Util import number
def bbencode(n):
    a = 0
    for i in bin(n)[2:]:
        a = a << 1
        if (int(i)):
            a = a ^ n
        if a >> 256:
            a = a ^ 0x10000000000000000000000000000000000000000000000000000000000000223L
    return a

flag = 61406787709715709430385495960238216763226399960658358000016620560764164045692
for i in range(1000000):
    flag = bbencode(flag)
    #flag -- 66 6c 61 67
    if('666c6167' == str(hex(flag)[2:10])):
        print(i)
        print(number.long_to_bytes(flag))
        break
#flag{you_xian_yu_huan_le_duo_!!}

```



## Complicated Crypto

> 五层密码，好复杂![img](https://img.baidu.com/hi/jx2/j_0065.gif)

### CRC爆破

下载下来是一个被加密的压缩包：`Complicated Crypto.7z`

由于7z的压缩包是无视伪加密的，但有没有密码的相关信息，使用`winrar`打开可以看到有四个文件，其中有个名称叫做`CRC Collision`，所以现在尝试进行CRC爆破

可以直接使用脚本进行攻击，[6位爆破神器下载地址](<https://github.com/theonlypwner/crc32>):

```bash
python crc32.py reverse 0xA58A1926
#_CRC32
python crc32.py reverse 0x4DAD5967
#_i5_n0
python crc32.py reverse 0x4DAD5967
#t_s4f3

```

或者使用这个：

```python
 #crc32_util.py
 # -*- coding: utf-8 -*-
   
 import itertools
 import binascii
 import string
   
   
 class crc32_reverse_class(object):
     def __init__(self, crc32, length, tbl=string.printable,
                  poly=0xEDB88320, accum=0):
         self.char_set = set(map(ord, tbl))
         self.crc32 = crc32
         self.length = length
         self.poly = poly
         self.accum = accum
         self.table = []
         self.table_reverse = []
   
     def init_tables(self, poly, reverse=True):
         # build CRC32 table
         for i in range(256):
             for j in range(8):
                 if i & 1:
                     i >>= 1
                     i ^= poly
                 else:
                     i >>= 1
             self.table.append(i)
         assert len(self.table) == 256, "table is wrong size"
         # build reverse table
         if reverse:
             found_none = set()
             found_multiple = set()
             for i in range(256):
                 found = []
                 for j in range(256):
                     if self.table[j] >> 24 == i:
                         found.append(j)
                 self.table_reverse.append(tuple(found))
                 if not found:
                     found_none.add(i)
                 elif len(found) > 1:
                     found_multiple.add(i)
             assert len(self.table_reverse) == 256, "reverse table is wrong size"
   
     def rangess(self, i):
         return ', '.join(map(lambda x: '[{0},{1}]'.format(*x), self.ranges(i)))
   
     def ranges(self, i):
         for kg in itertools.groupby(enumerate(i), lambda x: x[1] - x[0]):
             g = list(kg[1])
             yield g[0][1], g[-1][1]
   
     def calc(self, data, accum=0):
         accum = ~accum
         for b in data:
             accum = self.table[(accum ^ b) & 0xFF] ^ (
                 (accum >> 8) & 0x00FFFFFF)
         accum = ~accum
         return accum & 0xFFFFFFFF
   
     def findReverse(self, desired, accum):
         solutions = set()
         accum = ~accum
         stack = [(~desired,)]
         while stack:
             node = stack.pop()
             for j in self.table_reverse[(node[0] >> 24) & 0xFF]:
                 if len(node) == 4:
                     a = accum
                     data = []
                     node = node[1:] + (j,)
                     for i in range(3, -1, -1):
                         data.append((a ^ node[i]) & 0xFF)
                         a >>= 8
                         a ^= self.table[node[i]]
                     solutions.add(tuple(data))
                 else:
                     stack.append(((node[0] ^ self.table[j]) << 8,) + node[1:] + (j,))
         return solutions
   
     def dfs(self, length, outlist=['']):
         tmp_list = []
         if length == 0:
             return outlist
         for list_item in outlist:
             tmp_list.extend([list_item + chr(x) for x in self.char_set])
         return self.dfs(length - 1, tmp_list)
   
     def run_reverse(self):
         self.init_tables(self.poly)
         desired = self.crc32
         accum = self.accum
         if self.length >= 4:
             patches = self.findReverse(desired, accum)
             for patch in patches:
                 checksum = self.calc(patch, accum)
                 print 'verification checksum: 0x{0:08x} ({1})'.format(
                     checksum, 'OK' if checksum == desired else 'ERROR')
             for item in self.dfs(self.length - 4):
                 patch = map(ord, item)
                 patches = self.findReverse(desired, self.calc(patch, accum))
                 for last_4_bytes in patches:
                     if all(p in self.char_set for p in last_4_bytes):
                         patch.extend(last_4_bytes)
                         print '[find]: {1} ({0})'.format(
                             'OK' if self.calc(patch, accum) == desired else 'ERROR', ''.join(map(chr, patch)))
         else:
             for item in self.dfs(self.length):
                 if crc32(item) == desired:
                     print '[find]: {0} (OK)'.format(item)
   
   
 def crc32_reverse(crc32, length, char_set=string.printable,
                   poly=0xEDB88320, accum=0):
     obj = crc32_reverse_class(crc32, length, char_set, poly, accum)
     obj.run_reverse()
   
   
 def crc32(s):
     return binascii.crc32(s) & 0xffffffff

```

```python
from crc32_util import *
crc = [0x7C2DF918,
       0xA58A1926,
       0x4DAD5967]
for i in crc:
    crc32_reverse(i, 6)

```

连起来就是`_CRC32_i5_n0t_s4f3`,这个就是压缩包的密码

### vigenere

打开后里面，还有个压缩包，查看里面的`tips.txt`文件，是个维吉尼亚密码

但是密钥数量太多，现在上[解密模板](<http://inventwithpython.com/hacking/diff/>)网站上找到相应解密模板

```python
# -*- coding: utf-8 -*-
#vigenereDictionaryHacker.py
import detectEnglish

LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def translateMessage(key, message, mode):
    translated = [] # 存储加密/解密消息字符串
    keyIndex = 0
    key = key.upper()
    for symbol in message: # 遍历每个消息里的字符的消息
        num = LETTERS.find(symbol.upper())
        if num != -1: # -1 意味着转换为大写在LETTERS找不到
            if mode == 'encrypt':
                num += LETTERS.find(key[keyIndex]) # 加密时相加
            elif mode == 'decrypt':
                num -= LETTERS.find(key[keyIndex]) # 解密时相减
            num %= len(LETTERS) # 处理潜在的循环           
            # 添加转换后加密/解密字符
            if symbol.isupper():
                translated.append(LETTERS[num])
            elif symbol.islower():
                translated.append(LETTERS[num].lower())
            keyIndex += 1 # 继续下一个用密钥字符来解密
            if keyIndex == len(key):
                keyIndex = 0
        else:
            # 字符不在LETTERS里直接添加
            translated.append(symbol)
    return ''.join(translated)

def decryptMessage(key, message):
    return translateMessage(key, message, 'decrypt')

def hackVigenere(ciphertext):
    fo = open('keys.txt')
    words = fo.readlines()
    fo.close()
    for word in words:
        word = word.strip()
        decryptedText = decryptMessage(word, ciphertext)
        if detectEnglish.isEnglish(decryptedText, wordPercentage=40):
            print('------------------------>>>Notice!<<<----------------------')
            print('Possible encryption break:')
            print('->>Possible key: ' + str(word))
            print('->>Possible plaintext: ' + decryptedText[:100])
            print('Enter D for done, or just press Enter to continue breaking:')
            response = raw_input('> ')
            if response.upper().startswith('D'):
                return decryptedText

def main():
    ciphertext = """rla xymijgpf ppsoto wq u nncwel ff tfqlgnxwzz sgnlwduzmy vcyg ib bhfbe u tnaxua ff satzmpibf vszqen eyvlatq cnzhk dk hfy mnciuzj ou s yygusfp bl dq e okcvpa hmsz vi wdimyfqqjqubzc hmpmbgxifbgi qs lciyaktb jf clntkspy drywuz wucfm"""
    hackedMessage = hackVigenere(ciphertext)
    if hackedMessage != None:
        print('\nCopy Possible plaintext to the clipboard:\n')
        print(hackedMessage)
    else:
        print('Failed to hack encryption.')

if __name__ == '__main__':
    main()

```

```python
# -*- coding: utf-8 -*-
# detectEnglish.py
# 英文单词探测模块
# 模块引用:
#   import detectEnglish
#   detectEnglish.isEnglish(someString) # 返回真或假
# 模块需要一个包含常见英文单词的"words.txt"，下载地址：http://invpy.com/dictionary.txt
# 将dictionary.txt改成word.txt
UPPERLETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
LETTERS_AND_SPACE = UPPERLETTERS + UPPERLETTERS.lower() + ' \t\n'

def loadDictionary():
    dictionaryFile = open('word.txt')
    englishWords = {}
    for word in dictionaryFile.read().split('\n'):
        englishWords[word] = None
    dictionaryFile.close()
    return englishWords

ENGLISH_WORDS = loadDictionary()

def getEnglishCount(message):
    message = message.upper()
    message = removeNonLetters(message)
    possibleWords = message.split()
    # print possibleWords
    if possibleWords == []:
        return 0.0 # 没有单词返回0.0

    matches = 0
    for word in possibleWords:
        if word in ENGLISH_WORDS:
            matches += 1
    return float(matches) / len(possibleWords)

def removeNonLetters(message):
    lettersOnly = []
    for symbol in message:
        if symbol in LETTERS_AND_SPACE:
            lettersOnly.append(symbol)
    return ''.join(lettersOnly)

def isEnglish(message, wordPercentage=20, letterPercentage=85):
    # 默认设置转换后的message中单词的20%能在words.txt中的单词列表找到
    # 默认设置转换后的message中85%是字母或空格
    # (not punctuation or numbers).
    wordsMatch = getEnglishCount(message) * 100 >= wordPercentage
    numLetters = len(removeNonLetters(message))
    messageLettersPercentage = float(numLetters) / len(message) * 100
    lettersMatch = messageLettersPercentage >= letterPercentage
    return wordsMatch and lettersMatch

```

```bash
$ python vigenereDictionaryHacker.py
------------------------>>>Notice!<<<----------------------  
Possible encryption break:  
->>Possible key: YEWCQGEWCYBNHDHPXOYUBJJPQIRAPSOUIYEOMTSV  
->>Possible plaintext: the vigenere cipher is a method of encrypting alphabetic text by using a series of different caesar 

```

然后在线解密：

```txt
the vigenere cipher is a method of encrypting alphabetic text by using a series of different caesar ciphers based on the letters of a keyword it is a simple form of polyalphabetic substitution so password is vigenere cipher funny

```

`vigenere cipher funny`就是密码

### `sha1`爆破

然后解压：

```txt
恭喜!
现在我们遇到一个问题,我们有一个zip文件,但我们不知道完整的解压密码。
幸好我们知道解压密码的一部分sha1值。
你能帮我们找到的密码吗?
不完整的密码："*7*5-*4*3?"  *代表可打印字符
不完整的sha1："619c20c*a4de755*9be9a8b*b7cbfa5*e8b4365*"  *代表可打印字符
人生苦短，我用Python。

```

使用模板进行`sha1`爆破，下面是个demo程序：

```python
#break_sha1.py
import hashlib
import time

def match(h,pwd):
    hl=list(h)
    if hl[0]=='6':
        if hl[1]=='1':
            if hl[2]=='9':
                if hl[3]=='c':
                    if hl[4]=='2':
                        if hl[5]=='0':
                            if hl[6]=='c':
                                if hl[8]=='a':
                                    if hl[16]=='9':
                                        if hl[24]=='b':
                                            if hl[32]=='e':
                                                print "Find!"
                                                print "Hash:%s" %h
                                                print "Password:%s" %pwd
                                                matched=1
                                                return matched

    else:
        matched=0
        return matched

def generate():
    x=range(32,128)
    for i in x:
        for j in x:
            for k in x:
                for l in x:
                    pwd=chr(i)+'7'+chr(j)+'5-'+chr(k)+'4'+chr(l)+'3?'
                    sha1_hash=hashlib.sha1()
                    sha1_hash.update(pwd)
                    h=sha1_hash.hexdigest()
                    matched=match(h,pwd)
                    if matched:
                        print "congratulation!"
                        return 0
                    else:
                        pass
def main():
    start=time.clock()
    print "Breaking,please wait!"
    generate()
    end=time.clock()
    print "Used time:%s" %(end-start)
if __name__ == '__main__':
    main()

```

得到的结果是：

```bash
Breaking,please wait!        
Find!                            
Hash:619c20c4a4de75519be9a8b7b7cbfa54e8b4365b
Password:I7~5-s4F3?               
congratulation!      
Used time:70.78125

```

### MD5

将easy SHA1解压之后

```txt
Hello World ;-)
MD5校验真的安全吗？
有没有两个不同的程序MD5却相同呢？
如果有的话另一个程序输出是什么呢？
解压密码为单行输出结果。

```

看到这段文字，说另一个程序输出是什么，不知道思路，网上查查，找到一篇这样的[blog](<https://blog.csdn.net/thanklife/article/details/78685255>)

将其中两个程序下载运行：

```python
#第一个输出
Hello World ;-)
#第二个输出
Goodbye World :-(

```

所以这里的密码应该是`Goodbye World :-(`

### RSA

解压后，最后是一个RSA加密：
使用`openssl`查看公钥文件:

```bash
RSA Public-Key: (1026 bit) 
Modulus:                       
02:8f:ff:9d:d3:e6:fe:97:81:64:9e:b7:fe:5e:93:    
03:cf:69:63:47:c4:11:0b:c4:ba:39:69:f0:b1:16:  
69:84:0c:51:d8:1a:68:42:b6:df:2b:09:0f:21:cd: 
76:d4:37:1a:8c:0e:47:04:8c:96:5e:ca:5b:46:91: 
3a:fb:b8:da:05:20:72:a0:56:6d:70:39:c6:18:ab: 
a9:06:57:59:b0:59:e2:9e:48:5d:c5:06:1a:16:ac:    
63:12:94:38:d9:35:4e:65:df:57:47:54:6b:85:db: 
3d:69:98:19:c4:b7:73:2d:f9:27:c7:08:4a:5d:52:  
d6:e6:d6:aa:c1:44:62:34:25                                                                                                             
Exponent:                 
01:f8:fb:a4:10:05:2d:f7:ed:a3:46:2f:1a:ac:d6:     
9e:40:76:04:33:ca:33:57:67:cd:73:05:a3:d0:90: 
80:5a:5f:d4:05:dd:6e:ea:70:e9:8f:0c:a1:e1:cf:  
25:47:48:67:1b:f0:c9:80:06:c2:0e:ee:1d:62:79: 
04:35:09:fe:7a:98:23:8b:43:91:60:a5:61:2d:a7:  
1e:90:45:14:e8:12:80:61:7e:30:7c:3c:d3:31:3f: 
a4:c6:fc:a3:31:59:d0:44:1f:bb:18:d8:3c:af:4b:
d4:6f:6b:92:97:a8:0a:14:2d:d6:9b:f1:a3:57:cc:   
b5:e4:c2:00:b6:d9:0f:15:a3
Modulus=28FFF9DD3E6FE9781649EB7FE5E9303CF696347C4110BC4BA3969F0B11669840C51D81A6842B6DF2B090F21CD76D4371A8C0E47048C965ECA5B46913AFBB8DA052072A0566D7039C618ABA9065759B059E29E485DC5061A16AC63129438D9354E65DF5747546B85DB3D699819C4B7732DF927C7084A5D52D6E6D6AAC144623425    

```

看的出来，这里需要维纳攻击:

使用rsa-wiener-attack工具求出d,

```
if __name__ == "__main__":
    #test_is_perfect_square()
    #print("-------------------------")
    n = 460657813884289609896372056585544172485318117026246263899744329237492701820627219556007788200590119136173895989001382151536006853823326382892363143604314518686388786002989248800814861248595075326277099645338694977097459168530898776007293695728101976069423971696524237755227187061418202849911479124793990722597
    e = 354611102441307572056572181827925899198345350228753730931089393275463916544456626894245415096107834465778409532373187125318554614722599301791528916212839368121066035541008808261534500586023652767712271625785204280964688004680328300124849680477105302519377370092578107827116821391826210972320377614967547827619
    d = hack_RSA(e,n)
    print("d=",d)

```

得到`d = 8264667972294275017293339772371783322168822149471976834221082393409363691895`

下面就可以直接写解密脚本了：

```python
#coding=utf-8
#owner:IFpop
#time:2019/10/29

import gmpy2
from Crypto.Util import number

n = 460657813884289609896372056585544172485318117026246263899744329237492701820627219556007788200590119136173895989001382151536006853823326382892363143604314518686388786002989248800814861248595075326277099645338694977097459168530898776007293695728101976069423971696524237755227187061418202849911479124793990722597
d = 8264667972294275017293339772371783322168822149471976834221082393409363691895

with open('flag.enc','rb')as f:
    c = number.bytes_to_long(f.read()) 
m = pow(c,d,n)
print(number.long_to_bytes(m))
#flag{W0rld_Of_Crypt0gr@phy}

```



## DSA

关于`DSA`之前也没怎么接触过，现在遇到，就顺便总结一下

### 知识点

#### 概述

1. 是Schnorr和ElGamal签名算法的变种，被美国NIST作为数字签名标准
2. 它是另一种公开密钥算法，它不能用作加密，只用作数字签名。
3. DSA使用公开密钥，为接受者验证数据的完整性和数据发送者的身份。它也可用于由第三方去确定签名和所签数据的真实性。DSA算法的安全性基于解离散对数的困难性，这类签字标准具有较大的兼容性和适用性，成为网络安全体系的基本构件之一。

#### 其他知识点

[总结](<https://www.jarviswang.me/?p=169>)

### 解题

> DSA是基于整数有限域离散对数难题的，其安全性与RSA相比差不多。DSA的一个重要特点是两个素数公开，这样，当使用别人的p和q时，即使不知道私钥x，你也能确认它们是否是随机产生的，还是作了手脚。
>
> 可以使用openssl方便地进行dsa签名和验证。
>
> 签名与验证：
>
> ```bash
> openssl dgst -sha1 -sign dsa_private.pem -out sign.bin message.txt
> openssl sha1 -verify dsa_public.pem -signature sign.bin message.txt
> 
> ```
>
> 本题的攻击方法曾被用于PS3的破解，答案格式：CTF{x}(x为私钥，请提交十进制格式)

下载文件解压，发现里面有着四个`packet`以及一个公钥

使用上述命令可以验证通过。

其中的`message`文件可以查看，可以找到一些信息:

```python
#message1
Digital Signature Algorithm (DSA)是Schnorr和ElGamal签名算法的变种，被美国NIST作为DSfS(DigitalSignature Standard)。
http://baike.baidu.com/item/DSA%E7%AE%97%E6%B3%95
#message2
这里简要介绍了一些asn1结构编码
#message3
介绍了一些openssl
#message4
。。。

```

查了一下asn1的知识，发现`openssl`中就存在着asn1parse转码操作，所以以此查看sign.bin中的信息

```bash
openssl asn1parse [-inform PEM|DER] [-in filename] [-out filename] [-noout] [-offset number] [-length number] [-i] [- structure filename] [-strparse offset] 

```

```bash
 openssl asn1parse -inform der -in packet1/sign1.bin 
0:d=0  hl=2 l=  45    cons: SEQUENCE 
2:d=1  hl=2 l=  21    prim: INTEGER      :8158B477C5AA033D650596E93653C730D26BA409  
25:d=1  hl=2 l=  20   prim: INTEGER      :165B9DD1C93230C31111E5A4E6EB5181F990F702 

openssl asn1parse -inform der -in packet2/sign2.bin         
0:d=0  hl=2 l=  44 cons: SEQUENCE                                      
2:d=1  hl=2 l=  20 prim: INTEGER         :60B9F2A5BA689B802942D667ED5D1EED066C5A7F   
24:d=1  hl=2 l=  20 prim: INTEGER        :3DC8921BA26B514F4D991A85482750E0225A15B5

openssl asn1parse -inform der -in packet3/sign3.bin 
0:d=0  hl=2 l=  44 cons: SEQUENCE                                     
2:d=1  hl=2 l=  20 prim: INTEGER         :5090DA81FEDE048D706D80E0AC47701E5A9EF1CC    
24:d=1  hl=2 l=  20 prim: INTEGER        :30EB88E6A4BFB1B16728A974210AE4E41B42677D

openssl asn1parse -inform der -in packet4/sign4.bin     
0:d=0  hl=2 l=  44  cons: SEQUENCE                               
2:d=1  hl=2 l=  20  prim:  INTEGER      :5090DA81FEDE048D706D80E0AC47701E5A9EF1CC  #r
24:d=1  hl=2 l=  20 prim:  INTEGER      :5E10DED084203CCBCEC3356A2CA02FF318FD4123  #s

```

$$
r = (g^k mod\ p) mod\ q \qquad \qquad \\
s = [k^{-1}*(H(M)+xr)] mod\ q
$$

由于对多条消息进行数字签名时，k是不变的，所以：
$$
k*s_1 = H(M_1)+xr(mod\ q) \quad (1) \\
k*s_2 = H(M_2)+xr(mod\ p) \quad (2)\\
$$
由`(1)*s2`、`(2)*s1`得：
$$
k*s_1*s_2 = s_2*H(M_1)+s_2*xr(mod\ q) \\
k*s_2*s_1 = s_1*H(M_2)+s_1*xr(mod\ q)
$$
最终可以解得:
$$
x = [s_2*H(M_1)-s_1*H(M_2)]（s_1*r-s_2*r）^{-1} mod\ q
$$
而上面的分析可以发现，只有packet3和packet4的r是相同的，所以脚本如下：

```python
from Crypto.PublicKey import DSA
from hashlib import sha1
import gmpy2
with open('dsa_public.pem','rb') as f:
    key = DSA.importKey(f.read())
    y = key.y
    g = key.g
    p = key.p
    q = key.q
f3 = open("packet3/message3", 'rb')
f4 = open("packet4/message4", 'rb')
data3 = f3.read()
data4 = f4.read()
sha = sha1()
sha.update(data3)
m3 = int(sha.hexdigest(), 16)
sha = sha1()
sha.update(data4)
m4 = int(sha.hexdigest(), 16)
s3 = 0x30EB88E6A4BFB1B16728A974210AE4E41B42677D
s4 = 0x5E10DED084203CCBCEC3356A2CA02FF318FD4123
r = 0x5090DA81FEDE048D706D80E0AC47701E5A9EF1CC

x = ((s4*m3-s3*m4)*gmpy2.invert(s3*r-s4*r,q))%q
print(x)
#520793588153805320783422521615148687785086070744

```

所以`CTF{520793588153805320783422521615148687785086070744}`

## vigenere

这题要使用kriski测试法，太麻烦了，直接上[大佬程序](<http://73spica.tech/blog/tw_mma_ctf_2016_vigenere-cipher/>)

```python
#!usr/env/python
#coding=utf-8
#owner: IFpop
#time: 2910/11/2

from base64 import b64encode, b64decode
import sys
import os
import random
from fractions import gcd
from math import sqrt
 
candi_count = 0
chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/'
encrypted = "a7TFeCShtf94+t5quSA5ZBn4+3tqLTl0EvoMsNxeeCm50Xoet+1fvy821r6Fe4fpeAw1ZB+as3Tphe8xZXQ/s3tbJy8BDzX4vN5svYqIZ96rt35dKuz0DfCPf4nfKe300fM9utiauTe5tgs5utLpLTh0FzYx0O1sJYKgJvul0OfiuTl00BCks+aaJZm8Kwb4u+LtLCqbZ96lv3bieCahtegx+7nzqyO6YCb4b9LovCELZ9Pe0L5rLSaBDzXaftxseAw1JzCF0MGjeCacKb69u9TlgCudZT6Os3ojhcWxD914vNHfeCuaJvH4s4aarBKlGdsT8G4UKZhfJB+y0LbjqCOnZT6baF1WiZeNtfsNtuoo+c=="
 
def shift(char, key, rev = False):
    if not char in chars:
        return char
    if rev:
        return chars[(chars.index(char) - chars.index(key)) % len(chars)]
    else:
        print((chars.index(char) + chars.index(key)) % len(chars))
        return chars[(chars.index(char) + chars.index(key)) % len(chars)]
 
def encrypt(message, key):
    encrypted = b64encode(message.encode('ascii')).decode('ascii')
    return ''.join([shift(encrypted[i], key[i % len(key)]) for i in range(len(encrypted))])
 
def original_decrypt(encrypted, key):
    encrypted = ''.join([shift(encrypted[i], key[i % len(key)], True) for i in range(len(encrypted))])
    return b64decode(encrypted.encode('ascii')).decode('ascii')
 
# not using encode or decode ascii
def decrypt(encrypted, key):
    encrypted = ''.join([shift(encrypted[i], key[i % len(key)], True) for i in range(len(encrypted))])
    return b64decode(encrypted)
 
def generate_random_key(length = 5):
    return ''.join(map(lambda a : chars[a % len(chars)], os.urandom(length)))
 
def Kasiski_exam(encrypted):
    strlist = []
    count = 0
    indexlist = []
    for i in range(len(encrypted)):
        for j in range(i,len(encrypted)):
            if j-i<3:
                    continue
            start = i
            search_str = encrypted[i:j]
            while True:
                detect = encrypted[start:].find(search_str)
                if detect == -1:
                    break
                else:
                    count+=1
                    if count==2:
                        strlist.append(search_str)
                        indexlist.append(detect+j-i)
                    start += detect+(j-i)
            if count==0:
                break
            count=0
    print(indexlist)
    print(strlist)
    anslist = my_factor(indexlist)
    return anslist
 
def my_factor(numlist):
    factor_list = []
    for x in range(2,int(sqrt(numlist[0]))+1):
        if numlist[0]%x == 0 and x>=5 and x<=14:
            factor_list.append(x)
    for i in range(1,len(numlist)):
        anslist = list(factor_list)
        num = numlist[i]
        for x in factor_list:
            if num%x !=0:
                anslist.remove(x)
    return anslist
 
def is_ascii(string):
    if string:
        for char in string:
            if  char > 126:
                return False
            if char<32 and not char==10:
                return False
    return True
 
def split_str_and_isascii(plain,num,block):
    start = 3*block
    for i in range(start,len(plain),9):
        if not is_ascii(plain[i:i+num]):
            return False
    return True
 
# if key_len == 12
def brute_key(encrypted,key_len):
    global candi_count
    candi_key_list = [[],[],[]]
    for block in range(int(key_len/4)):
        for a in chars:
            for b in chars:
                if not split_str_and_isascii(decrypt(encrypted,a+b+"aa"),1,block):
                    continue
                for c in chars:
                    if not split_str_and_isascii(decrypt(encrypted,a+b+c+"a"),2,block):
                        continue
                    for d in chars:
                        if split_str_and_isascii(decrypt(encrypted,a+b+c+d),3,block):
                            candi_key_list[block].append(a+b+c+d)
                            candi_count+=1
    return candi_key_list
 
#if key_len == 6
def brute_key_6(encrypted,key_len):
    global candi_count
    candi_key_list = []
    for block in range(int(key_len/4)):
        for a in chars:
            for b in chars:
                if not split_str_and_isascii(decrypt(encrypted,a+b+"aa"),1,block):
                    continue
                for c in chars:
                    if not split_str_and_isascii(decrypt(encrypted,a+b+c+"a"),2,block):
                        continue
                    for d in chars:
                        if split_str_and_isascii(decrypt(encrypted,a+b+c+d),3,block):
                            candi_key_list.append(a+b+c+d)
                            candi_count+=1
    return candi_key_list
 
def main():
    # ==== kasiski examination ====
    factor_list = Kasiski_exam(encrypted) # [6,12]
    key_len = factor_list[1]
    # ==== brute force attack to base64 ====
    print("Start brute force...")
    candi_key1,candi_key2,candi_key3 = brute_key(encrypted,key_len)
    print(candi_key1)
    print(candi_key2)
    print(candi_key3)
 
    # ==== key candidate ====
    keylist = []
    for key1 in candi_key1:
        for key2 in candi_key2:
            for key3 in candi_key3:
                keylist.append(key1+key2+key3)
    print(candi_count)
    print(keylist)
 
    # if "TWCTF{" in decrypted, It is highly possible that the key is correct.
    for key in keylist:
        dec = decrypt(encrypted,key)
        check = b"TWCTF{"
        if check in dec:
            print("--------- key candidate : decrypted ---------------")
            print(key,":",dec)
            print()
 
if __name__ == '__main__':
    main()
#TWCTF{C14ss1caL CiPhEr iS v3ry fun}

```



## superexpress

下载下来两个文件：

```python
#problem.py
import sys
key = '****CENSORED***************'
flag = 'TWCTF{*******CENSORED********}'

if len(key) % 2 == 1:
    print("Key Length Error")
    sys.exit(1)

n = len(key) / 2
encrypted = ''
for c in flag:
    c = ord(c)
    for a, b in zip(key[0:n], key[n:2*n]): #关于zip函数可以自己查一下
        c = (ord(a) * c + ord(b)) % 251
    encrypted += '%02x' % c

print encrypted
#enc 805eed80cbbccb94c36413275780ec94a857dfec8da8ca94a8c313a8ccf9

```

由于最后的结果会模上251，所以key的所有字母的ASCII一定在251以内且长度为偶数，脚本如下：

```python
#!usr/env/python3
#coding=utf-8
#owner: IFpop
#time: 2019/10/31

import string
#由于flag的开头是TWCTF{},而a,b一定会在251以内，所以可以将a,b爆破出来
def find_key():
    for a in range(251):
        for b in range(251):
            if (ord("T") * a + b) % 251 == int_enc[0] and (ord("W") * a + b) % 251 == int_enc[1] and (ord("C") * a + b) % 251 == int_enc[2]:
                return a, b

enc = "805eed80cbbccb94c36413275780ec94a857dfec8da8ca94a8c313a8ccf9"
int_enc = []
#将上面密文转化成10进制
for i in range(0, len(enc), 2):
    int_enc += [int(enc[i:i + 2], 16)]

a,b = find_key()
#生成所有可打印字符
chars = string.printable
flag = ""
for i in int_enc:
    for j in chars:
        if (ord(j)*a+b)%251 == i:
            flag += j
print(flag)
#TWCTF{Faster_Than_Shinkansen!}

```



## 好多盐

> 某遗留系统采用固定格式+6-10位数字类型密码，今天他们发生了数据泄露事件，已知固定格式为{FLAG:}，做为一名黑客，你要开始干活了。字符串长度为10位

题目给了很多hash过的文件，以及盐，关于这方面的概念可以自行百度`md5`与盐的相关知识，直接爆破就行:

```python
#!usr/env/python3
#coding=utf-8
#owner: IFpop
#time: 2019/11/1
#!usr/env/python3
#coding=utf-8
#owner: IFpop
#time: 2019/11/1

from Crypto.Hash import MD5

password = '''f09ebdb2bb9f5eb4fbd12aad96e1e929 p5Zg6LtD
 6cea25448314ddb70d98708553fc0928 ZwbWnG0j
 2629906b029983a7c524114c2dd9cc36 1JE25XOn
 2e854eb55586dc58e6758cfed62dd865 ICKTxe5j
 7b073411ee21fcaf177972c1a644f403 0wdRCo1W
 6795d1be7c63f30935273d9eb32c73e3 EuMN5GaH
 d10f5340214309e3cfc00bbc7a2fa718 aOrND9AB
 8e0dc02301debcc965ee04c7f5b5188b uQg6JMcx
 4fec71840818d02f0603440466a892c9 XY5QnHmU
 ee8f46142f3b5d973a01079f7b47e81c zMVNlHOr
 e4d9e1e85f3880aedb7264054acd1896 TqRhn1Yp
 0fd046d8ecddefc66203f6539cac486b AR5lI2He
 f6326f02adaa31a66ed06ceab2948d01 Aax2fIPl
 720ba10d446a337d79f1da8926835a49 ZAOYDPR2
 06af8bcc454229fe5ca09567a9071e62 hvcECKYs
 79f58ca7a81ae2775c2c2b73beff8644 TgFacoR3
 46aaa5a7fef5e250a2448a8d1257e9cf GLYu0NO4
 2149ac87790dd0fe1b43f40d527e425a 5Xk2O1sG
 d15a36d8be574ac8fe64689c728c268e aZikhUEy
 ff7bced91bd9067834e3ad14cc1464cd E7UROqXn
 8cc0437187caf10e5eda345cb6296252 XPin3mVB
 5cfcdca4a9cb2985a0b688406617689e nsGqoafv
 5a7dfa8bc7b5dfbb914c0a78ab2760c6 YC1qZUFR
 8061d8f222167fcc66569f6261ddd3cc wNgQi615
 3d8a02528c949df7405f0b48afe4a626 CO2NMusb
 70651acbc8bd027529bbcccdbf3b0f14 CAXVjFMd
 a9dbe70e83596f2d9210970236bdd535 TL6sjEuK
 9ed6ef5780f705ade6845b9ef349eb8f tJ90ibsz
 4b46fac0c41b0c6244523612a6c7ac4a VTjOSNmw
 8141e6ecb4f803426d1db8fbeb5686ef lh75cdNC
 df803949fd13f5f7d7dd8457a673104b V39sEvYX
 19052cc5ef69f90094753c2b3bbcd41d YwoGExpg
 cf8591bdccfaa0cdca652f1d31dbd70f pJCLui49
 66e10e3d4a788c335282f42b92c760a1 NQCZoIhj
 94c3ae5bcc04c38053106916f9b99bda vOktelLQ
 e67e88646758e465697c15b1ef164a8d x0hwJGHj
 84d3d828e1a0c14b5b095bedc23269fb 2HVWe9fM
 264a9e831c3401c38021ba3844479c3f Cx4og6IW
 ed0343dec184d9d2c30a9b9c1c308356 g2rqmPkT
 ad5ba8dc801c37037350578630783d80 pFK2JDT5
 3f588bedb704da9448e68fe81e42bca6 4ANDOiau
 970c9cf3cad3dfa7926f53ccaae89421 R6ML7Qy8
 e0a097b7cceaa7a8949fe039884e4a2d dul2ynqL
 7df505218102c64b1fe4fa5981ddb6fa jPeoyS57
 fd4f6043da1f7d5dca993c946ef6cd7c 6p9CwGaY
 5fe6d99b9a2824949279187c246c9c30 OGQ2J57y
 135b150ad513a961089bb1c05085a3d9 h0dw1Fro
 ad6af4fb623b3c51181a371911667fed HbQT4dRz
 c9fa4b0db317d88e2b10060225e92494 ebVnpMzS
 d0deab17d115bd6fdce8592bb3667643 bL5zwgvX
 006f0cb3a422716692f143f28eb0d187 NHXg1Fof
 ddc125de34da1a6ec0cbe401f147bc8f GDai9Y0n
 be5052053c5a806e8f56ed64e0d67821 40alyH3w
 aaf18ac446b8c385c4112c10ae87e7dc ZJQzuIL0
 a2db20a4b7386dc2d8c30bf9a05ceef7 QnpOlPWH
 8a4fbc32a3251bb51072d51969ba5d33 rtcbipeq
 5e35d2c9675ed811880cea01f268e00f i1Hbne6h
 9da23007699e832f4e9344057c5e0bd3 EtbGpMSW
 f09233683d05171420f963fc92764e84 fxHoinEe
 4feabf309c5872f3cca7295b3577f2a8 KymkJXqA
 9b94da2fa9402a3fdb4ff15b9f3ba4d2 G3Tdr1Pg
 b3cd8d6b53702d733ba515dec1d770c5 Y71LJWZz
 6a5b3b2526bb7e94209c487585034534 rIwb4oxt
 e9728ef776144c25ba0155a0faab2526 e1sOXSb8
 d41a5e7a98e28d76dbd183df7e3bcb49 36bedvia
 81d5ebfea6aff129cf515d4e0e5f8360 dDG4qTjW'''

password = password.split('\n')
def solve():
    for i in password:
        print(i)
        pass_md5 = i.split(' ')[0]
        salt = i.split(' ')[1]
        #由于有着6-10位数字
        for j in range(100000,10000000000):
            print(j)
            md5 = MD5.new()
            temp = '{FLAG:'+str(j).zfill(10)+'}'+salt
            temp = bytes(temp,encoding="utf-8")
            md5.update(temp)
            if md5.hexdigest() == pass_md5:
                print(j)
                break
solve()
#1234567890

```



## 影之密码

> 请分析下列密文进行解密 8842101220480224404014224202480122 得到flag，flag为8位大写字母

**分析**：

1. `flag`是8位大写字母
2. 有7个0，正好分成8段
3. 每段中仅有1，2，4，8，全是2的幂数
4. 查询有关2^n的加密方式，[二进制幂数加密法](<https://baike.baidu.com/item/%E4%BA%8C%E8%BF%9B%E5%88%B6%E5%B9%82%E6%95%B0%E5%8A%A0%E5%AF%86%E6%B3%95/2410151?fr=aladdin>)
5. 这里与实际上的二进制幂数加密还是稍微有些区别，8 -– 3 但是这里直接给出，最后解密的结果其实就是将其相加，转成ASCII

**解密**：

```python
#!usr/env/python3
#coding=utf-8
#owner:IFpop

enc = '8842101220480224404014224202480122'
enc = enc.split('0')
print(enc)
ans = ''
for i in enc:
    temp = 0
    for j in i:
        temp += int(j)
    ans += chr(ord('A')+temp-1)
print(ans)
#WELLDONE

```



## Jarvis’s encryption system

> Let’s play with Jarvis’s new encryption box.
>
> **nc pwn.jarvisoj.com 9880**

下载下来有两个附件：一个是crypto500.py，一个有关加密过程的图片(就不放上来了)

```python
#!/usr/bin/env python
from Crypto.PublicKey import RSA
import gmpy2
key = RSA.importKey(open('private.pem').read())
N = 808637320166213096433765975908829772554859069394497436792703828416763985949910999652518305818627321094257781267795371106923808192073932662313603219525599014635435542122940843344921727149256852355110338886574805360544004118210641173633231100848831019159519744863314748281129830905559513810272933968408858616937223539622595750248885831720830102914499513408356858587797522763592193335162884129664298938995394243273615798207065590802899685489088903478734288977143851327400816886878238915788561611104380001569848016035186213716602462262685777960742683591155978590371074585063550419528377002596163321548052257322263024813745933243795081592986850478573362522245788630785664119935566422559659277401321793012274415007906726880710258434953224297253000176721652344571059040066987969691706315602374506498087282531643212970147526356421919309049062439117990930204486012562031589114880474346559407445496718773030816258262150397230280669274725009415653773469037623986165899557423095323109994543129373149980880777219450714265152054529287453826506032747047856303879606356141420416161004589629524370677871918513405209191951229311529443558187652701599377904802383252318582028816524498306240682160249309341335405511246150908708558397938689907425750101507
p = key.p
q = key.q
def encrypt(m, e):
	return pow(m, e, N)	
def main():
	print 'Welcome to Jarvis\'s encryption system.Let\'s init the cipher first:'
	print "e:",
	e = int(raw_input().strip())
	d = gmpy2.invert(e,(p-1)*(q-1))
	print "d: %d" % d
	
	cnt = 0
	while True:
		cnt += 1
		print "m%d:" % cnt,
		m = int(raw_input().strip())
		c = encrypt(m, e)
		print "c%d: %d" % (cnt, c)
		print ''
if __name__ == '__main__':
	main()

```

使用上述nc命令进行访问，键入e值，会返回d值。

1. 先把图片中的信息提取出来(用winhex查看末尾就行)

2. 通过已知的明文、密文对e进行爆破

   ```python
   #usr/env/python3
   #coding=utf-8
   #owner: IFpop
   #time: 2019/11/5
   
   import gmpy2
   from Crypto.Util import number
   
   n = 808637320166213096433765975908829772554859069394497436792703828416763985949910999652518305818627321094257781267795371106923808192073932662313603219525599014635435542122940843344921727149256852355110338886574805360544004118210641173633231100848831019159519744863314748281129830905559513810272933968408858616937223539622595750248885831720830102914499513408356858587797522763592193335162884129664298938995394243273615798207065590802899685489088903478734288977143851327400816886878238915788561611104380001569848016035186213716602462262685777960742683591155978590371074585063550419528377002596163321548052257322263024813745933243795081592986850478573362522245788630785664119935566422559659277401321793012274415007906726880710258434953224297253000176721652344571059040066987969691706315602374506498087282531643212970147526356421919309049062439117990930204486012562031589114880474346559407445496718773030816258262150397230280669274725009415653773469037623986165899557423095323109994543129373149980880777219450714265152054529287453826506032747047856303879606356141420416161004589629524370677871918513405209191951229311529443558187652701599377904802383252318582028816524498306240682160249309341335405511246150908708558397938689907425750101507
   m1 = 89372489723987498237894327984372
   c1 = 792279062886162218096642776664224514933347584486280723004734021586336212749049858600481963227286459323970478541843083793725468708921717787221937249530784012084036132167698694870670989692185525559265359595824727956010042190235432643115112280623082788133230708728369892499755238276075667536752879449115011933006031581738186877618805996280847737363426887886868682686959858371130406926178828888575004380515988821399247906070333132810952695798429265793849588130806947806841034544612000197604854503195512120025729616966658790540157838337703936086683817085220432748606686965902101050255048796382841321391071407100767404596588780879740560771450534303617347553555472893929700798373187625224545676303975128589469709553887522697982505366205159178754377849727155295773459020853899833570753142832536760229326028534739725856990225488803963836214548294423502322319111713836053680359093114158912017408230992904911531693795674356749450578360594750306010644345865018135713049088702085668117922755659876667178408188245170381487842104129405699987082399408416605832498886309106565903612880735897179022046135207448286905927468981921408174446350113407999312543013150441972687118445672308468055301677455644948365453703227341347327118261153884632046860369729
   
   e = 1 
   while(1):
       print(e)
       c = pow(m1,e,n)
       if c == c1:
           #7845741   跑了很久，希望之后能找到更快的方法
           print("done!")
           print(e)
           break
       e = e + 1
   
   ```

3. 利用`nc`访问链接，得到d

4. 解密就行：

   ```python
   #usr/env/python3
   #coding=utf-8
   #owner: IFpop
   #time: 2019/11/5
   
   import gmpy2
   from Crypto.Util import number
   
   d = 624460328909915360701402168639641282028094468418961878947574807290638891758678991143435088653980701535371225162050430031333639072505365342535152293096454464491608234713910040741806054032872119204341656042243036836513731486079394171780995659012791615808025872985542653518800484827924355387767430294123689221121329057758535673622344148467540232245253256875196052350040448617224502051601181938246394036842235391465615724331125440683500889291172253639404968619326290436776700446299000007994603663440301337649478949521483497552296109838827309290662620012954396232530653067994746179325738761837228276717554780296018709380622306541045859622715377902354561164951333797443088787938481179135106105790091663516291819506679417163921126064227724274720567814644923715786512409941352289194976639518315198223889636540907899742620702027181209723760906029440110133038012652837512150214031930229627563605747245442722777826347211476418833664939434587222857079580932195626606642019627685477852118740507133047312988551945249158637120933025247874896831420739652406553559282198158772718455703088272187706565621125165787151495212884395636011063049499722644316616892917352706474956487897928799493388647214180485284836266930315584778253034297866155428036121429
   n = 808637320166213096433765975908829772554859069394497436792703828416763985949910999652518305818627321094257781267795371106923808192073932662313603219525599014635435542122940843344921727149256852355110338886574805360544004118210641173633231100848831019159519744863314748281129830905559513810272933968408858616937223539622595750248885831720830102914499513408356858587797522763592193335162884129664298938995394243273615798207065590802899685489088903478734288977143851327400816886878238915788561611104380001569848016035186213716602462262685777960742683591155978590371074585063550419528377002596163321548052257322263024813745933243795081592986850478573362522245788630785664119935566422559659277401321793012274415007906726880710258434953224297253000176721652344571059040066987969691706315602374506498087282531643212970147526356421919309049062439117990930204486012562031589114880474346559407445496718773030816258262150397230280669274725009415653773469037623986165899557423095323109994543129373149980880777219450714265152054529287453826506032747047856303879606356141420416161004589629524370677871918513405209191951229311529443558187652701599377904802383252318582028816524498306240682160249309341335405511246150908708558397938689907425750101507
   c = 738822002752800877524466308025949155169562722946933006009883884249589602039677687891359871510923927357766748131398443497541198900771818831638644263405425815579383553019562159083788644122365536627592737115316351290153544908592280731090451811311680698586032725090719266003369555867584457372823678746133588560994163232730766388456903527206840527304843529539480355012405496730615078972755415860013097394363116913629756292725693596880188792245847698225435105827398989245800248197290718407831242734331874121327502564673597694670795036098967372950089253263743880807024448724715652660602771818683520844873803372738417012436219777372987997036211306992938395670636075660990930360358970016244484405618827909229400111542660072678812089441010001235353317911131109787281238112284352067511452432985149442969693926797740772628154057474332702139775407456229918917403138849681496015981718513476254353617586634306067889050783266988506871489696817574207289110594169371818597141857443042841485880477066344316648550850088971005108756497748568090122624591451915965314486079436499049418137147522360690326710468200339550170216543240318289067712843687012174036874897324652429812609807952220427326987655148639613323665786093803557065570465270944069296977739085
   m = pow(c,d,n)
   print(number.long_to_bytes(m))
   #USTCTF{U_r_real33y_m4st3r_0f_math}
   
   ```

## 神秘压缩包

> 就不告诉你密码，看你怎么办。

下载下来一个rar压缩包，一般rar是不会存在伪加密的(至少目前没有遇到过)，尝试爆破，发现时间太长，不太行。

剩下就是尝试一个crc32爆破了(方法同Complicated Crypto)，这里尝试5位

```python
from crc32_util import *
crc = [0x20AE9F17,
       0xD2D0067E,
       0x6C53518D,
       0x80DF4DC3,
       0x3F637A50,
       0xBCD97038]
for i in crc:
    crc32_reverse(i, 5)

```

得到结果：

```bash
verification checksum: 0x20ae9f17 (OK)
[find]: l./rc (OK)
[find]: passw (OK)
verification checksum: 0xd2d0067e (OK)
[find]: "_YWn (OK)
[find]: N,tS* (OK)
[find]: Rc(R> (OK)
[find]: ord:f (OK) 
[find]: s=8;r (OK)
verification checksum: 0x6c53518d (OK)
[find]: /8LWp (OK)
[find]: CKaS4 (OK)
[find]: ~Z-;l (OK) 
verification checksum: 0x80df4dc3 (OK)
[find]: apEwF (OK)
verification checksum: 0x3f637a50 (OK)
^Q6w (OK)
[find]: \<0Zk (OK)
[find]: a-|23 (OK)
[find]: }b 3' (OK)
verification checksum: 0xbcd9703b (OK)
[find]: hyAo5 (OK) 

```

所以密码为：`password:f~Z-;lapEwF\<0ZkhyAo5`

得到`XUSTCTF{6ebd0342caa3cf39981b98ee24a1f0ac}`

## 简单ECC

> 已知椭圆曲线加密Ep(a,b)参数为
>
> p = 15424654874903
>
> a = 16546484
>
> b = 4548674875
>
> G(6478678675,5636379357093)
>
> 私钥为
>
> k = 546768
>
> 求公钥K(x,y)
>
> 提示：K=kG
>
> 提交格式XUSTCTF{x+y}(注意，大括号里面是x和y加起来求和，不是用加号连接)

```python
#!usr/env/python3
#coding=utf-8
#owner: IFpop
#time: 2019/11/5

import gmpy2

a = 16546484
b = 4548674875
M = 15424654874903
G = (6478678675, 5636379357093)
#初始的K与G是相同的，
K = (6478678675,5636379357093)

for i in range(1,546768):
    x1,y1 = K
    x2,y2 = G
    if K!=G:
        t = int((y2-y1)*gmpy2.invert(x2-x1,M))
    else:
        t = int((3*x1*x1+a)*gmpy2.invert(2*y1,M))
    x3 = t*t-x1-x2
    y3 = t*(x1-x3)-y1
    K = (x3%M,y3%M)
print("XUSTCTF{"+str(K[0]+K[1])+"}")
#XUSTCTF{19477226185390}

```

## God Like RSA

[RSA-集锦](<https://ifpop.github.io/2019/10/21/RSA-%E9%9B%86%E9%94%A6/#more>)

## Extremely hard RSA

[RSA-集锦](<https://ifpop.github.io/2019/10/21/RSA-%E9%9B%86%E9%94%A6/#more>)

## very hard RSA

[RSA-集锦](<https://ifpop.github.io/2019/10/21/RSA-%E9%9B%86%E9%94%A6/#more>)

## hard RSA

[RSA-集锦](<https://ifpop.github.io/2019/10/21/RSA-%E9%9B%86%E9%94%A6/#more>)

## BrokenPic

下载下来是一个bmp文件，文件损坏不能打开，使用winhex打开，发现没有bmp文件头,填入文件头重新填入：

```asciiarmor
42 4D 38 0C 30 00 00 00 00 00 36 00 00 00 28 00 00 00 56 05 00 00 00 03 00 00 01 00 18 00 00 00 00 00 02 0C 30 00 12 0B 00 00 12 0B 00 00 00 00 00 00 00 00 00 00

```

这里补充一下有关bmp头格式：

```txt
//存储方式为小端序
42 4D //2bytes "BM"
36 58 02 00 //4 bytes Total size included "BM" magic(s)
00 00 00 00 //这里必须置为0
36 00 00 00 //从文件开始到位图数据之间的偏移量 这里是54
28 00 00 00 //bitmap head 的大小为40字节
56 05 00 00 //宽度为1366
00 03 00 00 //高度为768
01 00  //这个字的值永远是1
18 00  //每个像素占用的位数
00 00 00 00 //压缩方式
00 0C 30 00 // 3148800的字节大小 这个可通过看文件详细信息得到	
12 0B 00 00  //水平分辨率
12 0B 00 00  //垂直分辨率
00 00 00 00
00 00 00 00

```

形成新的bmp后，得到里面得内容：

`key:PHRACK-BROKENPIC`

和一个不能扫出东西的二维码

现在问题来了，这个key是用来干嘛的，再看看bmp的16进制格式：

```bash
D55F7AB07937BA26B22468328A68C1F2
......
后面好像都一样

```

想到（这个我还真没想到）AES是分组加密，16字节一组，不过目前所学有key的密码貌似也不是很多

尝试AES解密：

```python
#usr/env/python3
#coding=utf-8
#owner: IFpop
#time: 2019/11/5

from Crypto.Cipher import AES

key = "PHRACK-BROKENPIC"
#python3之后加密函数中传入的都是字节形式
key = key.encode("utf-8")
aes = AES.new(key,mode = AES.MODE_ECB) #这是ECB的加密形式，以后这种解密还是使用python不需要指定mode

with open('brokenpic.bmp','rb') as f:
    data = f.read()
    pic = aes.decrypt(data)

with open('ans.bmp','wb') as f:
    f.write(pic)

```

然后也是想之前那样，修复bmp，可以扫码得到`flag:PCTF{AES_i5_W3ak_foR_im4ge}`

## Medium RSA

[RSA-集锦](<https://ifpop.github.io/2019/10/21/RSA-%E9%9B%86%E9%94%A6/#more>)





# Basic

## 握手包

> 给你握手包，flag是Flag_is_here这个AP的密码，自己看着办吧。

下载下来一个cap文件，使用wireshark打开后发现，文件应该使加密过的，网上查一下关于cap的破解知识，发现Kali有个自带工具aircrack-ng，进行字典破解(我这里使用的使kali `/usr/share/wordlists` 目录下的`rockyou.txt`)

```bash
aircrack-ng wifi.cap -w rockyou.txt
#11223344
```

`flag{11223344}`



## 德军的密码

> 已知将一个flag以一种加密形式为使用密钥进行加密，使用密钥WELCOMETOCFF加密后密文为 000000000000000000000000000000000000000000000000000101110000110001000000101000000001 请分析出flag。Flag为12位大写字母

01串的长度为84，题目提示说使12为大写字母，所以将字符串分成12份，每份应该占有7个01串，此时的key正好也右12为，那么无非就是加减乘除异或等运算，尝试发现此时是逐位异或。

```python
#!usr/enc/python3
#coding=utf-8
#owner: IFpop
#time: 2019/11/8

key = "WELCOMETOCFF"
bin_c = "000000000000000000000000000000000000000000000000000101110000110001000000101000000001"
#先将字符串分成七段，然后转换成ASCII，随后与key进行异或
c = ""
for i in range(12):
    temp = bin_c[i*7:(i+1)*7]
    #print(temp)
    temp = int(temp,2)
    c = c + chr(temp)
#print(c)
str_c = ""
for i in range(12):
    str_c += chr(ord(c[i])^ord(key[i]))
print(str_c)
#WELCOMECISRG
```





## -.-字符串

> 请选手观察以下密文并转换成flag形式
>
> ..-. .-.. .- -–. ..... ..--— ..--— -–--— .-–-– --—.. -.. -.... -.... ..... ..…-– --—.. -–..… -.. .-–-– -.. .- -–-–. ..…-– .-–-– --—.. .-–-– ..--— -... -–... -–... -–... -.... ...-– ..….- .-–-– -–--—
>
> flag形式为32位大写md5

这看起来像是莫斯电码，尝试解码：

```txtx
flag522018d665387d1da931812b77763410
```

提示说32位大写的md5，去掉flag就是答案。



## A Piece Of Cake

> nit yqmg mqrqn bxw mtjtm nq rqni fiklvbxu mqrqnl xwg dvmnzxu lqjnyxmt xatwnl, rzn nit uxnntm xmt zlzxuuk mtjtmmtg nq xl rqnl. nitmt vl wq bqwltwlzl qw yivbi exbivwtl pzxuvjk xl mqrqnl rzn nitmt vl atwtmxu xamttetwn xeqwa tsftmnl, xwg nit fzruvb, nixn mqrqnl ntwg nq gq lqet qm xuu qj nit jquuqyvwa: xbbtfn tutbnmqwvb fmqamxeevwa, fmqbtll gxnx qm fiklvbxu ftmbtfnvqwl tutbnmqwvbxuuk, qftmxnt xznqwqeqzluk nq lqet gtamtt, eqdt xmqzwg, qftmxnt fiklvbxu fxmnl qj vnltuj qm fiklvbxu fmqbtlltl, ltwlt xwg exwvfzuxnt nitvm twdvmqwetwn, xwg tsivrvn vwntuuvatwn rtixdvqm - tlftbvxuuk rtixdvqm yivbi evevbl izexwl qm qnitm xwvexul. juxa vl lzrlnvnzntfxllvldtmktxlkkqzaqnvn. buqltuk mtuxntg nq nit bqwbtfn qj x mqrqn vl nit jvtug qj lkwnitnvb rvquqak, yivbi lnzgvtl twnvnvtl yiqlt wxnzmt vl eqmt bqefxmxrut nq rtvwal nixw nq exbivwtl.

这么多字符串一般来说就是替换密码了，先试试比较简单的单表替换密码，[解密](<https://quipqiup.com/>)

```txt
the word ro?ot can refer to ?oth physical ro?ots and virtual software agents, ?ut the latter are usually referred to as ?ots. there is no consensus on which machines ?ualify as ro?ots ?ut there is general agreement among e?perts, and the pu?lic, that ro?ots tend to do some or all of the following: accept electronic programming, process data or physical perceptions electronically, operate autonomously to some degree, move around, operate physical parts of itself or physical processes, sense and manipulate their environment, and e?hi?it intelligent ?ehavior - especially ?ehavior which mimics humans or other animals. flag is su?stitutepassisveryeasyyougotit. closely related to the concept of a ro?ot is the field of synthetic ?iology, which studies entities whose nature is more compara?le to ?eings than to machines.
```

我们很容易可以分析出，r -– b，所以最终的`flag:PCTF{substitutepassisveryeasyyougotit}`



## Shellcode

> 作为一个黑客，怎么能不会使用shellcode?
>
> 这里给你一段shellcode，你能正确使用并最后得到flag吗？

关于shellcode，他是利用漏洞执行代码从而获取shellcode一类程序，它实际就是汇编对应的机器码，但由于机器码大多是不可见字符，所以无法直接显示。

开始以为这个是通过base64加密不可见字符得到的，但发现不能解密，百度发现存在着其他的转码方式[链接](<https://blog.csdn.net/instruder/article/details/6050048>)

使用[工具](<https://github.com/inquisb/shellcodeexec>)

```bash
.\shellcodeexec.x32.exe PYIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJIYIhkmKzyCDq4l4FQyBlrRWEahI1tLKT16Pnk1ftLnkPvwlnkW6fhNkan5pNkgF6XPOR8T5HsCivaN19okQSPlKRLvD6DNk3uelNkpTthRXuQ9znk2jEHLK1Ja0FaXkhcTtBink4tlKUQhnvQYotqo0ylnLMTO0SDEWZahOtMwqhG8kXteksLwTdh1e8aLKsja4uQ8kavLKdLrklK0ZeL7qjKLKUTLKuQM8k9bdvDeL1qiSnR5XVIXTOyjENikrphNnrnVnhlBrzHooKOYoyok93u7tOKCNyHzBBSnguLgTcbyxlNKOYoYoMYaUTHphRL2LupQQ0htsFRTn541x3E2Se5T26PyKK8QLTddJlIZFBvyoSeUTLIkrv0oKy8ORpMmlk7Gl6DBrm8SoyoioyoaxrOqh0XwP1xu1Qw1upBbHrmrED3T34qiKOxQLTdEZOyZCaxQmRxgPUp0hpnPn4srRe8BDSo2PT7axqOCWROpophSYpnSo04u83K72Peu70hBpCsqDpF4qHIMXpLQ429k98aEaJr1BF3Ca3bIozp01IPf0Yof5GxAA
```

弹窗出`flag:PCTF{Begin_4_good_pwnn3r}`



## Help!!

> 出题人硬盘上找到一个神秘的压缩包，里面有个word文档，可是好像加密了呢~让我们一起分析一下吧！

下载一个压缩包，说是加密了，其实是个伪加密，winhex改一下，得到一张图片

开始以为是图片隐写，发现没有藏信息在16进制之中，而且不是LSB隐写，

后来想到word.docx中会不会还有东西，使用`binwalk`分解一下，发现在/word/media中存在着另一张图片，得到flag

![image2](C:/Users/X1TABLET/Desktop/image2.png)

## Baby’s Crack

> 既然是逆向题，我废话就不多说了，自己看着办吧。

下载下来有两个文件，一个exe程序，一个flag.enc程序，题目说是逆向题，所以还是直接使用ida打开看看

查看main函数

```c
 _main(*(_QWORD *)&argc, argv, envp);
  if ( v8 <= 1 )
  {
    printf("Usage: %s [FileName]\n", *v9);
    printf("FileName是待加密的文件");
    exit(1);
  }
  File = fopen(v9[1], "rb+");
  if ( File )
  {
    v5 = fopen("tmp", "wb+");
    while ( feof(File) == 0 )
    {
      v7 = fgetc(File);
      if ( v7 != -1 && v7 )
      {
        //此处是核心代码，对于每个文件中的字符进行下列操作，所以我们只需要逆一下就行
        if ( v7 > 47 && v7 <= 96 )
        {
          v7 += 53;
        }
        else if ( v7 <= 46 )
        {
          v7 += v7 % 11;
        }
        else
        {
          v7 = 61 * (v7 / 61);
        }
        fputc(v7, v5);
      }
    }
    fclose(v5);
    fclose(File);
    sprintf(&Dest, "del %s", v9[1]);
    system(&Dest);
    sprintf(&Dest, "ren tmp %s", v9[1]);
    system(&Dest);
    result = 0;
  }
  else
  {
    printf("无法打开文件%s\n", v9[1]);
    result = -1;
  }
  return result;
```

下面是解题程序：

```python
#!usr/env/python3
#coding=utf-8
#owner: IFpop
#time: 2019/11/12

import string
enc = "jeihjiiklwjnk{ljj{kflghhj{ilk{k{kij{ihlgkfkhkwhhjgly"
m = ""
length = len(enc)
dic = string.printable
tag = 0
for i in range(length):
    for j in dic:
        if ord(j) > 47 and ord(j) <= 96:
            temp = chr(ord(j)+53)
        elif ord(j) <= 46:
            temp = chr(ord(j)+ord(j)%11)
        else:
            temp = chr(61*(ord(j)//61))
        # print(temp)
        if temp == enc[i]:
            print(j)
            m += j
#m = 504354467B596F755F6172335F476F6F645F437261636B33527D
#明文是16进制编码
print(bytes.fromhex(m))
```



## 熟悉的声音

> 两种不同的元素，如果是声音的话，听起来是不是很熟悉呢，据说前不久神盾局某位特工领便当了大家都很惋惜哦
>
> XYYY YXXX XYXX XXY XYY X XYY YX YYXX
>
> 请提交PCTF{你的答案}

特工，声音，密码，这不就是摩斯电码嘛，现在就是需要知道X,Y分别代表什么

```python
#!usr/env/python3
#coding=utf-8

#将两种情况都打印一遍
s = "XYYY YXXX XYXX XXY XYY X XYY YX YYXX"
s = s.replace('X','.')
s = s.replace('Y','-')
print(s)
#.--- -... .-.. ..- .-- . .-- -. --..
s = "XYYY YXXX XYXX XXY XYY X XYY YX YYXX"
s = s.replace('X','-')
s = s.replace('Y','.')
print(s)
#-... .--- -.-- --. -.. - -.. .- ..--
#jbluwewnz
```

发现这也不是个有意义的字符，可能是flag,交上去发现不对，可能还有加密，尝试常用的一些解密方式

凯撒解密，发现这样一个字符串`phrackctf`，交上去发现不对，查询才知道，摩斯电码只能是大写

`PCTF{PHRACKCTF}`

## 取证

> 有一款取证神器如下图所示，可以从内存dump里分析出TureCrypt的密钥，你能找出这款软件的名字吗？名称请全部小写。
>
> ![1573611867291](C:\Users\96552\AppData\Roaming\Typora\typora-user-images\1573611867291.png)
>
> 提交格式：PCTF{软件名字}

搜索内存取证神器，发现一篇[博客](<https://cloud.tencent.com/developer/article/1076631>)，`flag：PCTF{volatility}`



## ROPGadget

> 都说学好汇编是学习PWN的基础，以下有一段ROPGadget的汇编指令序列，请提交其十六进制机器码(大写，不要有空格)
>
> XCHG EAX,ESP
>
> RET
>
> MOV ECX,[EAX]
>
> MOV [EDX],ECX
>
> POP EBX
>
> RET
>
> 提交格式：PCTF{你的答案}

说是要将上述汇编指令转换为机器码，好多种方法，这里我使用一个转换工具，得到`94C38B08890A5BC3`

所以`PCTF{94C38B08890A5BC3}`

## Easy RSA

> 还记得veryeasy RSA吗？是不是不难？那继续来看看这题吧，这题也不难。
>
> 已知一段RSA加密的信息为：0xdc2eeeb2782c且已知加密所用的公钥：
>
> (N=322831561921859 e = 23)
>
> 请解密出明文，提交时请将数字转化为ascii码提交
>
> 比如你解出的明文是0x6162，那么请提交字符串ab
>
> 提交格式:PCTF{明文字符串}

1. 尝试将模数N进行[分解](www.factordb.com)

   得到`p =  13574881  q = 23781539`

2. 下面就可以开始解密

   ```python
   #!usr/env/python3
   #coding=utf-8
   #owner: IFpop
   #time: 2019/11/13
   
   import gmpy2
   from Crypto.Util import number
   p = 13574881
   q = 23781539
   n = p*q
   e = 23
   c = 0xdc2eeeb2782c
   fn = (p-1)*(q-1)
   
   d = gmpy2.invert(e,fn)
   m = pow(c,d,n)
   print(number.long_to_bytes(m))
   #3a5Y
   ```

   所以`PCTF{3a5Y}`



## 爱吃培根的出题人

> 听说你也喜欢吃培根？那我们一起来欣赏一段培根的介绍吧：
>
> bacoN is one of aMerICa’S sWEethEartS. it’s A dARlinG, SuCCulEnt fOoD tHAt PaIRs FlawLE
>
> 什么，不知道要干什么？上面这段巨丑无比的文字，为什么会有大小写呢？你能发现其中的玄机吗？
>
> 提交格式：PCTF{你发现的玄机}

提示很明显是培根密码，但我们知道培根密码是由A,B两个字符组成的特殊隐写方式，题目中说大小写？玄机？

大小写与A，B对应，这样就可以算是培根了，但具体是大写与A还是小写与A还得测试一下

```python
#coding=utf-8
#以维基百科上的为准
dic = {'AAAAA':'a','AAAAB':'b','AAABA':'c','AAABB':'d','AABAA':'e','AABAB':'f',
        'AABBA':'g','AABBB':'h','ABAAA':'i/j','ABAAB':'k','ABABA':'l','ABABB':'m',
        'ABBAA':'n','ABBAB':'o','ABBBA':'p','ABBBB':'q','BAAAA':'r','BAAAB':'s',
        'BAABA':'t','BAABB':'u/v','BABAA':'w','BABAB':'x','BABBA':'y','BABBB':'z'}
    
init = "bacoN is one of aMerICa'S sWEethEartS. it's A dARlinG, SuCCulEnt fOoD tHAt PaIRs FlawLE"
init = init.replace(' ','').replace('.','').replace(',','').replace("'",'')
s1 = ""
s2 = ""
ans1 = []
ans2 = []
for i in init:
    if i.isupper():
        s1 += 'A'
        s2 += 'B'
    else:
        s1 += 'B'
        s2 += 'A'
for i in range(len(s1)//5):
    ans1.append(s1[i*5:i*5+5])
    ans2.append(s2[i*5:i*5+5])
# print(ans1)
print(ans2)
# for i in range(len(ans1)):
#     ans1[i] = dic[ans1[i]]
for i in range(len(ans2)):
    ans2[i] = dic[ans2[i]]
# print(''.join(ans1))
print(''.join(ans2))
#baconi/jsnotfood
```

所以最后应该是`PCTF{baconisnotfood}`

## Secret

> 传说中的签到题
>
> 题目入口：<http://web.jarvisoj.com:32776/>
>
> Hint1: 提交格式PCTF{你发现的秘密}

页面没有信息，那就只有消息头会藏信息了，查看消息头，发现`Welcome_to_phrackCTF_2016`



## Easy Crackme

> 都说逆向挺难的，但是这题挺容易的，反正我不会，大家来挑战一下吧~~:)

使用ida64打开， 找到main函数

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rdi
  char v5; // [rsp+0h] [rbp-38h]
  char v6; // [rsp+1h] [rbp-37h]
  char v7; // [rsp+2h] [rbp-36h]
  char v8; // [rsp+3h] [rbp-35h]
  char v9; // [rsp+4h] [rbp-34h]
  char v10; // [rsp+5h] [rbp-33h]
  unsigned __int8 v11; // [rsp+10h] [rbp-28h]
  _BYTE v12[7]; // [rsp+11h] [rbp-27h]

  v5 = 0xABu;
  v6 = 0xDDu;
  v7 = 0x33;
  v8 = 0x54;
  v9 = 0x35;
  v10 = 0xEFu;
  printf((unsigned __int64)"Input your password:");
  _isoc99_scanf((unsigned __int64)"%s");
  if ( strlen((const char *)&v11) == 26 )
  {
    v3 = 0LL;
    if ( (v11 ^ 0xAB) == list1 )  //list1 0xFB 判断第一位异或的结果
    {
      while ( (v12[v3] ^ (unsigned __int8)*(&v5 + ((signed int)v3 + 1) % 6)) == byte_6B41D1[v3] )  //9E 67 12 4E 9D 98 AB 0 6 46  8A F4 B4 6 0B 43 DC D9 A4 6C 31 74 9C D2 A0   与上面的v5开始的6位数进行异或
      {
        if ( ++v3 == 25 )
        {
          printf((unsigned __int64)"Congratulations!");
          return 0;
        }
      }
    }
  }
  printf((unsigned __int64)"Password Wrong!! Please try again.");
  return 0;
}
```

逻辑还是比较清楚的，现在就直接写脚本：

```python
#coding=utf-8

s = [0x9E,0x67,0x12,0x4E,0x9D,0x98,0xAB,0,0x6,0x46,0x8A,0xF4,0xB4,0x6,0x0B,0x43,0xDC,0xD9,0xA4,0x6C,0x31,0x74,0x9C,0xD2,0xA0]
s2 = [0xAB,0xDD,0x33,0x54,0x35,0xEF]
flag ="P"
j = 0
for i in s:
    flag += chr(i^s2[(j+1)%6])
    j = j+1
print(flag)
#PCTF{r3v3Rse_i5_v3ry_eAsy}
```

## 公倍数

> 请计算1000000000以内3或5的倍数之和。
>
> 如：10以内这样的数有3,5,6,9，和是23
>
> 请提交PCTF{你的答案}

直接爆破，就行~

```python
#coding=utf-8

sum = 0
for i in range(1,1000000000):
    if i%3 == 0 or i%5 == 0:
        sum+=i
print(sum)
```

## 神秘的文件

> 出题人太懒，还是就丢了个文件就走了，你能发现里面的秘密吗？

下载一个文件，将其file一下

```bash
Linux rev 1.0 ext2 filesystem data, UUID=8eecd08f-bae8-41ff-8497-8338f58ad15b
```

是linux的磁盘文件，使用binwalk 查看文件，看是否可以分离，随后就产生了256个文件，使用winhex打开查看，每个文件中仅有一个字符，所以256个文件连起来应该是我们需要的信息，下面写个脚本处理一下

```python
#!usr/env/python
#owner: IFpop
#time: 2019/11/14
#coding=utf-8

ans =""
for i in range(253):
    with open(str(i),'rb') as f:
        ans += f.read()
print(ans)
```

得到：

```txt
Haha ext2 file system is easy, and I know you can easily decompress of it and find the content in it.But the content is spilted in pieces can you make the pieces together. Now this is the flag PCTF{P13c3_7oghter_i7}. The rest is up to you. Cheer up, boy
```

## veryeasyRSA

> 已知RSA公钥生成参数：
>
> p = 3487583947589437589237958723892346254777 q = 8767867843568934765983476584376578389
>
> e = 65537
>
> 求d = 
>
> 请提交PCTF{d}

直接解就行：

```python
#coding=utf-8

import gmpy2
p = 3487583947589437589237958723892346254777 
q = 8767867843568934765983476584376578389
e = 65537
fn = (p-1)*(q-1)
d = gmpy2.invert(e,fn)
print(d)
#19178568796155560423675975774142829153827883709027717723363077606260717434369
```

## 美丽的实验室logo

> ​	出题人丢下个logo就走了，大家自己看着办吧

下载下来一个jpg，使用binwalk啥的也没有发现藏有神秘东西，可能是LSB，使用stegsolve打开，

使用Frame browser拿到flag

## 手贱

> 某天A君的网站被日，管理员密码被改，死活登不上，去数据库一看，啥，这密码md5不是和原来一样吗？为啥登不上咧？
>
> d78b6f302l25cdc811adfe8d4e7c9fd34
>
> 请提交PCTF{原来的管理员密码}

看了半天，不知道问题在哪。。后来才知道这里的md5的长度是33位，有一位是多出来的，遍历一下，逐个解就行

## 段子

> 程序猿圈子里有个非常著名的段子：
>
> 手持两把锟斤拷，口中疾呼烫烫烫。
>
> 请提交其中“锟斤拷”的十六进制编码。(大写)
>
> FLAG: PCTF{你的答案}

用python转一下就行，

```python
s='锟斤拷'.decode('utf-8').encode('gbk').encode('hex')
print s.upper()
```

## veryeasy

> 使用基本命令获取flag

strings一下即可得到flag

## 关于USS	lab

> USS的英文全称是什么，请全部小写并使用下划线连接_，并在外面加上PCTF{}之后提交

百度一下即可，`PCTF{ubiquitous_system_security}`

## base64?

> GUYDIMZVGQ2DMN3CGRQTONJXGM3TINLGG42DGMZXGM3TINLGGY4DGNBXGYZTGNLGGY3DGNBWMU3WI===

特征很明显是base32，解密：`504354467b4a7573745f743373745f683476335f66346e7d`

好像是16进制，转一下：`PCTF{Just_t3st_h4v3_f4n}`