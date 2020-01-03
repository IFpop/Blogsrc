---
title: Sudoku_Study_daily
date: 2020-01-03 14:31:45
tags:
- python
- Daily
categories:
- Homework
- study
---

# 2019/12/16

今天开始启动了软件工程大作业的工作，大概做了如下：

- 创建一个`github`仓库`Soduku`(这里貌似打错了，本来是`Sudoku`，但由于已经交给老师的仓库链接是之前的那个，也就没有进行更改了)

+ 预计需消耗时间，撰写`PSP`表格部分内容

+ 搭建项目内容的博客框架，参考如下网站

  `https://blog.csdn.net/Pan_Quixote/article/details/84678996`

+ 收集数独生成终局的资料，大概查阅如下网站：

  ```txt
  https://www.cnblogs.com/BIT1120161931/p/8618878.html
  https://blog.csdn.net/Pan_Quixote/article/details/84678996
  ```

  **`ps`:此时没有在创建博客，所以相关内容暂且写到本地文件上**

# 2019/12/19

+ 选取一个合适的算法——数列法，并分析其可行性

+ 使用`python`语言完成编写

+ 思路大致如下：

  ```python
  # sudoku_generate.py
  # 先确定左上角的数字为5
  # 由所述算法可知 对每一行的一位操作变换是基于0,3,6 ,1,4,7, 2,5,8(此处首位应该保持不变为0)
  # 对于每一种全排列都有30种终局
  # 由于每种排列需要生成30种终局，提前将变化方式记录如下 
  move_way = (
      '''
      这里省略30变换方式，可见github仓库源代码文件
      '''
  )
  '''
  将生成终局的类命名为create_sudoku,对其进行包装
  '''
  class create_sudoku:
      def __init__(self, num):
          '''
          初始化各种类
          '''
      def create_sudoku(self):
           '''
           1. 得到一个全排列
           2. 通过全排列进行30种变换
           3. 再得到全排列，返回1，直到创建了足够数量数独
           '''
      
      def nextPermutation(self, nums):
          '''
          通过回溯法，求解全排列
          '''
      def write2file(self):
          '''
          将数独写入文件
          '''
           
  ```

# 2019/12/20

+ 建立主控函数`sudoku.py`，代码详情见`github`仓库

  ```python
  #coding=utf-8
  #owner: IFpop
  #time: 2019/12/20
  
  import sudoku_generate
  from copy import deepcopy
  import sys
  import time
  
  def main():
      try:
          cmd = sys.argv[1]
          print("cmd:"+cmd)
          # 如果是-c的话。就执行create
          if cmd[1] == 'c':
              '''
              生成数独
              '''
          elif cmd[1] == 's':
              '''
              解数独
              '''
  
      except ValueError:
          print("please input correct number")
      except IOError:
          print("Error: Not find or open failed!")
  
  main()
  ```

+ 使用命令对其进行测试

  ```bash
  python suoku.py -c 1000000
  
  running time is 30.9375 
  ```

  效果并不是特别理想。此时没有进行性能分析，之后和解数独一起进行分析

# 2019/12/21

- 创建一个博客

- 将之前所写的本地内容填到其中

  

# 2019/12/24

# 2020/1/2

+ GUI设计

  + GUI环境搭建

    ```python
    # Requirement
    pyqt5
    pyqt5-tools
    opencv-python
    ```

  + 此处省略若干操作(随后补充环境搭建过程以及GUI设计思路)

# 2020/1/3

+ GUI代码编写

  在写这部分内容过程中，是将之间的solve以及generate作为接口进行调用，但是由于之前使用`cython`，发现并不能调用模块下的变量，所以暂且使用之间最开始的python版本进行编写这部分内容，随后进行对应优化。

  ```python
  '''
  
  '''
  ```

  