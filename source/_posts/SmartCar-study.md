---
title: SmartCar-study
date: 2019-10-25 00:08:32
tags:
- SmartCar
- IAR
- openmv
- daily_record
categories:
- Study
---

这是一位不成器的计算机选手开始挑战跨专业的探测信标的~~智障车~~智能车🔞



# 2019/10/22

练习如何焊接电路板，成就：成功焊坏一个芯片，貌似是车队最后一个 😆

# 2019/10/23

看完`IAR`使用手册，熟悉`IAR`的实际操作😁

> 工程相关源文件的树型结构，可分为“工程配置文件”，“源程序文件”，“机器码文件”
>
> 1. “工程配置文件”包含的文件与芯片及工程初始化相关，包含链接文件与启动代码文件。启动代码文件“`crt0.s`”与“`start.c`”，“链接文件”包括`Pflash.icf`与`Ram.icf`两个文件，通过修改它们可以将可执行代码链接到芯片RAM中或Flash中
> 2. ”源程序文件夹“包括C语言程序、头文件，C语言程序一般包括构件C文件夹”Component_C“、框架C文件夹”Frame_C“、中断服务例程源文件`isr`与主程序源文件`main`，头文件一般包括`include.h`、构件头文件”Component_H”,框架C文件夹“Frame_H”。系统启动并初始化后，程序先执行配置文件的启动代码文件，随后根据`main`中定义的逻辑顺序执行，当遇到中断请求时，转而执行`isr.c`中定义的相应中断处理程序；中断结束，则返回中断出继续顺序执行。与总体有关的架构程序相关的头文件和源文件分别放在了`Frmae_H`和`Frame_C`文件夹中，其中`Frame_H`一般会有`common.h`、`system_SKEAZ1284.h`、`sysinit.h`、`vectors.h`等头文件，`system_SKEAZ1284.h`时芯片寄存器及相关定义头文件，它被视为芯片的接口文件，`sysinit.h`与`sysinit.c`(存在于`Frame_C`中)一起完成系统初始化，系统时钟等，而`common.c`与`common.h`一起完成一些基本函数
> 3. “机器码文件”包括`.out`文件和`.map`文件，写到`Flash`中的文件为`.out`文件

# 2019/10/24

今天把`kea128code`中的common部分函数，梳理了一下有哪些函数以及函数的用途👀





| 文件名称    | 文件功能                                                     |
| ----------- | ------------------------------------------------------------ |
| assert.c    | 包含assert_failed函数，用于在出错的时候进行报错              |
| assert.h    | 包含assert中函数说明，定义了DEBUG_PRINT                      |
| common.h    | 这里是一个公用的头文件，集合了`CPU header file，platform specific header file，toolchain specfic header filescommon utilities` |
| `io.c`      | in_char(从端口捕获输入)，out_char(将信息输出至指定端口)，char_present(貌似是返回目前端口的字符串，感觉in_char就够用了，不知道这个干嘛的） |
| `io.h`      | 将`io.c`中的函数定义                                         |
| `memtest.c` | 包含memTestDataBus，memTestAddressBus，memTestDevice三个函数，分别测试数据总线，地址总线和硬件设备 |
| `memtest.h` | 定义`memtest.c`的函数以及数据格式                            |
| `printf.c`  |                                                              |
| `queue.c`   | 由于C语言并没有队列、栈等数据结构，所以在C语言编写中需要自己写，这里自己定义了一些队列必须的函数，`queue_init`初始化了队列，`queue_isempty`判断队列是否为空，`queue_add`向队列中添加新元素，`queue_remove`删除队列中的元素，`queue_peek`获取队列第一个元素，`queue_move`整体队列迁移(这个函数倒是比较好玩，C++中queue库中貌似没有) |
| `queue.h`   | 里面包含队列结构体的定义，头结点和尾结点，然后还有函数定义，这个队列应该是可以直接用的(目测比较完好) |
| `startup.c` | 里面有个`pragma`，是程序预处理指令，但跟我之前了解的不太一样，点[这里](https://zhidao.baidu.com/question/1381870523902781300.html)查看详情。所以`__section_begin`获取这个段的首地址，`__section_end`获取这个段的尾地址。嗯？到现在还是没太看懂`common_startup`的具体实现，我的理解是他初始化程序的时候建立了一个虚拟的类似于操作系统的那部分，将ROM中存储的信息存入到RAM中，然后便于与内存建立交互。然后具体过程其实挺懵的，就是通过linker获得变长table以及变长RAM的地址，然后将table中的值赋给RAM,然后`wirte_vtor(函数定义在cpu中的arm_cm0.h中)`说是将指针指向一个新的复制的table，但里面的具体的程序也没看懂，接着看，获取了ROM的地址和`data_ram`的地址，然后将rom中的值开始赋值给`data_ram`了（我想问这里面还没有东西吧？？？），总之，这部分需要去问学长！！！ |
| `startup.h` | 就简单定义了`common_startup`这个函数                         |
| `stdlib.h`  | 一个C语言的库，这个不自带？？                                |
| typedef.h   | 自定义库，就是了一些数据结构的简写                           |
| `uif.c`     |                                                              |
| `uif.h`     | 定义了`uif.c`中的函数原型，同时定义了最大指令长度为10        |



# 2019/10/25

`config files`存在着`flash`和`RAM`的配置信息

`cpu`文件夹中相关函数信息

| 文件名               | 文件功能                                                     |
| -------------------- | ------------------------------------------------------------ |
| `arm_cm0.c`          | 定义了`stop`，`wait`，`write_vtor`函数，`stop`是该进程进入了`deepsleep`，`wait`是从`deepsleep`状态苏醒至`sleep`会改变状态编码，`wirte_vtor`将矢量表偏移寄存器的值更改为指定值，被`startup`调用 |
| `arm_cm0.h`          | 使用`#undef`取消系统对关键字的定义转而自己进行`#define`,使用`asm`进行汇编指令定义与使用，其中`asm(" CPSIE i")`是允许全能中断，`asm(" CPSID i")`是禁止全能中断，关键在单词末尾的’E’与’D’分别是enable和disable |
| `crt0.s`             | 汇编代码文件，这是程序运行的开始（先于main函数），实际上的程序在汇编里面也会有这样一段代码，主要用途是将寄存器清零 |
| `isr.h`              | 中断服务例程源文件`isr.h`,具体实现过程其实没咋弄懂，还是问问学长 |
| `start.c`            | 启动代码文件,[为什么要禁用看门狗](http://www.sohu.com/a/122050439_505888)，这里的`cpu_identify`和`flash_identify`是需要自己去写的，`SystemInit`这里也是禁用看门狗，但是不太明白的是为什么要禁用两次 |
| `start.h`            | 定义`start.c`中函数的头文件                                  |
| `sysinit.c`          | 初始化系统，包括`sim、ics、uart`等,现在其实还没怎么建立起`SIM通信`以及`ICS和UART`怎么使用的概念 |
| `sysinit.h`          | 定义了`sysinit.c`中的函数                                    |
| `system_SKEAZ1284.h` | `system_SKEAZ1284.h`时芯片寄存器及相关定义头文件，它被视为芯片的接口文件 |

人傻了，这东西也太错综复杂，本来想着一周速成单片机，看来有点困难。。😭

还是接着看吧

`drives`文件

|       文件名 | 文件功能                                                     |
| -----------: | ------------------------------------------------------------ |
|     `acmp.h` | 这里我查到的是`Analog Comparator`，即模拟比较器，然后其中还定义了一些有关`DAC`函数，用于`DAC`转换？仔细研究的话还是得要慢慢看 |
|      `adc.c` | 首先，这个不是`moba`游戏，没有`ADC`选手，[ADC模块](<http://bbs.elecfans.com/jishu_1812180_1_1.html>)， 基本信息就是可以将连续的信号转换称数字信号，然后其中对每次处理的数字信号进行求和，之后求平均，达到了减少信息的失真率 |
|      `adc.h` | 定义了关于ADC模块的一些配置信息，如`adc_ref_list`(适用电压范围)，`ADC clock source`(ADC时钟来源)，`ADC divider`(ADC中会按几位非分配)以及`ADC mode`(有`8，10，12bit`)的选择，但是什么情况选择什么样子的模式，这里应该怎么去控制也不太清楚 |
| `bit_band.h` | 位带的头文件，[位带详情](http://news.eeworld.com.cn/mcu/article_2016061326941.html),可以使用普通的加载/存储指令来对单一的比特进行读写 |
|      `BME.h` | [`BME`](https://community.nxp.com/docs/DOC-98798) 是`Bit Manipulation Engine`，位操作引擎功能，是`M0+`上的一个集成模块 |
|      `crc.c` | `CRC`(循环冗余校验,Cyclic redundancy check)，这是一种通过除法运算来建立有效信息位和校验位之间的约定关系的，也就是用来确定信息传输是否正确，减少的误码的产生 |
|    `flash.c` | 一个闪存驱动程序                                             |
|    `flash.h` | 定义有关`flash`的配置，以及一些函数                          |
|      `ftm.c` | ftm定时器，[详情](<https://max.book118.com/html/2017/1006/136242796.shtm>) |
|      `ftm.h` | 定义ftm必须的函数                                            |
| `gpio_icf.h` | 定义了`gpio`的配置文件，如输入输出端口信息以及寄存器信息，[详情](<https://wenku.baidu.com/view/ca7f65020029bd64793e2c48.html>) |
|     `gpio.c` | 实现了通用输入输出的必要函数                                 |
|     `gpio.h` | 定义了`gpio`的函数                                           |



# 2019/10/26

今天还是接着函数，发现个[中文文档](<http://www.doc88.com/p-1344840862773.html>)



# 2019/10/30

现在稍微整理一下例程文件大概内容

| 文件名字              | 文件功能                              |
| --------------------- | ------------------------------------- |
| 8700_2100.c           |                                       |
| fun.c                 |                                       |
| isr.c                 | 定义串口中断、定时器中断、KBI中断     |
| LQ12864.c             | 里面有着与LCD有关的函数，应该是显示的 |
| LQKEY.c               | 关于按键的控制，key是按键，key1是拨码 |
| LQLED.c               | 控制信号灯的函数                      |
| main.c                | 函数的入口点                          |
| MPU6050.c与MPU9250.c  | 是两种不同的微处理器，具体区别不清    |
| MPUIIC.c              | 是微处理器的通信函数                  |
| Serial_oscilloscope.c | 发送数据到上位机                      |

# 2019/10/31

现在大致有了一个关于`main`函数的思路：

```c
void main(void)
{  
  DisableInterrupts ;   //禁止中断，这里是防止其他程序在运行是抢占CPU资源,为了方便程序初始化
  //获取时钟频率
  //这里进行初始化
  //LCD初始化
  //adc初始化
  //gpio初始化，拨码和九轴传感器
  //定时中断初始化PIT

  //需要初始化蓝牙串口
  //需要初始化OLED
  //需要初始化编码器
  //FTM_count_clean()清除计数值
  //需要初始化舵机
  //需要初始化电机
  EnableInterrupts;     //开启总中断，现在中断恢复，其他程序可以正常运行
  
  while(1){
      //接收蓝牙模块的控制
      //接收app发送的速度与方向值，分别控制舵机与电机
  }
}
```

先学了一下关于`pwm`（脉冲调制）的知识，emmm,又是没有收获的一天



# 2019/11/2

今天由于比赛原因没能参加今天的培训，晚上正好把ppt上的内容学习一下

1. 关于推挽输出和开漏输出，这篇[博客](<https://www.jianshu.com/p/d0f5aad20ee7>)讲的很好了

一个小问题——就是三极管开关闭合机制是啥，输入0？截止？或者是我们自己控制的？

2. 之前讲过编码器原理？



# 2019/11/7

关于如何控制舵机的问题：

> - https://www.cnblogs.com/zhoubatuo/p/6138033.html
>
> - https://blog.csdn.net/qq_36192043/article/details/80812947

`PWM`意为脉冲宽度调制，可用于调整输出直流平均电压，对于矩形波而言，输出平均压等于峰值电压×占空比，占空比是一个脉冲周期内高电平时间与周期的比值，例如，峰值电压等于`5V`，占空比等于50%的方波信号平均电压等于`2.5V`，也就是万用表直流档测量得到的电压值



关于`pwm`波对舵机与电机的控制：

1. 首先,关于舵机，先初始化`pwm`波，以一个定值频率和占空比告诉舵机这是此时状态的`pwm`波，之后对`pwm`波赋值的方式是改变占空比，也就是此时高电平的持续时间，但对于角度方面处理尚不清楚(我的理解是与初始值的相对值就是偏转角度)，我想我们应该用的是180度舵机吧？

   中位需要自己调

2. 其次，关于电机，同样初始`pwm`，确定初始状态，也就是初始转速?但我想这开始启动的时候车不是应该不动嘛？这里占空比为啥不设为0。

   这里就是0

现在需要解决的问题是`motor`控制和`serov`控制函数应该怎么去写，貌似需要用到`PID`控制,然后就是什么是开环启动什么是闭环启动

- 开环控制：

  > 开环控制就是没有反馈系统的控制，比如使用调光台灯，旋钮调节到哪里就是那里，感觉不对可以再次调节一下

- 闭环控制：

  > 一般友人们设定目标，由电路自己检测电路实行反馈检测数据。达到跟踪设定的操作过程就叫做闭环控制



# 2019/11/10

昨天下午5个小时，用来检测驱动板的电路问题(而且不能升压至12V）开始是一直短路的，看完其他小组的板子才发现，芯片以及钽电容是有方向的，emmm，由于这块板子已经被折磨的不成人样了，所以最终决定重新焊，又花了一个小时，我们重新焊好了驱动板，好了，现在可以得到12V的电压，但是问题又来了，主控板上的双排母又出现接触不良的现象，所以之后在进行之后的检测吧（溜...毕竟我不是搞电路的，甩锅...)



# 2019/11/11

昨天问了学长很多问题，现在在这总结一下，以便方便我后面的任务的进行

+ 首先整理一下app的输出：

  ```java
  //手动控制
  byte_buffer.write((byte) 0xc1);
  byte_buffer.write(Integer.toString(direction).getBytes());
  byte_buffer.write((byte) 32);//' '
  byte_buffer.write(Integer.toString(speed).getBytes());
  byte_buffer.write((byte) 0);
  
  //遥杆控制
  byte_buffer.write((byte) 0xc3);
  byte_buffer.write(Float.toString(x).getBytes());
  byte_buffer.write((byte) 32);//' '
  byte_buffer.write(Float.toString(y).getBytes());
  byte_buffer.write((byte) 32);//' '
  byte_buffer.write(Integer.toString(speed).getBytes());
  byte_buffer.write((byte) 0);
  ```

  

- `uart`与蓝牙接收的问题

  `uart`只能一个字节一个字节地接收，需要设置起始字节和结束字节,然后需要写一个中断函数`UART2_buleteeth_ISR`,具体如下：

  ```c
  //接收蓝牙信息
  void UART2_buleteeth_ISR(void)
  {
  	//使用static是为了在传输一道指令时只初始化一次
  	static uint8_t buffer[128]; //记录信息
  	static uint8_t control_type = 0;  //记录模式类型
  	static bool receive_start_flag = false; //标记一次传送是否完成
      static uint8_t *ptr = 0;
  
  	DisableInterrupts;//关总中断
  	//从通道中获取一个字节
  	uint8_t  data = Uart_GetChar(UARTR2);
  	if (data == 0xc1 || data == 0xc3) //一共会有两种模式
  	{
  		ptr = buffer;
          receive_start_flag =1;
  		control_type = data;
  	}
  	else if (data == '\0')
  	{
  		*ptr = '\0';
  		ptr = buffer;
  		if (receive_start_flag == 1)
  		{
  			receive_start_flag = 0;
  			Test(control_type, buffer); //接收之后的处理
  		}
  		else
  		{
  			*ptr = data;
  			++ptr;
  		}
  	}
  	EnableInterrupts;   //开总中断
  }
  ```

  之后进入`Test`程序中进行处理

  ```c
  void Test(uint8_t control_type,uint8_t* buffer)
  {
  	//首先应该是通过蓝牙连接
  	//根据0xc1和0xc3来区别手动和矢量
  	//如果是矢量就获取x,y方向的矢量信息和速度
  	//如果是手动控制就获取控制码以及速度
  	//这里会使用uart接收字符串但具体尚不清楚,接收到字符串后对其进行处理，判断前面的0xc1或0xc3对control_type进行赋值
  	//control_type  控制类型
  	//cmd 操作码
  	//speed 速度
  	//vec_x  x方向向量 double
  	//vec_y  y方向向量 double
  	//手动控制模式
  	int speed;
  	if (control_type == 0xc1)
  	{
  		//首先会对接收到的字符串进行操作获取cmd,speed等信息
  		//先确定相应模式
  		int cmd;
  		//从内存中读出字符串
  		sscanf((const char*)buffer, "%d %d", &cmd, &speed);
  		switch(cmd)
  		{
  			//停车
  			case 0:
  			//将两个电机的Pwm波全部置为0
  			FTM_PWM_Duty(CFTM2, FTM_CH0, 0);
  			FTM_PWM_Duty(CFTM2, FTM_CH2, 0);
  			break;
  
  			//切回找灯模式
  			case 1:
  			//这里暂且待定,可能需要摄像头？
  			break;
  
  			//后退
  			case 2:    
  			//将控制电机转向的io输出全部变成反转
  			gpio_init(PTE3, 1, 0);//电机左反转
  			gpio_init(PTI3, 1, 1);
  			gpio_init(PTE1, 1, 0);//电机右反转
  			gpio_init(PTG7, 1, 1);
  			break;
  
  			//左行
  			case 4:
  			//将舵机的方向转为左边,这里的duty需要调正一下，具体数值我也不太清楚
  			FTM_PWM_Duty(CFTM1, FTM_CH1, 100);
  			break;
                          
  			//右行
  			case 6:
  			//同上，duty需要测试
  			FTM_PWM_Duty(CFTM1, FTM_CH1, 400);
  
  			//顺时针
  			//这里采取的策略和右转是一样的，只是此时的是一直保持右转
  			case 7:	
  			break;
  
  			//前进
  			case 8:
  			//这里就是初始化的pwm，但是可能对于不同电机这个值可能不太一样，需要调整
  			gpio_init(PTE3, 1, 1);//电机左正转
  			gpio_init(PTI3, 1, 0);
  			gpio_init(PTE1, 1, 1);//电机右正转
  			gpio_init(PTG7, 1, 0);
  
  			//逆时针
  			case 9:
  			//同7 
  				break;
  		default: break;
  	}
  	
  }	
  	//现在是矢量控制
  	//矢量控制模式
  	else if (control_type == 0xc3)
  	{
  		double vec_y;
  		double vec_x;
  		sscanf((const char*)buffer, "%lf %lf %d", &vec_x, &vec_y,&speed);
  		//首先会对字符串进行操作，获取矢量信息和速度
  		//按照vec_y坐标进行分段
  		//如果vec_y>0，则代表前进方向
  		if (vec_y > 0)
  		{
  			gpio_init(PTE3, 1, 1);//电机左正转
  			gpio_init(PTI3, 1, 0);
  			gpio_init(PTE1, 1, 1);//电机右正转
  			gpio_init(PTG7, 1, 0);
  			//关于角度其实可能进行模糊处理，分成三层30，60，90，判断更靠近那个段，然后直接进行相应赋值
  		}
  		else if (vec_y < 0)
  		{
  			gpio_init(PTE3, 1, 0);//电机左反转
  			gpio_init(PTI3, 1, 1);
  			gpio_init(PTE1, 1, 0);//电机右反转
  			gpio_init(PTG7, 1, 1);
  			//偏向判断跟前进差不多
  		}
  		else if (vec_y == 0)
  		{
  			//现在就只有两个方向，左或者右
  			//右
  			if (vec_x >= 0)
  			{
  				FTM_PWM_Duty(CFTM1, FTM_CH1, 400);
  			}
  			//左
  			else {
  				FTM_PWM_Duty(CFTM1, FTM_CH1, 100);
  			}
  		}
  	}
  	
  	//不管是那种控制最后对速度的赋值方式都是一样的,app可发送的最大速度为10240
  	//计算当前速度占空比
  	double dspeed = speed * 1.0 * 1000 / 10240;
  	//两个电机输出pwm波
  	FTM_PWM_Duty(CFTM2, FTM_CH0, dspeed);
  	FTM_PWM_Duty(CFTM2, FTM_CH2, dspeed);
  }
  ```




# 2019/11/14

今天晚上想去试试串口调试，但是在执行过程中还是遇到诸多问题

+ 首先，串口调试程序那个文档中提到`H05`是主从一体，`H06`是主机和从机分开，关于蓝牙的判别上，上面也没有进行标记。。

+ 然后，测试逻辑，开始我们想的是，使用UART2通道默认引脚，所以按照这个注释上的应该是与单片机上的`RX`与`D6`相连，`TX`与`D7`相连，但是学长说了`rx`连`tx`，就不太明白是啥意思。

  ```python
  '''
           串口号   默认引脚            重映射引脚
          UART0:  RX--B0 ；TX--B1     PTA3 TX ,PTA2 RX
          UART1:  RX--C6 ；TX--C7     PTF3 TX ,PTF2 RX
          UART2:  RX--D6 ；TX--D7     PTI1 TX ,PTI0 RX 
  '''
  ```

+ 上述也就是直接将蓝牙与单片机连起来，然后`app`直接发送给车，但是我们目前还没有到达这一步，我们想先从电脑上能不能得到`app`发送的消息，或者是蓝牙连上单片机上之后我们要怎么调试（知道）程序的运行过程。想着这部分应该是串口调试程序完成的。所以现在关于串口程序的界面问题又有一些问题

  这张图中端口是默认的`COM2`，然后波特率是干啥用的其实也不太明确。

  > 尝试自己解决，看看这篇[博客](https://blog.csdn.net/dok12/article/details/80152239)。
  >
  > 串口其实就是传输的端口，波特率是发送频率来着，貌似跟速度有关，波特率越大，传输的频率越快

+ 然后就是关于上次那个`app`，界面如下：

  发现一个奇怪的问题，就是手动控制的按钮不点，摇杆也是不能动的，然后关于那个send窗口是干什么的也不太清楚

  > 这部分是为了防止误触而设置的。



# 2019/11/17

简单进行了蓝牙测试，使用`H06`和`ch340`连接，可以得到手机`app`传出的参数。但是可能也遇到了一些问题，在和小车相连时只能发送转向信号，由于现在还是不知道怎么在程序内部进行调试，所以这部分目前还是不知道怎么处理。

现在可以进行简单的转向操作，或者进行转向。

不过，在学长以及网上资源的帮助下，终于实现了蓝牙控制。

# 2019/11/18

简单学一下[`openmv`](<https://book.openmv.cc/>)



# 2019/11/24

今天大概做了这么一些事情：

- 对摄像头进行调参，主要是曝光率，使其能够设别到对角的红灯

- 对蓝牙控制进行简单删减，并实现转圈(转圈其实就是一个电机正转，一个电机反转）

- 实现简单摄像头找灯

  > 思路如下：
  >
  > 1. 当找不到灯时，就转圈
  > 2. 如果找到灯，通过x,w判断方向，调整舵机进行偏转。
  > 3. 到达灯附近`60-70cm`时(通过w,h的值进行判断)，给电机一个偏向然后保持不动。



# 2019/11/26

今天去地下室调车时，车突然出现一顿一顿的问题，蓝牙连接也不太稳定。。测试1个小时都不知道怎么回事。。就当其是电路问题吧。。明天让负责电路的同学进行测试。

# 2019/11/27

结果出现了，电路是没有问题的，电池电压低于`7.2V`就不能正常工作。。`emmm`，真的人傻了

# 2019/11/28

今天做了以下事项：

- 测试了拨码的功能。

- 编码器

  ```c
  //初始化编码      
  ftm_count_init(ftm0);   //对E0引脚输入的脉冲进行计数    E0接编码器LSB   
  gpio_init(H7,GPI,0);    //用于判断方向                C5接编码器DIR   
  ftm_count_init(ftm1);   //对E7引脚输入的脉冲进行计数    E7接编码器LSB
  gpio_init(H5,GPI,0);    //用于判断方向                  H5接编码器DIR
  ```

  

- 弄清`pwm`波初始化以及输出过程，由于编码器后续可能需要占用两个`ftm`模块，所以需要将舵机这个模块给空出来，使用定时中断进行控制(具体过程尚不清楚)

  > 看看关于这篇[详解](<https://blog.csdn.net/u014183377/article/details/41091927>),虽然是kea60，但思路差不多

# 2019/11/29

最近想要实现使用拨码控制是蓝牙控制或摄像头控制。但也遇到了几处问题。就拨码开关打开的话，应该是会给单片机一个高电平。然后发现里面拨码对应的引脚只有四个（注释里面写的四个，分别对应拨码开关编号2，4，6，8）

```c
//按照之前所说，那应该是我打开第二个拨码
if (KEY1_Read(KEY0))
{
    //打开摄像头中断
    uart_enable_re_int(UARTR1);
    //让单片机亮灯2
    LED_Ctrl(LED2, LEDON);
}
else
{
    //否则关闭摄像头中断
    uart_disable_re_int(UARTR1);
    LED_Ctrl(LED3, LEDON);
}

```

明天去测试一下是否可行



# 2019/12/1

今日计划：

- [x] 了解如何通过其他替换`ftm`输出`pwm`给舵机的方案
- [x] 晚上去地下车，测试一下摄像头能否正常工作
- [x] 将车的前部给固定一下，顺便对摄像头调参，固定摄像头。



# 2019/12/14

现存问题及预估解决方案

+ 摄像头角度需调整，调整好以后固定死
+ 杜邦线连接稳定性（今天测车过程中舵机pwm控制线被撞掉导致原地转圈）
+ 电机过烫（加入速度闭环控制）
+ 到达预定区域后偏向，避免撞上灯柱，但现在问题是偏向后车并没有把灯灭掉，需第二次进行灭灯，此时车会直接撞向灯柱，须进一步细调



# 2019/12/16

分析学长代码

1. 关于如何适用当定时器产生`pwm`波

   > #include "fsl_ftm.h"  找到这个文件

