---
title: HDU_Problem_exercise
date: 2019-10-14 21:14:51
tags: 
- HDU
categories: 算法
mathjax: true
---

又开始捡起自己的算法练习篇~~

# 1006 [ Tick and Tick](http://acm.hdu.edu.cn/showproblem.php?pid=1006)

**Problem Description**

```txt
The three hands of the clock are rotating every second and meeting each other many times everyday. Finally, they get bored of this and each of them would like to stay away from the other two. A hand is happy if it is at least D degrees from any of the rest. You are to calculate how much time in a day that all the hands are happy.
```

**Input**

```txt
The input contains many test cases. Each of them has a single line with a real number D between 0 and 120, inclusively. The input is terminated with a D of -1.
```

**Output**

```txt
For each D, print in a single line the percentage of time in a day that all of the hands are happy, accurate up to 3 decimal places.
```

**Sample Input**

```
0
120
90
-1
```

**Sample Output**

```
100.000
0.000
6.251
```



**题意：** 时钟的三个指针，在他们之间的角度大于D度时，可以认为是happy，求一天中的happy时间占的百分比

**分析：**由于12小时后，时针、分针、看到这个首先想到的追击与相遇问题，我们可以将时、分、秒针的速度统一单位，然后可以求出相对速度。得到相对速度之后单独对两个针分析(由于是三个角度都需要大于D)，由此得到两针相差一度所需要的时间，那么最晚达到D度和最早结束D度之间的区间时间就是`happy-time`，然后就考虑周期的问题，但最早结束的应该转到下一个满足条件状态（加上一个周期)。最后记得我们是勇12小时来计算的，即43200s

**代码**

```c++
#include<stdio.h>

double max(double a,double b,double c){
	return a>b?(a>c?a:c):(b>c?b:c);
}
double min(double a,double b,double c){
	return a<b?(a<c?a:c):(b<c?b:c);
}

int main()
{
	double d; //需要间隔的度数
	double c_sm = 3600*1.0/59; 
	double c_sh = 43200*1.0/719;
	double c_mh = 43200*1.0/11; //这三行是时针、分针、秒针相遇的周期
	double sum;
	double happys,happye; //开始happy和结束happy
	double sm = 10*1.0/59;
	double sh = 120*1.0/719;
	double mh = 120*1.0/11;  //这是相差一度需要的时间
	double d_sm,d_sh,d_mh,not_d_sm,not_d_sh,not_d_mh;//表示相差d°及以上的时刻和不再相差d°及以上的时刻
	
	while(~scanf("%lf",&d)&&d!=-1){
		sum = 0;
		d_sm=sm*d; not_d_sm=c_sm-d_sm;
        d_sh=sh*d; not_d_sh=c_sh-d_sh;
        d_mh=mh*d; not_d_mh=c_mh-d_mh;
        
        happys=max(d_sm,d_sh,d_mh);
        happye=min(not_d_sm,not_d_sh,not_d_mh);  //happy区间应该选择最晚开始的和最早结束的
		while(happys<=43200&&happye<=43200)//43200是时针针转一圈的秒数
        {
            happys=max(d_sm,d_sh,d_mh);//两两之间最后一个满足相差d°及以上的条件视为开始happy时刻
            happye=min(not_d_sm,not_d_sh,not_d_mh);//两两之间第一个不再满足相差d°及以上视为结束happy的时刻

            if(happys<happye)
                sum+=happye-happys;//如果end的时间比start的晚,由sum记录并累积

            if(happye==not_d_sm)
            {d_sm+=c_sm;not_d_sm+=c_sm;}
            else if(happye==not_d_sh)
            {d_sh+=c_sh;not_d_sh+=c_sh;}
            else if(happye==not_d_mh)
            {d_mh+=c_mh;not_d_mh+=c_mh;}//happy时间end后最慢的指针要提前一个周期才能让比它快的再次追上
        }
        printf("%.3lf\n",sum/43200*100); 
	}		
	return 0;
}                              
```



# 1007 [Quoit Design](http://acm.hdu.edu.cn/showproblem.php?pid=1007)

**Problem Description**

```txt
Have you ever played quoit in a playground? Quoit is a game in which flat rings are pitched at some toys, with all the toys encircled awarded.
In the field of Cyberground, the position of each toy is fixed, and the ring is carefully designed so it can only encircle one toy at a time. On the other hand, to make the game look more attractive, the ring is designed to have the largest radius. Given a configuration of the field, you are supposed to find the radius of such a ring.

Assume that all the toys are points on a plane. A point is encircled by the ring if the distance between the point and the center of the ring is strictly less than the radius of the ring. If two toys are placed at the same point, the radius of the ring is considered to be 0.
```

**Input**

```txt
The input consists of several test cases. For each case, the first line contains an integer N (2 <= N <= 100,000), the total number of toys in the field. Then N lines follow, each contains a pair of (x, y) which are the coordinates of a toy. The input is terminated by N = 0.
```

**Output**

```txt
For each test case, print in one line the radius of the ring required by the Cyberground manager, accurate up to 2 decimal places.
```

**Sample Input**

```
2
0 0
1 1
2
1 1
1 1
3
-1.5 0
0 0
0 1.5
0
```

**Sample Output**

```
0.71
0.00
0.75
```

​	

```c++
/*
看完题目发现是个最近点对的问题 
*/
#include<iostream>
#include<algorithm>
#include<cmath>
using namespace std;
int n;
//定义点的结构体 
struct Point{
	double x;
	double y;
}pt[100007];
int a[100007];//可以记录大概满足要求的点的下标 
//对功能进行函数包装
int cmp(Point a,Point b)
{
	if(a.x!=b.x)
		return a.x<b.x;
	else 
		return a.y<b.y;
}
int cmp_y(int i,int j)
{
	return pt[i].y<pt[j].y;
} 
//获取距离 
double getdis(Point &a,Point &b)
{
	return sqrt((a.x-b.x)*(a.x-b.x)+(a.y-b.y)*(a.y-b.y));
} 
double solve(int l,int r){
	double ans = 0;
	//只有两个点就直接输出 
	if(r-l <= 2)
	{
		//当两个点重合,返回0 
		if(r-l == 0)
			return ans;
		ans = getdis(pt[l],pt[l+1]);
		//当只有一个点时，返回ans 
		if(r-l == 1)
			return ans;
		for(int i = l ; i <= r ; i++){
			for(int j=i+1 ; j <= r ; j++)
			{
				ans = min(ans,getdis(pt[i],pt[j]));
			}
		} 
		return ans;
	}
	//剩下就是多个点的问题了 
	int m = (l+r)>>1;
	double temp1 = solve(l,m);
	double temp2 = solve(m+1,r);
	ans = min(temp1,temp2);
	//获取区间中的点，对y坐标进行排序
	int k = 0;
	for(int i = l ; i <= m && pt[m].x -pt[i].x ; i++)
		a[k++] = i;
	for(int j = m+1 ; j <= r && pt[r].x-pt[j].x ; j++)
		a[k++] = j;
	sort(a,a+k,cmp_y);
	for(int i = 0 ; i < k ; i++)
	{
		for(int j = i+1 ; j < k && j <= i+7 ; j++)
		{
			ans = min(ans,getdis(pt[a[i]],pt[a[j]]));
		}
	 } 
	return ans;
	 
}
int main()
{
	while(~scanf("%d",&n)&&n)
	{
		for(int i = 0 ; i < n ; i++)
		{
			scanf("%lf%lf",&pt[i].x,&pt[i].y);
		}
		sort(pt,pt+n,cmp);
		printf("%.2lf\n",solve(0,n-1)*1.0/2);
	}
} 
```



# 1008 [ Elevator](http://acm.hdu.edu.cn/showproblem.php?pid=1008)

`Problem Description`

```txt
The highest building in our city has only one elevator. A request list is made up with N positive numbers. The numbers denote at which floors the elevator will stop, in specified order. It costs 6 seconds to move the elevator up one floor, and 4 seconds to move down one floor. The elevator will stay for 5 seconds at each stop.
For a given request list, you are to compute the total time spent to fulfill the requests on the list. The elevator is on the 0th floor at the beginning and does not have to return to the ground floor when the requests are fulfilled.
```

`Input`

```txt
There are multiple test cases. Each case contains a positive integer N, followed by N positive numbers. All the numbers in the input are less than 100. A test case with N = 0 denotes the end of input. This test case is not to be processed. 
```

`Output`

```txt
Print the total time on a single line for each test case.
```

`Sample Input`

```
1 2
3 2 3 1
0
```

`Sample Output`

```
17
41
```



**题意**

一个楼梯用于升降，第一个N数为请求数量，随后跟着N个请求，对于上升请求，每上一楼6秒，停5秒，对于下降请求，每下一楼4秒，停5秒。

**代码**

```c++
#include<iostream>
using namespace std;

int main()
{
    int n;
    while(cin>>n&&n)
    {
        int now_level = 0;
        int temp;
        int sum = 0;
        for(int i = 0 ; i < n ; i++)
        {
            cin>>temp;
            if(now_level > temp)
                sum += (now_level-temp)*4 + 5;
            else 
                sum += (temp - now_level)*6 + 5;
            now_level = temp;
        }
        cout<<sum<<endl;
    }
}
```



# 1009 [ FatMouse' Trade](http://acm.hdu.edu.cn/showproblem.php?pid=1009)

`Problem Description`

```txt
FatMouse prepared M pounds of cat food, ready to trade with the cats guarding the warehouse containing his favorite food, JavaBean.
The warehouse has N rooms. The i-th room contains J[i] pounds of JavaBeans and requires F[i] pounds of cat food. FatMouse does not have to trade for all the JavaBeans in the room, instead, he may get J[i]* a% pounds of JavaBeans if he pays F[i]* a% pounds of cat food. Here a is a real number. Now he is assigning this homework to you: tell him the maximum amount of JavaBeans he can obtain.
```

`Input`

```txt
The input consists of multiple test cases. Each test case begins with a line containing two non-negative integers M and N. Then N lines follow, each contains two non-negative integers J[i] and F[i] respectively. The last test case is followed by two -1’s. All integers are not greater than 1000.
```

`Output`

```txt
For each test case, print in a single line a real number accurate up to 3 decimal places, which is the maximum amount of JavaBeans that FatMouse can obtain. 
```

`Sample Input`

```
5 3
7 2
4 3
5 2
20 3
25 18
24 15
15 10
-1 -1
```

`Sample Output`

```
13.333
31.500
```

`题意`

M吨猫粮，

`分析`

尝试贪心

`代码`

```c++
#include<iostream>
#include<algorithm>
using namespace std;

struct food{
	double J;
	double F;
	double value;
}M[1005];
//按照权重贪心 
bool  cmp(food a,food b){
	return a.value>b.value;
}
int main()
{
	int m,n;
	while(cin>>m>>n && (m!=-1 && n!=-1))
	{
		double sum = 0;
		for(int i = 0 ; i < n ; i++)
		{
			cin>>M[i].J>>M[i].F;
			M[i].value = M[i].J*1.0/M[i].F;
		}
		sort(M,M+n,cmp);
		for(int i = 0 ; i < n; i++)
		{
			if(M < 0)
				break;
			if(M[i].F > m)
			{
				sum += m*1.0*M[i].J/M[i].F;
				m = 0;
			}
			else
			{
				sum += M[i].J;
				m -= M[i].F;
			}
		}
		printf("%.3lf\n",sum);
	}
} 	
```



# 1010 [Tempter of the Bone](http://acm.hdu.edu.cn/showproblem.php?pid=1010)

`Problem Description`

```txt
The doggie found a bone in an ancient maze, which fascinated him a lot. However, when he picked it up, the maze began to shake, and the doggie could feel the ground sinking. He realized that the bone was a trap, and he tried desperately to get out of this maze.

The maze was a rectangle with sizes N by M. There was a door in the maze. At the beginning, the door was closed and it would open at the T-th second for a short period of time (less than 1 second). Therefore the doggie had to arrive at the door on exactly the T-th second. In every second, he could move one block to one of the upper, lower, left and right neighboring blocks. Once he entered a block, the ground of this block would start to sink and disappear in the next second. He could not stay at one block for more than one second, nor could he move into a visited block. Can the poor doggie survive? Please help him.

```

`Input`

```txt
The input consists of multiple test cases. The first line of each test case contains three integers N, M, and T (1 < N, M < 7; 0 < T < 50), which denote the sizes of the maze and the time at which the door will open, respectively. The next N lines give the maze layout, with each line containing M characters. A character is one of the following:

‘X’: a block of wall, which the doggie cannot enter;
‘S’: the start point of the doggie;
‘D’: the Door; or
‘.’: an empty block.

The input is terminated with three 0’s. This test case is not to be processed.
```

`Output`

```txt
For each test case, print in one line “YES” if the doggie can survive, or “NO” otherwise.
```

`Sample Input`

```
4 4 5
S.X.
..X.
..XD
....
3 4 5
S.X.
..X.
...D
0 0 0
```

 

Sample Output

```
NO
YES
```



# 1011 [Starship Troopers](http://acm.hdu.edu.cn/showproblem.php?pid=1011)

