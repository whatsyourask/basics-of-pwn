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
   0x0000120c <+0>:	lea    ecx,[esp+0x4]
   0x00001210 <+4>:	and    esp,0xfffffff0
   0x00001213 <+7>:	push   DWORD PTR [ecx-0x4]
   0x00001216 <+10>:	push   ebp
   0x00001217 <+11>:	mov    ebp,esp
   0x00001219 <+13>:	push   ecx
   0x0000121a <+14>:	sub    esp,0x24
   0x0000121d <+17>:	call   0x127e <__x86.get_pc_thunk.ax>
   0x00001222 <+22>:	add    eax,0x2dde
   0x00001227 <+27>:	mov    DWORD PTR [ebp-0xc],0x1
   0x0000122e <+34>:	mov    DWORD PTR [ebp-0x10],0x2
   0x00001235 <+41>:	mov    DWORD PTR [ebp-0x14],0x3
   0x0000123c <+48>:	mov    DWORD PTR [ebp-0x18],0x4
   0x00001243 <+55>:	mov    DWORD PTR [ebp-0x1c],0x5
   0x0000124a <+62>:	mov    DWORD PTR [ebp-0x20],0x6
   0x00001251 <+69>:	sub    esp,0x8
   0x00001254 <+72>:	push   DWORD PTR [ebp-0x20]
   0x00001257 <+75>:	push   DWORD PTR [ebp-0x1c]
   0x0000125a <+78>:	push   DWORD PTR [ebp-0x18]
   0x0000125d <+81>:	push   DWORD PTR [ebp-0x14]
   0x00001260 <+84>:	push   DWORD PTR [ebp-0x10]
   0x00001263 <+87>:	push   DWORD PTR [ebp-0xc]
   0x00001266 <+90>:	call   0x1189 <some_func1>
   0x0000126b <+95>:	add    esp,0x20
   0x0000126e <+98>:	mov    DWORD PTR [ebp-0x24],eax
   0x00001271 <+101>:	mov    eax,0x0
   0x00001276 <+106>:	mov    ecx,DWORD PTR [ebp-0x4]
   0x00001279 <+109>:	leave  
   0x0000127a <+110>:	lea    esp,[ecx-0x4]
   0x0000127d <+113>:	ret    
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

At the address of `0xffffd1d8` - `0xffffd1e8` you can see our values 1, 2, 3, 4, 5, 6. But before them...
