from pwn import *

# Specify the architecture
context.arch = 'i386'
# Create a shellcode
shellcode = shellcraft.sh()
print(shellcode)
# Assembly it
assembled_shellcode = asm(shellcode)
print(assembled_shellcode)
