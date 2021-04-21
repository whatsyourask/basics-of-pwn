; nasm -f elf32 dirty-low-level-shellcode.asm
; ld -m elf_i386 dirty-low-level-shellcode.o -o dirty-low-level-shellcode

; push the string '/bin/sh\0
  push 0x68732f00
  push 0x6e69622f
; move the first argument (/bin//sh) to ebx
  mov ebx, esp
; push address of the string
  push ebx
; move the second argument (argv array) to ecx
  mov ecx, esp
; move to eax the number of the syscall
  mov eax, 0xb
; do interruption
  int 0x80
