#include <stdlib.h>

// gcc high-level-shellcode.c -o high-level-shellcode
// use -m32 to compile x86-86 arch shellcode

int main(){
  // Start a new process /bin/sh or just spawn a shell
  execve("/bin/sh", NULL, NULL);
  // Exit normally
  exit(0);
}
