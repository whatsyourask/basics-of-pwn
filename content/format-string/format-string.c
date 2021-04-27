#include <stdio.h>
#include <string.h>

// gcc format-string.c -o format-string -fno-stack-protector -no-pie -z execstack -m32


int main(int argc, char *argv[]){
  char buff[200];
  strncpy(buff, argv[1], 200);
  printf(buff);
  return 0;
}
