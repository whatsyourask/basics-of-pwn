#include <stdio.h>
#include <string.h>

// gcc got-overwrite.c -o got-overwrite -fno-stack-protector -no-pie -z execstack -Wl,-z,norelro -m32


int main(int argc, char *argv[]){
  char buff[200];
  strncpy(buff, argv[1], 200);
  printf(buff);
  char buff2[200];
  gets(buff2);
  printf(buff2);
  return 0;
}
