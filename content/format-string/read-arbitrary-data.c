#include <stdio.h>
#include <string.h>
#include <unistd.h>

// gcc read-arbitrary-data.c -o read-arbitrary-data -m32

int main(int argc, char *argv[]){
  const char *allow = "Access granted.\n";
  const char *deny = "Access denied.\n";
  char buff[200];
  read(1, buff, 200);
  if (strncmp("password\0", buff, 9) == 0) {
    printf(allow);
    system("/bin/sh");
  } else {
    printf(deny);
    printf("Say goodbye!!!");
  }
  read(1, buff, 200);
  printf(buff);
}
