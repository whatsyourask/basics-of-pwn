#include <unistd.h>
#include <string.h>

// gcc stack-overflow.c -o stack-overflow -fno-stack-protector

// Function that sets user id to 0 and execute the shell
void shell(){
  setuid(0);
  system("/bin/sh");
}

int main(int argc, char *argv[]){
  char vuln_buff[250];
  // vulnerable
  strcpy(vuln_buff, argv[1]);
  return 0;
}
