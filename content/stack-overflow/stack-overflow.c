#include <unistd.h>
#include <string.h>

// gcc stack-overflow.c -o stack-overflow -fno-stack-protector -no-pie -z execstack -m32

// Function that sets user id to 0 and execute the shell
void shell(){
  setuid(0);
  system("/bin/sh");
}

void vuln_func(){
  char vuln_buff[250];
  // vulnerable
  gets(vuln_buff);
}

int main(int argc, char *argv[]){
  vuln_func();
  return 0;
}
