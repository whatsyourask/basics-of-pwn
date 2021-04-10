#include <unistd.h>

int main(int argc, char *argv[]){
  char vuln_buff[100];
  int access = 0;
  gets(vuln_buff);
  if (access == 1234){
    system("/bin/bash");
  }
  return 0;
}
