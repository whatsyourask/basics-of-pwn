#include <stdlib.h>
/*
This program is simple as possible
*/

// Compile with:
// gcc stack-example.c -o stack-example -m32
// -m32 option is just for better explanation

int some_func1(int a, int b, int c, int d, int e, int f){
  int result = some_func2(e, f);
  return a + b + c + d + result;
}

int some_func2(int e, int f){
  int argv[10];
  short ind;
  size_t len = 10;
  for(ind = 0; ind < 10; ind++){
    argv[ind] = ind;
  }
  return e * f;
}

int main(int argc, char *argv[]){
  int a = 1, b = 2, c = 3, d=4, e=5, f=6;
  int result = some_func1(a, b, c, d, e, f);
  return 0;
}
