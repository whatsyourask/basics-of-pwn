#include <stdio.h>

// gcc specifiers.c -o specifiers -m32

int main(int argc, char *argv[]){
  int num = -824;
  printf("Signed int: %d\n", num);
  unsigned int num2 = 10000;
  printf("Unsigned int: %u\n", num2);
  printf("Hexadecimal: %x\n", num);
  int *p = &num2;
  printf("Pointer: %p\n", p);
  const char *s = "Some string";
  printf("String: %s\n", s);
  int *count = &num2;
  printf("Number of bytes written: %n\n", count);
  printf("%u\n", *count);
  return 0;
}
