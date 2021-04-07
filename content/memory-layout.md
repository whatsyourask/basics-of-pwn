# Memory layout of the process

This is the memory view of the process.

## General view

![general-view](../images/general-memory-view.png "https://github.com/whatsyourask/basics-of-pwn/blob/main/images/general-memory-view.png")

### Stack

The stack stores the variables that were added as arguments, and created during the execution of a function. The stack grows from the higher memory addresses to the lower memory addresses.

```C
void some_func(int arg1){
  short var = 0;
  short var2;
}
```

### Shared memory

The process loads the shared libraries used by executable in the shared memory. It usually includes files such as `malloc.o` or `printf.o`.

### Heap

The heap stores the variables that were dynamically allocated with *alloc family of functions. For object oriented programming languages the heap also stores the objects. The heap grows from the lower memory addresses to the higher memory addresses which is opposite to stack.

```C
int *arr;
size_t arr_size = 5;
arr = (int *)malloc(arr_size * sizeof(arr));
```

### BSS

The bss section stores the uninitialized variables, but which were declared.

```C
int var;
char *str;
short arr[12];
```

### Initialized data

This sections stores the variables that were declared and initialized.

```C
int ind = 0;
size_t size = 10;
const char *temp = "Hello, World!";
```

### Text

The text section stores the text of the assembly instructions.

For example, our program:

```C
#include <stdio.h>

int main(){
	printf("Hello, World!");
	return 0;
}
```

To see the text section of the program:

```bash
gcc example.c -o example -m32
objdump -d -M intel example
```

Text section of main function:

```
00001199 <main>:
    1199:	8d 4c 24 04          	lea    ecx,[esp+0x4]
    119d:	83 e4 f0             	and    esp,0xfffffff0
    11a0:	ff 71 fc             	push   DWORD PTR [ecx-0x4]
    11a3:	55                   	push   ebp
    11a4:	89 e5                	mov    ebp,esp
    11a6:	53                   	push   ebx
    11a7:	51                   	push   ecx
    11a8:	e8 28 00 00 00       	call   11d5 <__x86.get_pc_thunk.ax>
    11ad:	05 53 2e 00 00       	add    eax,0x2e53
    11b2:	83 ec 0c             	sub    esp,0xc
    11b5:	8d 90 08 e0 ff ff    	lea    edx,[eax-0x1ff8]
    11bb:	52                   	push   edx
    11bc:	89 c3                	mov    ebx,eax
    11be:	e8 6d fe ff ff       	call   1030 <printf@plt>
    11c3:	83 c4 10             	add    esp,0x10
    11c6:	b8 00 00 00 00       	mov    eax,0x0
    11cb:	8d 65 f8             	lea    esp,[ebp-0x8]
    11ce:	59                   	pop    ecx
    11cf:	5b                   	pop    ebx
    11d0:	5d                   	pop    ebp
    11d1:	8d 61 fc             	lea    esp,[ecx-0x4]
    11d4:	c3                   	ret
```
