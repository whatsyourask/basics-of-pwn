# basic-pwn
My course work about a basic binary exploitation.

![pwn-structure](images/pwn-structure.png "https://github.com/whatsyourask/basics-of-pwn/blob/main/images/pwn-structure.png")

## <b>Table of Contents</b>

- [Memory organization of the executable files]
- [ELF and its key things]
  * [ELF format]
  * [Features of ELF]
- [Vulnerabilities types]
  * [Buffer overflow]
  * [Stack overflow]
    * [Jump to arbitrary address]
    * [Shellcode writing]
    * [NOP chain]
    * [Easy exploit of the stack overflow with python pwntools module]
  * [Format string vulnerabilities]
    * [Format string specifiers]
    * [Read arbitrary data]
    * [Exploitation]
  * [Heap overflow]
- [Security techniques]
  * [Non-Executable Stack(NX)]
  * [Address Space Layout Randomization(ASLR)]
  * [Stack canary]
  * [Position Independent Executable(PIE)]
