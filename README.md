# basics-of-pwn

My course work about a basic binary exploitation.

![pwn-structure](images/pwn-structure.png "https://github.com/whatsyourask/basics-of-pwn/blob/main/images/pwn-structure.png")

## <b>Table of Contents</b>

- [Memory layout of the process](content/memory-layout.md "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/memory-layout.md")
- [ELF and its key things](content/elf.md "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/elf.md")
  * [ELF format](content/elf.md#elf-format "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/elf.md#elf-format")
  * [Features of ELF](content/elf.md#elf-features "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/elf.md#elf-features")
- [Vulnerabilities types](content/vulnerabilities.md "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/vulnerabilities.md")
  * [Buffer overflow](content/buffer-overflow/buffer-overflow.md "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/buffer-overflow/buffer-overflow.md")
    * [Structure within the stack](content/buffer-overflow/buffer-overflow.md#structure-within-the-stack "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/buffer-overflow/buffer-overflow.md#structure-within-the-stack")
    * [Exploitation](content/buffer-overflow/buffer-overflow.md#exploitation "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/buffer-overflow/buffer-overflow.md#exploitation")
  * [Stack overflow](content/stack-overflow/stack-overflow.md "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/stack-overflow/stack-overflow.md")
    * [Jump to arbitrary address](content/stack-overflow/stack-overflow.md#jump-to-arbitrary-address "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/stack-overflow/stack-overflow.md#jump-to-arbitrary-address")
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
  * [Relocation Read-Only]
