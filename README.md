# basics-of-pwn

My course work about basic binary exploitation.

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
    * [Jump to an arbitrary address](content/stack-overflow/stack-overflow.md#jump-to-an-arbitrary-address "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/stack-overflow/stack-overflow.md#jump-to-an-arbitrary-address")
    * [Shellcode writing](content/stack-overflow/stack-overflow.md#shellcode-writing "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/stack-overflow/stack-overflow.md#shellcode-writing")
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

## Resources

### ELF

* [wiki](https://elinux.org/Executable_and_Linkable_Format_(ELF) "https://elinux.org/Executable_and_Linkable_Format_(ELF)")
* [pdf book](http://flint.cs.yale.edu/cs422/doc/ELF_Format.pdf "http://flint.cs.yale.edu/cs422/doc/ELF_Format.pdf")

### syscalls tables

* [x86 syscalls table](https://syscalls32.paolostivanin.com/ "https://syscalls32.paolostivanin.com/")
* [x86-64 syscalls talbe](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/?__cf_chl_captcha_tk__=b8fbfda8ee898b6c00431d92d27106cd1c313f62-1618472325-0-AVAEkq6Rq4DjlvcvmulDzU6XfjgFvTTN0vhhH4mviS5viqf9vPu5czIo7DVnp9JqHNrXbhBWhfd2VstZJ-fpOp9QyfP0hYuOiHtEuck9YzjfUb_7vsjOswfrqcQUsUGAJoVrVRk5wbj-oW5Il013tEo_lmRwXzl_aTG1Jq6yq21b4SHTRFy0KjSvKgpeYnxw6p8iNFEKAGCHXM19l2AqZX4KPVpa1EAJ6qxxSIcSgFG-YPzA2R32c1yc7GqS9AtHCLuUd6cJlUNwfCaExjDqNWhaYQFJNJP9tn-QkwdfORVMrPXCIh3-9MdVgIzRntG3i1b0UKJKNBXPjXi5EHVhJoy4AuS9p2jhB6QK0_r2zcq2LcS_8vLXBwiguZgxBERG82_W6utBhMl21gOVLJkfPHXrhUNSv6BESMmOhEGixBn0UCMgSLwL-yj1iE_hCD_gDIIF2zGI59_uVwyru52YCwg5H_BzuvDRyhy1HILTJIjMWo_Dq3fctguS8t0aZ1OMgIxaAj0m_LF05T2HOrwHnFYPnm79oakC7hu_STxDQ7SYil9uFw-U8FVIypSnosYhu8F9hreEeJj6wC9QRyHhny4GP7ka912JnikVP9p2hYlx7XSZY_W0ojKVvOPgy9TLnwPkjpQuk8rYsr8LMic2fow "https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/?__cf_chl_captcha_tk__=b8fbfda8ee898b6c00431d92d27106cd1c313f62-1618472325-0-AVAEkq6Rq4DjlvcvmulDzU6XfjgFvTTN0vhhH4mviS5viqf9vPu5czIo7DVnp9JqHNrXbhBWhfd2VstZJ-fpOp9QyfP0hYuOiHtEuck9YzjfUb_7vsjOswfrqcQUsUGAJoVrVRk5wbj-oW5Il013tEo_lmRwXzl_aTG1Jq6yq21b4SHTRFy0KjSvKgpeYnxw6p8iNFEKAGCHXM19l2AqZX4KPVpa1EAJ6qxxSIcSgFG-YPzA2R32c1yc7GqS9AtHCLuUd6cJlUNwfCaExjDqNWhaYQFJNJP9tn-QkwdfORVMrPXCIh3-9MdVgIzRntG3i1b0UKJKNBXPjXi5EHVhJoy4AuS9p2jhB6QK0_r2zcq2LcS_8vLXBwiguZgxBERG82_W6utBhMl21gOVLJkfPHXrhUNSv6BESMmOhEGixBn0UCMgSLwL-yj1iE_hCD_gDIIF2zGI59_uVwyru52YCwg5H_BzuvDRyhy1HILTJIjMWo_Dq3fctguS8t0aZ1OMgIxaAj0m_LF05T2HOrwHnFYPnm79oakC7hu_STxDQ7SYil9uFw-U8FVIypSnosYhu8F9hreEeJj6wC9QRyHhny4GP7ka912JnikVP9p2hYlx7XSZY_W0ojKVvOPgy9TLnwPkjpQuk8rYsr8LMic2fow")

### gef

* [docs](https://gef.readthedocs.io/en/master/ "https://gef.readthedocs.io/en/master/")
* [repo](https://github.com/hugsy/gef "https://github.com/hugsy/gef")

### gdb

* [unset environement](https://stackoverflow.com/questions/55593045/how-to-set-environment-variable-within-gdb-using-shell-command)
