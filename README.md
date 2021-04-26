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
    * [Vulnerable code](content/buffer-overflow/buffer-overflow.md#vulnerable-code "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/buffer-overflow/buffer-overflow.md#vulnerable-code")
  * [Stack overflow](content/stack-overflow/stack-overflow.md "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/stack-overflow/stack-overflow.md")
    * [Jump to an arbitrary address](content/stack-overflow/stack-overflow.md#jump-to-an-arbitrary-address "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/stack-overflow/stack-overflow.md#jump-to-an-arbitrary-address")
    * [Shellcode writing](content/stack-overflow/stack-overflow.md#shellcode-writing "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/stack-overflow/stack-overflow.md#shellcode-writing")
    * [Exploitation](content/stack-overflow/stack-overflow.md#exploitation "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/stack-overflow/stack-overflow.md#exploitation")
    * [NOP chain](content/stack-overflow/stack-overflow.md#nop-chain "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/stack-overflow/stack-overflow.md#nop-chain")
    * [pwntools](content/stack-overflow/stack-overflow.md#pwntools "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/stack-overflow/stack-overflow.md#pwntools")
  * [Format string vulnerability](content/format-string/format-string.md "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/format-string/format-string.md")
    * [View vulnerability](content/format-string/format-string.md#view-vulnerability "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/format-string/format-string.md#view-vulnerability")
    * [Format string specifiers](content/format-string/format-string.md#format-string-specifiers "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/format-string/format-string.md#format-string-specifiers")
    * [Read arbitrary data](content/format-string/format-string.md#read-arbitrary-data "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/format-string/format-string.md#read-arbitrary-data")
    * [Jump to an arbitrary address](content/format-string/format-string.md#jump-to-an-arbitrary-data "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/format-string/format-string.md#jump-to-an-arbitrary-data")
    * [Writing in several stages](content/format-string/format-string.md#writing-in-several-stages "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/format-string/format-string.md#writing-in-several-stages")
    * [Exploitation](content/format-string/format-string.md#exploitation "https://github.com/whatsyourask/basics-of-pwn/blob/main/content/format-string/format-string.md#exploitation")
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

### pwntools

* [docs](https://docs.pwntools.com/en/latest/ "https://docs.pwntools.com/en/latest/")
* [repo](https://github.com/Gallopsled/pwntools "https://github.com/Gallopsled/pwntools")

### Format string

* [stanford pdf](https://crypto.stanford.edu/cs155old/cs155-spring08/papers/formatstring-1.2.pdf "https://crypto.stanford.edu/cs155old/cs155-spring08/papers/formatstring-1.2.pdf")
