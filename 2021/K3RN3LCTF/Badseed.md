# Bad Seed

## Challenge
We are given a binary and an ascii text which introduces pwntools

To get shell, we need to answer 3 questions correctly.

The first question:
```c
void question_one(void)

{
  long in_FS_OFFSET;
  double dVar1;
  int local_24;
  float local_20;
  int local_1c;
  int local_18;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_20 = 6.035077;
  local_1c = 4000;
  local_24 = 0;
  local_18 = 0;
  dVar1 = floor(6.035077095031738);
  local_14 = (int)dVar1;
  local_18 = (int)((float)local_1c / local_20);
  puts("how heavy is an asian elephant on the moon?");
  __isoc99_scanf(&DAT_00402034,&local_24);
  if (local_18 != local_24) {
    puts("wrong bye bye");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("\ngreat 2nd question:");
  puts("give me the rand() value");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

So, the answer to question 1 is 662 since (int)(4000 / 6.035077) = 662

For question 2:
```c
void question_two(void)

{
  long in_FS_OFFSET;
  int local_24;
  int local_20;
  int local_1c;
  time_t local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_18 = time((time_t *)0x0);
  __isoc99_scanf(&DAT_00402034,&local_24);
  srand((uint)local_18);
  local_20 = rand();
  local_1c = rand();
  if (local_1c != local_24) {
    puts("wrong bye bye");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("great 3rd question:");
  puts("no hint this time... you can do it?!");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

and question 3:
```c
void question_three(void)

{
  long in_FS_OFFSET;
  int local_2c;
  uint local_28;
  int local_24;
  int local_20;
  int local_1c;
  time_t local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_18 = time((time_t *)0x0);
  srand((uint)local_18);
  local_28 = rand();
  srand(local_28);
  local_24 = rand();
  local_20 = (int)local_28 / local_24;
  local_1c = local_20 % 1000;
  __isoc99_scanf(&DAT_00402034,&local_2c);
  if (local_1c != local_2c) {
    puts("wrong bye bye");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("great heres your shell");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Both of these questions uses the current time as the seed to `rand()`. We will use pwntools to obtain the current time and use it as the seed to `rand()`. In this way, we will get the same output of `rand()` as the server.

POC:
```python
from pwn import *
import ctypes

r = remote('ctf.k3rn3l4rmy.com', 2200)

# Question 1
r.sendlineafter(b'on the moon?', b'662')

# Question 2
r.recvuntil(b'me the rand() value')
libc = ctypes.CDLL('/lib/x86_64-linux-gnu/libm.so.6')
libc.srand(libc.time())
libc.rand()
num = libc.rand()
r.sendline(str(num).encode())

# Question 3
r.recvuntil(b'you can do it?!')
libc.srand(libc.time())
local_28 = libc.rand()
libc.srand(local_28)
local_24 = libc.rand()
num = (local_28//local_24) % 1000
r.sendline(str(num).encode())


r.interactive()
```

The output:
```bash
$ python3 pwn1.py 
[+] Opening connection to ctf.k3rn3l4rmy.com on port 2200: Done
[*] Switching to interactive mode

great heres your shell
$ ls
flag.txt
run
$ cat flag.txt
flag{i_0_w1th_pwn70ols_i5_3a5y}
```

Flag: `flag{i_0_w1th_pwn70ols_i5_3a5y}`
