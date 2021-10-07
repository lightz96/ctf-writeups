# Shuffled
```
Oh no, roo discovered the Fisher-Yates shuffle and decided the shuffle all my good advice. Please help me restore everything so that I know what I learned about classical cryptanalysis?

Note: The solution will give you instructions on how to get the flag, there will be no ictf{} in the plaintext directly.
```

## Challenge
The challenge provides a script:
``` python
import random
with open("plain.txt") as f:
    plain = list(f.read())

with open("seed.bin", "rb") as f:
    random.seed(f.read(2))

for i in range(len(plain) - 1, -1, -1):
    j = random.randint(0, i)
    plain[i], plain[j] = plain[j], plain[i]

with open("out.txt", "w") as f:
    f.write(''.join(plain))
```

And a text file:
```
n itxgektetttacguni.goe i  txroey reltihh ei uha o   nsact cenrI d symw blpgeo,l xeoiaa hh a sfts aewap iw ib rm yickan ta erI n qhitneltaaslifmentte lcllgiai ycawgsfai setki no  yithi  dtu
eoteiovohelu5rlprdl rengentuml  imavnsn  Srtyvr nos  nso epieefuecitaqrctodhutf es  ipAtrnii ioxocis fshfedtstenn,
lmealhka,tfyn slwiefso iu   frolec ie cfr  shtncenddgryiteomcag uneap eas qnsx

pnteaa tr  nwor , t sosrm
 tkyiteaeuenop)keOstlia fe inaguo,   ttf f.sht,un
 lha( t -weienaat nssywta aimte f owo buit shor  hopll no o  olna ewpta lyhtyye.b, r le.ee v lfebat yaecavuabgilghogit,ea tat a 
iogs i rektge  ntomx rrae en  csrtkhetrapal
```

Observation made:
1. Same seed is used to encode the plaintext
2. The seed is 2 bytes
3. The character in `plain[i]` after swap is fixed, but the character in `plain[j]` is not fixed. The character in `plain[j]` can still be swapped with other character.

Since we do not know the seed used, we need to generate the sequence of the value `j` of all possible seeds. Then, we need to reverse the sequence so that un-swap to get the plaintext. We need to start from the leftmost character for our swapping as ciphertext `plain[j]` maybe not be the plaintext `plain[i]`

Script:
``` python
import random

with open("6C23-out.txt") as f:
    cipher = list(f.read())

# Generate sequence of different seeds and reverse the order
# Note: I started with range(0, 127) instead of range(60, 61) and range(0, 127) instead of range(9, 10)
gen = []
for a in range(60, 61): # trial and error
    for b in range(9, 10): # trial and error
        seed = (chr(a) + chr(b)).encode()
        random.seed(seed)
        lst = []
        for i in range(len(cipher) - 1, -1, -1):
            lst.insert(0, random.randint(0, i))
        gen.append(lst)

# un-swap
for seq in gen:
    sample = cipher.copy() # "sample = cipher" does not create 2 lists
    for i in range(0, len(sample)):
        sample[i], sample[seq[i]] = sample[seq[i]], sample[i]
    print(''.join(sample), end="")
```

Output of the script:
```bash
$ python3 crypto1.py > plain.txt
$ cat plain.txt                 
Sometimes figuring out what exactly plaintext looks like is the hardest part of cryptanalysis.
One way in which you can try to solve this, is for instance by looking at bigram frequencies,
or even more generally, at k-gram frequencies.
In fact, quadgrams are often a very enlightening statistic that can even tell us what
language a text is written in, or even who is likely to be the original author of a piece of text.
Anyway, I think this should be plenty of plaintext now, so to get the flag, simply take the md5 of this plaintext
(be careful to make sure all whitespace is accounted for) and submit it inside of a flag wrapper.
```

Flag: `5e147ba884bb7fb7e31388debf551b68`