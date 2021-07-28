# Flip Flops

## Challenge Description
`Yesterday, Roo bought some new flip flops. Let's see how good at flopping you are.`

## Solution

> TDLR: Encrypt `16 bytes of random characters + "gimm3flag"`. Modify a byte in the first 16 bytes of the ciphertext (C<sub>i-1</sub>) so that the corresponding byte of the plaintext (P<sub>i</sub>) changes when decrypt.

Given code:
``` python
#!/usr/local/bin/python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii
import os

print('''
                                        ,,~~~~~~,,..
                             ...., ,'~             |
                             \    V                /
                              \  /                 /
                              ;####>     @@@@@     )
                              ##;,      @@@@@@@    )
                           .##/  ~>      @@@@@   .   .
                          ###''#>              '      '
      .:::::::.      ..###/ #>               '         '
     //////))))----~~ ## #}                '            '
   ///////))))))                          '             '
  ///////)))))))\                        '              '
 //////)))))))))))                                      '
 |////)))))))))))))____________________________________).
|||||||||||||||||||||||||||||||||||||||||||||||||||||||||

(yeah they're not flip flops but close enough)

''')

key = os.urandom(16)
iv = os.urandom(16)


for _ in range(3):
    print("Send me a string that when decrypted contains 'gimmeflag'.")
    print("1. Encrypt")
    print("2. Check")
    choice = input("> ")
    if choice == "1":
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = binascii.unhexlify(input("Enter your plaintext (in hex): "))
        if b"gimmeflag" in pt:
            print("I'm not making it *that* easy for you :kekw:")
            print(binascii.hexlify(cipher.encrypt(pad(pt, 16))).decode())
        else:
            print(binascii.hexlify(cipher.encrypt(pad(pt, 16))).decode())
    else:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = binascii.unhexlify(input("Enter ciphertext (in hex): "))
        print(cipher.decrypt(ct))
        assert len(ct) % 16 == 0
        if b"gimmeflag" in cipher.decrypt(ct):
            print('pwn')
        else:
            print("Bad")

print("Out of operations!")
```

### Background of AES-CBC Decryption
P<sub>0</sub> = Decrypt(C<sub>0</sub>) XOR IV

P<sub>i</sub> = Decrypt(C<sub>i</sub>) XOR C<sub>i-1</sub> (for all i > 0)

### Explanation
By prepending 16 bytes of random characters before the word “gimm3flag” allows me to control C<sub>i-1</sub> so that I can change a byte in P<sub>i</sub>

If I modify C<sub>i-1</sub> to C<sub>i-1</sub> XOR P<sub>i</sub> XOR [P<sub>i</sub> with a modified byte]:

P<sub>i</sub>' = Decrypt(C<sub>i</sub>) XOR C<sub>i-1</sub> XOR P<sub>i</sub> XOR [P<sub>i</sub> with a modified byte] 

P<sub>i</sub>' = P<sub>i</sub> XOR P<sub>i</sub> XOR [P<sub>i</sub> with a modified byte]

P<sub>i</sub>' = [P<sub>i</sub> with one byte modified]

Idea: Encrypt `16 bytes of random characters + "gimm3flag"`. Modify a byte in the first 16 bytes of the ciphertext (C<sub>i-1</sub>) so that the corresponding byte of the plaintext (P<sub>i</sub>) changes when decrypt. 

Working POC:
``` python
from pwn import *
import codecs

r = remote('chal.imaginaryctf.org', 42011)
r.recvuntil(b'>')
r.sendline(b'1')
str2encrypt = "AAAAAAAAAAAAAAAAgimm3flag".encode().hex()
r.recvuntil(b'plaintext (in hex):')
r.sendline(str2encrypt.encode())
encryptedStr = r.recvline().decode().strip()
xor = ord('3') ^ ord('e')
payload = encryptedStr[:8] + hex(int(encryptedStr[8:10], 16) ^ xor)[2:]  + encryptedStr[10:]
r.recvuntil(b'>')
r.sendline(b'2')
r.recvuntil(b'ciphertext (in hex):')
r.sendline(payload.encode())
r.interactive()
```

Flag: `ictf{fl1p_fl0p_b1ts_fl1pped_b6731f96}`