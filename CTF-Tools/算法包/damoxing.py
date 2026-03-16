import hashlib
from Crypto.Util.number import *
import string
import itertools


prefix = "2024jsmmjs message:"
ciper = "6b9cf4c69c9256d9a1128cf9d7351d76"
h = hashlib.sha256(prefix.encode()).hexdigest()
key = h[0:32]

c = b'\x6b\x9c\xf4\xc6\x9c\x92\x56\xd9\xa1\x12\x8c\xf9\xd7\x35\x1d\x76'
k = b'\x2a\x2f\x71\x0e\x1d\x72\x61\xe0\x6d\x98\xa8\xc1\x22\x01\x1f\xb5'
print()
#0110 1011 10011100
#0010 1010

#0100 0001
print(chr(0x41))
m = []
for i,c0 in enumerate(c):
    m.append(c[i] ^ k[i])

print(m)