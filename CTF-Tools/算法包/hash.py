from Crypto.Hash import MD5
import string
import itertools

def crack_pow(salt, target_hash):
    alphabet = string.ascii_letters + string.digits
    for prefix in itertools.product(alphabet, repeat=6):
        x = ''.join(prefix)
        h = MD5.MD5Hash.new((salt + x).encode()).hexdigest()
        if h == target_hash:
            return x
    return None

# 我们要找到两个不同的字符串，它们的哈希值相同
hash_table = {}

salt = "secure_salt"
dstHash = "0b13569a349ebeaf84bd8d5d11ca4d93"
result = crack_pow(salt, dstHash)

if result:
    print(f"Found XXXX: {result}")
else:
    print("Failed to find XXXX")
