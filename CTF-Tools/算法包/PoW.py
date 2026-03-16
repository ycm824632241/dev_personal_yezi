import hashlib
import string
import itertools

def crack_pow(proof_suffix, target_hash):
    alphabet = string.ascii_letters + string.digits
    for prefix in itertools.product(alphabet, repeat=4):
        x = ''.join(prefix)
        h = hashlib.sha256((x + proof_suffix).encode()).hexdigest()
        if h == target_hash:
            return x
    return None

# 示例使用
proof_suffix = "DXwPi7nDkcB1"  # 示例后缀
target_hash = "78a2e32b626654d910f5d66e3728711ae21fe68313654dafdb8c53feb181b4d4"  # 示例目标哈希
result = crack_pow(proof_suffix, target_hash)
if result:
    print(f"Found XXXX: {result}")
else:
    print("Failed to find XXXX")
