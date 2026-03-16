from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# 密钥和IV的长度需要符合AES的标准
key = get_random_bytes(16)  # 16字节的密钥 (AES-128)
iv = get_random_bytes(16)   # 16字节的初始化向量 (IV)

# 要加密的明文
data = b"Secret Message!"

# 创建AES对象，使用CBC模式
cipher = AES.new(key, AES.MODE_CBC, iv)

# 对明文进行填充 (block size is 16 for AES)
ciphertext = cipher.encrypt(pad(data, AES.block_size))

print("加密后的密文:", ciphertext)

# 创建AES对象，用于解密
cipher = AES.new(key, AES.MODE_CBC, iv)

# 解密并取消填充
plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

print("解密后的明文:", plaintext)
