import random
import math
import timeit

import sympy

def gcd(a, b):
    # 辗转相除法求最大公约数
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    # 扩展欧几里得算法求模逆
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_keypair(bits):
    # 生成RSA密钥对
    p = sympy.randprime(10 ** 63, 10 ** 64 / 2 - 1)
    q = sympy.randprime(10 ** 64, 10 ** 65 / 2 - 1)
    n = p * q
    k = (p - 1) * (q - 1)
    print("p=",p)
    print("q=",q)

    # 选择e，要求e与k互质
    e = random.randrange(1, k)
    while gcd(e, k) != 1:
        e = random.randrange(1, k)

    # 计算d，使得d是e模k的模逆
    d = modinv(e, k)
    public_key = (n, e)
    private_key = (n, d)

    return public_key, private_key

def encrypt(message, public_key):
    # 加密
    n, e = public_key
    cipher = pow(message, e, n)
    return cipher

def decrypt(cipher, private_key):
    # 解密
    n, d = private_key
    message = pow(cipher, d, n)
    return message

def main():
    # 要加密的消息
    message = 11223344556677889900
    print("明文:",message)

    # 生成RSA密钥对
    b = 128  # 位数
    public_key, private_key = generate_keypair(b)

    print("n=",public_key[0])
    print("e=",public_key[1])
    print("d=",private_key[1])

    # 加密消息
    encrypted_message = encrypt(message, public_key)
    print("加密后的消息:", encrypted_message)

    # 解密消息
    decrypted_message = decrypt(encrypted_message, private_key)
    print("解密后的消息:", decrypted_message)
    if message == decrypted_message:
        print("解密结果与明文相同！加解密正确！")

if __name__ == '__main__':
    # main()
    execution_time = timeit.timeit(main, number=10)  # number 表示执行次数
    print("RSA执行10次时间:", execution_time)