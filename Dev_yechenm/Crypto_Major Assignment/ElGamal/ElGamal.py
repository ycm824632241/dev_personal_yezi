import timeit
from random import randint
import sympy
import sys

sys.setrecursionlimit(10000) #调整递归深度

def fast_Mod(base, exp, modulus):
    base = base % modulus
    result = 1
    while exp != 0:
        if exp & 1:
            result = (result * base) % modulus
        exp >>= 1
        base = (base * base) % modulus
    return result


def find_primary_root(p, q): #求原根
    while True:
        g = randint(2, p - 2)
        if fast_Mod(g, 2, p) != 1 and fast_Mod(g, q, p) != 1:
            return g


def extended_gcd(a, b): #判断互素
    if b == 0:
        return a, 1, 0
    g, x, y = extended_gcd(b, a % b)
    return g, y, x - a // b * y


def Encrypt(p, g, y, m): #加密
    while True:
        k = randint(2, p - 2)
        if extended_gcd(k, p - 1)[0]:
            break
    c1 = fast_Mod(g, k, p)
    c2 = (m * fast_Mod(y, k, p)) % p
    return c1, c2


def Decrypt(c1, c2, p, a): #解密
    v = fast_Mod(c1, a, p)
    v_1 = extended_gcd(v, p)[1]
    M_secret = c2 * v_1 % p
    return M_secret


def main():

    # L = int(open("secret2.txt").readline())
    m = 11223344556677889900
    while True:
        q = sympy.randprime(10 ** 149, 10 ** 150 / 2 - 1) #利用sympy库寻找随机素数
        if sympy.isprime(q):
            p = 2 * q + 1
            if len(str(p)) == 150 and sympy.isprime(p): #利用sympy库判断素数
                break
    g = find_primary_root(p, q)

    x = randint(2, p - 2)
    y = fast_Mod(g, x, p)

    c1, c2 = Encrypt(p, g, y, m)
    M_secret = Decrypt(c1, c2, p, x)

    if m == M_secret:
        print("解密结果与明文相同！加解密正确！")
    else:
        print("解密结果与明文不同！加解密不正确！")
    print("相关参数:")
    print("明文 L = %d" %m)
    print("ALice的公钥(p,g,y):")
    print("p = %d" %p)
    print("g = %d" %g)
    print("x = %d" %x)
    print("y = g^x = %d" %y)
    print("密文(C1,C2):")
    print("C1 = %d" %c1)
    print("C2 = %d" % c2)
    print("解密得明文: ")
    print("L = %d" %M_secret)

if __name__ == '__main__':
    # main()
    execution_time = timeit.timeit(main, number=3)  # number 表示执行次数
    print("Elgamal执行10次时间:",execution_time)