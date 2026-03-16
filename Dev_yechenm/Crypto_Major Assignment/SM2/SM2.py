import random
from math import gcd, ceil, log
from gmssl import sm3
from creat_key import creat_k
from toolkit import *

# 密钥派生函数KDF。接收的参数是比特串Z和要获得的密钥数据的长度klen。返回klen长度的密钥数据比特串K
def KDF(Z, klen):
    v = 256           # 密码杂凑函数采用SM3
    if klen >= (pow(2, 32) - 1) * v:
        raise Exception("密钥派生函数KDF出错，请检查klen的大小！")
    ct = 0x00000001
    if klen % v == 0:
        l = klen // v

    else:
        l = klen // v + 1
    Ha = []
    for i in range(l):         # i从0到 klen/v-1（向上取整）,共l个元素
        s = Z + int_to_bits(ct).rjust(32, '0')         # s存储 Z || ct 的比特串形式 # 注意，ct要填充为32位
        s_bytes = bits_to_bytes(s)          # s_bytes存储字节串形式
        s_list = [i for i in s_bytes]
        hash_hex = sm3.sm3_hash(s_list)
        hash_bin = hex_to_bits(hash_hex)
        Ha.append(hash_bin)
        ct += 1
    if klen % v != 0:
        Ha[-1] = Ha[-1][:klen - v*(klen//v)]
    k = ''.join(Ha)
    return k

# 加密算法。接收的参数是椭圆曲线系统参数args(p, a, b, h, G, n)。其中n是基点G的阶。PB是B的公钥，M是明文消息。
def encry_sm2(args, PB, M):
    p, a, b, h, G, n = args         # 序列解包
    M_bytes = bytes(M, encoding='ascii')
    print("1) 随机数发生器产生随机数k∈[1,n-1]")
    k = random.randint(1, n-1)
    k_hex = hex(k)[2:]          # k_hex 是k的十六进制串形式
    print("生成的随机数k:", k_hex)
    print("")
    print("2) 计算椭圆曲线点C1=[k]G=(x1,y1)，将C1的数据类型转换为比特串")
    C1 = mult_point(G, k, p, a)
    print("椭圆曲线点C1=[k]G=(x1,y1)的坐标是:", tuple(map(hex, C1)))
    C1_bits = point_to_bits(C1)

    print("")
    print("3) 计算椭圆曲线点S=[h]PB")
    S = mult_point(PB, h, p, a)
    if S == 0:
        raise Exception("计算得到的S是无穷远点")
    print("椭圆曲线点S = [h]PB的坐标是:", tuple(map(hex, S)))
    print("")
    print("4) 计算椭圆曲线点[k]PB=(x2,y2)，将坐标x2、y2 的数据类型转换为比特串")
    x2, y2 = mult_point(PB, k, p, a)
    print("椭圆曲线点[k]PB=(x2,y2)的坐标是:", tuple(map(hex, (x2, y2))))
    x2_bits = field_to_bits(x2)
    print("x2的比特串形式是:", x2_bits)
    y2_bits = field_to_bits(y2)
    print("y2的比特串形式是:", y2_bits)
    print("")
    print("5) 计算t=KDF(x2 ∥ y2, klen),若t为全0比特串,则报错")
    M_hex = bytes_to_hex(M_bytes)
    klen = 4 * len(M_hex)
    print("明文消息的比特串长度 klen = ", klen)
    t = KDF(x2_bits + y2_bits, klen)
    print("通过KDF计算得到t,t = KDF(x2 ∥ y2, klen) = ", t)
    if eval('0b' + t) == 0:
        raise Exception("KDF返回了全零串,请检查KDF函数！")
    t_hex = bits_to_hex(t)
    print("t的十六进制表示形式是:", t_hex)
    print("")
    print("6) 计算计算C2 = M ⊕ t")
    C2 = eval('0x' + M_hex + '^' + '0b' + t)
    print("计算的C2是：", hex(C2)[2:])
    print("")
    print("7) 计算C3 = Hash(x2 ∥ M ∥ y2)")
    x2_bytes = bits_to_bytes(x2_bits)
    y2_bytes = bits_to_bytes(y2_bits)
    hash_list = [i for i in x2_bytes + M_bytes + y2_bytes]
    C3 = sm3.sm3_hash(hash_list)
    print("C3 = Hash(x2 ∥ M ∥ y2) = ", C3)
    print("")
    print("8) 输出密文C = C1 ∥ C2 ∥ C3")
    C1_hex = bits_to_hex(C1_bits)
    C2_hex = hex(C2)[2:]
    C3_hex = C3
    C_hex = C1_hex + C2_hex + C3_hex
    print("加密得到的密文为 C =", C_hex)
    return C_hex

# 解密算法。接收的参数为椭圆曲线系统参数args(p, a, b, h, G, n)。dB是B的私钥，C是密文消息。
def decry_sm2(args, dB, C):
    p, a, b, h, G, n = args
    print("1) 从C中取出比特串C1,将C1的数据类型转换为椭圆曲线上的点,验证C1是否满足椭圆曲线方程,若不满足则报错并退出")
    l = ceil(log(p, 2)/8)         # l是一个域元素（比如一个点的横坐标）转换为字节串后的字节长度.则未压缩的形式下秘闻第一部分C1长度为2l+1
    bytes_l1 = 2*l+1
    print("计算得到的C1的字节串长度是:", bytes_l1)
    hex_l1 = bytes_l1 * 2            # hex_l1是密文第一部分C1的十六进制串的长度
    C_bytes = hex_to_bytes(C)
    print("将十六进制密文串转换为字节串", C_bytes)
    C1_bytes = C_bytes[0:2*l+1]
    print("从密文字节串中取出的C1的字节串", C1_bytes)
    C1 = bytes_to_point(C1_bytes)
    print("将C1字节串转换为椭圆曲线上的点是", C1)
    if not charge_oncurve(args, C1):          # 检验C1是否在椭圆曲线上
        raise Exception("在解密算法B1中，取得的C1不在椭圆曲线上！")
    print("经验证C1在椭圆曲线上")
    x1, y1 = C1[0], C1[1]
    x1_hex, y1_hex = field_to_hex(x1), field_to_hex(y1)
    # print("C1坐标用的十六进串形式表示是：", (x1_hex, y1_hex))
    print()
    print("2) 计算椭圆曲线点S=[h]C1，若S是无穷远点，则报错并退出")
    S = mult_point(C1, h, p, a)
    print("计算得到 S:", S)
    if S == 0:
        raise Exception("在解密算法B2中,S是无穷远点,不符合要求")
    xS, yS = S[0], S[1]
    xS_hex, yS_hex = field_to_hex(xS), field_to_hex(yS)
    # print("S的坐标用十六进制串形式表示是：", (xS_hex, yS_hex))
    print()
    print("3) 计算[dB]C1=(x2,y2)，将坐标x2、y2的数据类型转换为比特串")
    temp = mult_point(C1, dB, p, a)
    x2, y2 = temp[0], temp[1]
    x2_hex, y2_hex = field_to_hex(x2), field_to_hex(y2)
    print("解密得到的[dB]C1=(x2,y2)的十六进制串形式是：", (x2_hex, y2_hex))
    print()
    print("4) 计算t=KDF(x2 ∥ y2, klen)，若t为全0比特串，则报错并退出")
    hex_l3 = 64           # hex_l3是密文第三部分C3的十六进制串的长度。C3是通过SM3得到的hash值，是64位十六进制串。
    hex_l2 = len(C) - hex_l1 - hex_l3           # hex_l2是密文第二部分C2的十六进制串的长度。
    klen = hex_l2 * 4           # klen是密文C2中比特串的长度
    print("计算的C2的比特串长度 klen =  ", klen)
    x2_bits, y2_bits = hex_to_bits(x2_hex), hex_to_bits(y2_hex)
    t = KDF(x2_bits + y2_bits, klen)
    print("计算得 t = KDF(x2 ∥ y2, klen) = ", t)
    if eval('0b' + t) == 0:
        raise Exception("在解密算法B4中,得到的t是全0串,请检查参数")
    t_hex = bits_to_hex(t)
    print("t的十六进制串形式是：", t_hex)
    print()
    print("5) 从C中取出比特串C2，计算M′ = C2 ⊕ t；")
    C2_hex = C[hex_l1: -hex_l3] #负数表示从结尾开始倒数
    print("C2 = ", C2_hex)
    M1 = eval('0x' + C2_hex + '^' + '0x' + t_hex)           # M1是M'，M′ = C2 ⊕ t
    M1_hex = hex(M1)[2:].rjust(hex_l2, '0')         # 注意位数要一致
    print("计算得 M′ = C2 ⊕ t = ", M1_hex)
    print()
    print("6) 计算u = Hash(x2 ∥ M′ ∥ y2),从C中取出比特串C3,若u != C3,则报错并退出；")
    M1_bits = hex_to_bits(M1_hex)
    cmp_bits = x2_bits + M1_bits + y2_bits          # cmp_bits存储用于计算哈希值以对比C3的二进制串
    cmp_bytes = bits_to_bytes(cmp_bits)
    cmp_list = [i for i in cmp_bytes]
    u = sm3.sm3_hash(cmp_list)          # u中存储
    print("计算得 u = Hash(x2 ∥ M′ ∥ y2) = ", u)
    C3_hex = C[-hex_l3:]
    print("从C中取出C3")
    print("C3 = ",C3_hex)
    if u != C3_hex:
        raise Exception("在解密算法B6中,计算的u与C3不同,请检查参数")
    print()
    print("7) 输出明文M′")
    M_bytes = hex_to_bytes(M1_hex)
    M = str(M_bytes, encoding='ascii')
    print("解密出的明文是：", M)
    return M

# 椭圆曲线系统参数args(p, a, b, h, G, n)的获取。
def get_args():
    p = eval('0x' + 'FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF'.replace(' ', ''))
    a = eval('0x' + 'FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC'.replace(' ', ''))
    b = eval('0x' + '28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93'.replace(' ', ''))
    h = 1
    n = eval('0x' + 'FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123'.replace(' ', ''))

    xG = eval('0x' + '32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7'.replace(' ', ''))
    yG = eval('0x' + 'BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0'.replace(' ', ''))
    # G 是基点
    G = (xG, yG)
    args = (p, a, b, h, G, n)           # args存储椭圆曲线参数
    return args

# 密钥获取。本程序中主要是消息接收方B的公私钥的获取。
def get_key():
    pri, pub_x, pub_y = creat_k()
    xB = eval('0x' + pub_x.replace(' ', ''))
    yB = eval('0x' + pub_y.replace(' ', ''))
    # PB是B的公钥
    PB = (xB, yB)
    #dB是B的私钥
    dB = eval('0x' + pri.replace(' ', ''))

    key_B = (PB, dB)
    return key_B

def main():
    print("SM2椭圆曲线公钥密码算法".center(100, '-'))
    print("本算法采用256位素数域上的椭圆曲线。椭圆曲线方程为：")
    print("y^2 = x^3 + ax + b")

    print("第1部分:获取相关参数".center(100, '-'))
    # 这里作为后续加解密算法参数的是元组args和key_B，ascii字符串明文消息M。均为不可变序列
    print("--获取椭圆曲线系统参数--")
    args = get_args()  # 获取椭圆曲线系统参数
    p, a, b, h, G, n = args  # 序列解包
    p, a, b, h, xG, yG, n = tuple(map(lambda a: hex(a)[2:], (p, a, b, h, G[0], G[1], n)))  # 将参数转换为十六进制串便于输出
    print("椭圆曲线系统所在素域的p是：", p)
    print("椭圆曲线系统的参数a是：", a)
    print("椭圆曲线系统的参数b是：", b)
    print("椭圆曲线系统的余因子h是：", h)
    print("椭圆曲线系统的基点G的横坐标xG是：", xG)
    print("椭圆曲线系统的基点G的纵坐标yG是：", yG)

    print("--获取接收方B的公私钥--")
    key_B = get_key()  # 设置消息接收方的公私钥
    PB, dB = key_B  # 序列解包，PB是公钥，是以元组形式存储的点(xB, yB), dB是私钥，是整数
    xB, yB, dB = tuple(map(lambda a: hex(a)[2:], (PB[0], PB[1], dB)))
    print("接收方B的公钥:")
    print("(%s,%s)" % (xB, yB))
    print("接收方B的私钥:")
    print(dB)
    print("--获取明文--")
    M = input('请输入明文(ascii字符串):')
    print("获取的明文是:", M)
    print("第2部分 加密算法部分".center(100, '-'))
    C = encry_sm2(args, PB, M)  # 加密算法的参数是椭圆系统参数，B的公钥PB，ascii字符串形式的明文消息M。返回十六进制串形式的密文消息

    print("第3部分 解密算法部分".center(100, '-'))
    de_M = decry_sm2(args, key_B[1], C)  # 解密算法的参数是椭圆曲线系统参数，B的私钥dB，十六进制串形式的密文消息。返回ascii字符串形式的明文消息M

    print("第4部分 明文验证".center(100, '-'))
    print("原始明文是：", M)
    print("解密得到的明文是：", de_M)
    if M == de_M:
        print("明文成功恢复")
    else:
        print("解密失败,请检查算法")


if __name__ == "__main__":
    main()
