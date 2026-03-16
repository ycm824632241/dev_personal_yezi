from math import gcd, ceil, log
from gmssl import sm3

#----------数据类型转换----------
# 整数到字节串的转换。接收非负整数x和字节串的目标长度k，k满足2^8k > x。返回值是长为k的字节串。k是给定的参数。
def int_to_bytes(x, k):         # 整体思路是先左填充0将x变为k*8位16进制数串，再每2位合成1个字节
    if pow(256, k) <= x:
        raise Exception("无法实现整数到字节串的转换，目标字节串长度过短！")
    s = hex(x)[2:].rjust(k*2, '0')          # s是k*2位十六进制串
    M = b''
    for i in range(k):
        M = M + bytes([eval('0x' + s[i*2:i*2+2])])
    return M


# 字节串到整数的转换。接受长度为k的字节串。返回值是整数x
def bytes_to_int(M):            # 整体思路是从后向前遍历M，每个字节的基数是2^8。
    k = len(M)          # k是字节串的长度
    x = 0           # x存储最后的整数
    for i in range(k-1, -1, -1):
        x += pow(256, k-1-i) * M[i]
    return x


# 比特串到字节串的转换。接收长度为m的比特串s。返回长度为k的字节串M。其中k = [L/8] 向上取整。
def bits_to_bytes(s):           # 先判断字符串整体是否能正好转换为字节串，即长度是否为8的倍数。若不是则左填充至长度为8的倍数。
    k = ceil(len(s)/8)          # 比特串长度除以8向上取整
    s = s.rjust(k*8, '0')           # 若能整除这一步相当于没有，若不能则相当于将其左填充为长度能被8整除得k
    M = b''         # M存储要返回的字节串
    for i in range(k):
        M = M + bytes([eval('0b' + s[i*8: i*8+8])])
    return M


# 字节串到比特串的转换。接收长度为k的字节串M，返回长度为m的比特串s，其中m = 8k。字节串逐位处理即可。
def bytes_to_bits(M):           # 整体思路是把每个字节变为8位比特串，用列表存储，最后连接起来
    s_list = []
    for i in M:
        s_list.append(bin(i)[2:].rjust(8, '0'))         # 每次循环存储1个字节。左填充补0
    s = ''.join(s_list)
    return s


# 域元素到字节串的转换。域元素是整数，转换成字节串要明确长度。文档规定域元素转换为字节串的长度是ceil(ceil(log(q, 2)/8))。接收的参数是域元素，返回字节串M
def field_to_bytes(e):
    q = eval('0x' + 'FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF'.replace(' ', ''))
    #ceil向上取整 t为域的大小
    t = ceil(log(q, 2))
    l = ceil(t / 8)
    return int_to_bytes(e, l)


# 字节串到域元素的转换。直接调用bytes_to_int()。接收的参数是字节串M，返回域元素a
def bytes_to_fielde(M):         # 域元素不用填充
    return bytes_to_int(M)


# 域元素到整数的转换
def fielde_to_int(a):           # 直接返回
    return a


# 点到字节串的转换。接收的参数是椭圆曲线上的点p，元组表示。输出字节串S。选用未压缩表示形式
def point_to_bytes(P):
    xp, yp = P[0], P[1]
    x = field_to_bytes(xp)
    y = field_to_bytes(yp)
    PC = bytes([0x04])
    s = PC + x + y
    return s


# 字节串到点的转换。接收的参数是字节串s，返回椭圆曲线上的点P，点P的坐标用元组表示
def bytes_to_point(s):
    if len(s) % 2 == 0:
        raise Exception("无法实现字节串到点的转换，请检查字节串是否为未压缩形式！")
    l = (len(s) - 1) // 2
    PC = s[0]
    if PC != 4:
        raise Exception("无法实现字节串到点的转换，请检查PC是否为b'04'！")
    x = s[1: l+1]
    y = s[l+1: 2*l+1]
    xp = bytes_to_fielde(x)
    yp = bytes_to_fielde(y)
    P = (xp, yp)            # 此处缺少检验点p是否在椭圆曲线上
    return P


#----------SM2算法相关转换----------
# 域元素到比特串
def field_to_bits(a):
    a_bytes = field_to_bytes(a)
    a_bits = bytes_to_bits(a_bytes)
    return a_bits


# 点到比特串
def point_to_bits(P):
    p_bytes = point_to_bytes(P)
    p_bits = bytes_to_bits(p_bytes)
    return p_bits


# 整数到比特串
def int_to_bits(x):
    x_bits = bin(x)[2:]
    k = ceil(len(x_bits)/8)         # 8位1组，k是组数。目的是方便对齐
    x_bits = x_bits.rjust(k*8, '0')
    return x_bits


# 字节串到十六进制串
def bytes_to_hex(m):
    h_list = []         # h_list存储十六进制串中的每一部分
    for i in m:
        e = hex(i)[2:].rjust(2, '0')            # 不能把0丢掉
        h_list.append(e)
    h = ''.join(h_list)
    return h


# 比特串到十六进制
def bits_to_hex(s):
    s_bytes = bits_to_bytes(s)
    s_hex = bytes_to_hex(s_bytes)
    return s_hex


# 十六进制串到比特串
def hex_to_bits(h):
    b_list = []
    for i in h:
        b = bin(eval('0x' + i))[2:].rjust(4, '0')           # 增强型for循环，是i不是h
        b_list.append(b)
    b = ''.join(b_list)
    return b


# 十六进制到字节串
def hex_to_bytes(h):
    h_bits = hex_to_bits(h)
    h_bytes = bits_to_bytes(h_bits)
    return h_bytes


# 域元素到十六进制串
def field_to_hex(e):
    h_bytes = field_to_bytes(e)
    h = bytes_to_hex(h_bytes)
    return h


#----------特殊函数与运算----------
# 模逆算法。返回M模m的逆。在将分式模运算转换为整数时用，分子分母同时乘上分母的模逆。
def cal_inverse(M, m):
    if gcd(M, m) != 1:
        return None
    u1, u2, u3 = 1, 0, M
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m


# 将分式模运算转换为整数。输入 up/down mod L, 返回该分式在模m意义下的整数。点加和二倍点运算时求λ用。
def fraction_to_int(up, down, p):
    num = gcd(up, down)
    up //= num
    down //= num         # 分子分母约分
    return up * cal_inverse(down, p) % p


# 椭圆曲线上的点加运算。接收的参数是元组P和Q，表示相加的两个点，p为模数。返回二者的点加和
def add_point(P, Q, p):
    if P == 0:
        return Q
    if Q == 0:
        return P
    x1, y1, x2, y2 = P[0], P[1], Q[0], Q[1]
    e = fraction_to_int(y2 - y1, x2 - x1, p)  # e为λ
    x3 = (e*e - x1 - x2) % p            # 注意此处也要取模
    y3 = (e * (x1 - x3) - y1) % p
    ans = (x3, y3)
    return ans


# 二倍点算法。不能直接用点加算法，否则会发生除零错误。接收的参数是点P，素数p，椭圆曲线参数a。返回P的二倍点。
def double_point(P, p, a):
    if P == 0:
        return P
    x1, y1 = P[0], P[1]
    e = fraction_to_int(3 * x1 * x1 + a, 2 * y1, p)  # e是λ
    x3 = (e * e - 2 * x1) % p        
    y3 = (e * (x1 - x3) - y1) % p
    Q = (x3, y3)
    return Q


# 多倍点算法。通过二进制展开法实现。接收的参数[k]p是要求的多倍点，m是模数，a是椭圆曲线参数。
def mult_point(P, k, p, a):
    s = bin(k)[2:]          # s是k的二进制串形式
    Q = 0
    for i in s:
        Q = double_point(Q, p, a)
        if i == '1':
            Q = add_point(P, Q, p)
    return Q


# 验证某个点是否在椭圆曲线上。接收的参数是椭圆曲线系统参数args和要验证的点P(x, y)。
def charge_oncurve(args, P):
    p, a, b, h, G, n = args
    x, y = P
    if pow(y, 2, p) == ((pow(x, 3, p) + a*x + b) % p):
        return True
    return False