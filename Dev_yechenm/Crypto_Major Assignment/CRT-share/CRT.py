#Chinese remainder theorem, CRT
import math

def get_M(List_mi, m): #求M
    List_M = []
    for mi in List_mi:
        List_M.append(m // mi)
    return List_M


def get_Inverse_M(List_Mi, List_mi): #求逆M 返回List_M-1
    List_Inverse_M = []
    for i in range(len(List_Mi)):
        List_Inverse_M.append(get_Inverse(List_Mi[i], List_mi[i])[0])
    return List_Inverse_M


def get_Inverse(an, bn): #求逆
    if bn == 0:
        x = 1
        y = 0
        q = an
        return x, y, q

    ret = get_Inverse(bn, an % bn)
    x = ret[0]
    y = ret[1]
    q = ret[2]
    temp = x
    x = y
    y = temp - an // bn * y
    return x, y, q


def crt(List_ai, List_mi): #CRT主程序
    for i in range(len(List_mi)):
        for j in range(i + 1, len(List_mi)):
            if  math.gcd(List_mi[i], List_mi[j]) != 1:
                print("不满足互素条件")
                return

    print("满足条件 进行中国剩余定理计算")
    m = 1
    for mi in List_mi:
        m = m * mi
    Mi_list = get_M(List_mi, m)
    Mi_inverse = get_Inverse_M(Mi_list, List_mi)
    x = 0
    for i in range(len(List_ai)):
        x += Mi_list[i] * Mi_inverse[i] * List_ai[i]
        x %= m
    # print("计算结果为")
    # print(x)
    return x


if __name__ == '__main__':
    f = "4.txt"
    fm = open(f, "r")
    print("读取"+f)
    N = fm.read().split("\n")
    N = list(map(int, N))
    List_ai = N[0:3]
    List_mi = N[3:6]
    crt(List_ai, List_mi)


