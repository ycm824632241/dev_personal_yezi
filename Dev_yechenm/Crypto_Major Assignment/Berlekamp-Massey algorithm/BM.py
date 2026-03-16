def BM(s):
    f_min = [0]  # f_min:最低次多项式
    l = [0]  # 记录最低次多项式次数
    for i in range(len(s)): #遍历
        d = 0
        for j in f_min:  # 计算d
            d += s[i + j - max(l)]  # mod问题、序列问题
        d = d % 2

        if d == 0:  # d = 0
            l.append(l[i])
        else:  # d != 0时
            if charge_l(l):  # l0=l1=l2=...=ln
                n = i
                fn = f_min.copy()
                f_min.append(i + 1) #fn+1 = x^n+1 + 1 (即把x^n+1加入多项式)
                l.append(i + 1) #ln+1 = n + 1
            else:  # l0=l1 = ... =lm<ln
                if max(f_min) > max(fn):  # 记录m以及fm的值
                    m = n
                    fm = fn.copy()
                n = i
                fn = f_min.copy()
                if m - l[m] >= n - l[n]: # L-lm > n-ln
                    for x in fm:
                        # f_min = f_min
                        f_min.append(x + (m - l[m] - n + l[n]))
                else: # L-lm < n-ln
                    for x in f_min:
                        f_min = fm
                        f_min.append(x + (n - l[n] - m + l[m]))

                l.append(max(f_min))
    f_min = condense(f_min) #模2加法去掉多余的项
    return f_min


def condense(f_min):  #模2加法去掉多余的项
    f = list(set(f_min))
    for i in f_min:
        if f_min.count(i) % 2 == 0:
            if i in f:
                f.remove(i)
    f = sorted(f, reverse=True)
    return f


def charge_l(l):  # 判断l列表中的数字是否全部相同
    for i in range(len(l) - 1):
        if l[i] != l[i + 1]:
            return False
    return True


def listtostr(f_min):  # 还原多项式字符串并返回
    result = ''
    for i in f_min:
        if i == 0:
            result += '1'
        else:
            result += 'x^' + str(i)
        if i != f_min[-1]:
            result += '+'
    return result


def strtolist(sequence):  # 将字符串转为int形列表
    result = []
    for i in sequence:
        result.append(int(i))
    return result


if __name__ == "__main__":
    # Berlekamp–Massey 算法是一种用于求数列的最短递推式的算法
    # 在此处更改你的序列
    seq = ['10010000111101000011100000011', '00001110110101000110111100011', '10101111010001001010111100010']
    for S in seq:
        f_min = BM(strtolist(S))
        print('序列：' + S)
        print('LFSR表达式：' + listtostr(f_min)) #即最低次多项式
        print('最小级数：' + str(max(f_min)))
        print("")
