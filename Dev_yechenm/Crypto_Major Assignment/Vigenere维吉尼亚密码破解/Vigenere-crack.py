'''维吉尼亚密码破解'''
import numpy as np
import wordninja


def alpha(cipher):  # 预处理,去掉空格以及回车
    c = ''
    for i in range(len(cipher)):
        if (cipher[i].isalpha()):
            c += cipher[i]
    return c


def count_IC(cipher):  # 给定字符串计算其重合指数
    count = [0 for i in range(26)]
    L = len(cipher)
    IC = 0.0
    for i in range(len(cipher)):  #规范大小写
        if (cipher[i].isupper()):
            count[ord(cipher[i]) - ord('A')] += 1
        elif (cipher[i].islower()):
            count[ord(cipher[i]) - ord('a')] += 1
    for i in range(26):
        IC += (count[i] * (count[i] - 1)) / (L * (L - 1))
    return IC


def count_group_IC(cipher, key_len):  # 对字符串按输入个数进行分组，计算每一组的IC值返回平均值
    N = ['' for i in range(key_len)] #共有几组字符串
    IC = [0 for i in range(key_len)] #对应有几个IC值

    for i in range(len(cipher)):     #将密文根据密钥长进行分组
        flag = i % key_len
        N[flag] = N[flag] + cipher[i]

    for i in range(key_len):
        IC[i] = count_IC(N[i])       #计算每组的IC值
    # print(IC)
    print(" 长度为%d时,平均重合指数为%.5f" % (key_len, np.mean(IC)) )
    return np.mean(IC)


def key_length(cipher):  # 求密钥长度
    print(" 1 - 根据重合指数确定密钥长度" )
    key_len = 0
    mins = 5
    average = 0.0
    for i in range(1, 10):  #求出最接近0.065的值
        k = count_group_IC(cipher, i)
        if (abs(k - 0.065) < mins):
            mins = abs(k - 0.065)
            key_len = i
            average = k

    print(" 密钥长度为%d,此时重合指数每组的平均值为%.5f, 取该值为密钥长\n" % (key_len, average))
    return key_len


def count_MIC(c1, c2, n):  # n=k1-k2为偏移量,计算c1,c2互重合指数MIC
    count_c1 = [0 for i in range(26)]
    count_c2 = [0 for i in range(26)]
    L1 = len(c1)
    L2 = len(c2)
    MIC = 0

    for i in range(L1):
        if (c1[i].isupper()):
            count_c1[ord(c1[i]) - ord('A')] += 1
        elif (c1[i].islower()):
            count_c1[ord(c1[i]) - ord('a')] += 1
    for i in range(L2):
        if (c2[i].isupper()):
            count_c2[(ord(c2[i]) - ord('A') + n) % 26] += 1
        elif (c2[i].islower()):
            count_c2[(ord(c2[i]) - ord('a') + n) % 26] += 1

    for i in range(26):
        MIC = MIC + (count_c1[i] * count_c2[i] / (L1 * L2))

    return MIC


def count_offset(c1, c2):  #遍历0-25，确定两个子串最优的偏移量n=k1-k2
    n = 0
    mins = 100
    k = [0.0 for i in range(26)]
    for i in range(26):
        k[i] = count_MIC(c1, c2, i)
        # print(i,k[i])
        if (abs(k[i] - 0.065) < mins):
            mins = abs(k[i] - 0.065)
            n = i
    return n


def group_offset(cipher, key_len):  # 分组计算，得到 密钥长度个组 的最优k(偏移量)
    print(" 2 - 根据互重合指数确定密钥")

    N = ['' for i in range(key_len)]
    MIC = [0 for i in range(key_len)]
    s = [0 for i in range(key_len)]

    for i in range(len(cipher)):  # 对密文进行分组
        flag = i % key_len
        N[flag] = N[flag] + cipher[i]

    for i in range(1, key_len):  # 计算与第一组之间的相对偏移量
        s[i] = count_offset(N[0], N[i])  # s[i] = k1-k(i+1)  #count_n确定最接近0.065的值作为当前这组的偏移量
        MIC[i] = count_MIC(N[0], N[i], s[i])  # MIC[i] = MIC(1,i+1)
        print(" 第1组和第%d组之间偏移为%d时，互重合指数为%.5f" % (i + 1, s[i], MIC[i]))
    return s


def key_final(key_len, s, k):  # k为第一个子串的移位，输出密钥并返回密钥所有字母的下标
    text = ['' for i in range(key_len)]
    for i in range(key_len):
        s[i] = -s[i] + k  # k2=k1-n
        text[i] = chr((s[i]) % 26 + ord('a'))

    k = k + 97
    print(" 首字母为%c , 密钥为%s , 偏移量为%d" % (k, text, k-97))
    return s


def the_end(cipher, key_len, s):  # 输入密文密钥返回明文结果
    plain = ''
    i = 0
    while (i < len(cipher)):
        for j in range(key_len):
            if (cipher[i].isupper()):
                plain += chr((ord(cipher[i]) - ord('A') - s[j] ) % 26 + ord('A'))
            else:
                plain += chr((ord(cipher[i]) - ord('a') - s[j] ) % 26 + ord('a'))
            i += 1
            if (i == len(cipher)):
                break
                # print(plain)
    return plain


if __name__ == "__main__":
    fp = open("cipher1.txt", "r")   #读取
    cipher = ''
    for i in fp.readlines():
        cipher = cipher + i
    fp.close()

    cipher = alpha(cipher)
    key_len = key_length(cipher)
    s = group_offset(cipher, key_len)
    temp = s.copy()

    for k in range(26):
        s = temp.copy()
        s = key_final(key_len, s, k)
        plain = the_end(cipher, key_len, s)
        print(" 参考输出：" + plain[0:35] + "\n")  # 输出部分明文确定偏移量k1
    print(" 参考输出，请输入第一个子串的偏移量:", end='')
    k = int(input())
    temp = key_final(key_len, temp, k)
    plain = the_end(cipher, key_len, temp)

    '''对英文文本进行分词'''
    word = wordninja.split(plain)
    plain = ''
    for i in range(len(word)):
        plain += word[i]
        plain += ' '

    f =0
    print(" 明文为:")
    for i in plain:
        print(i,end="")
        f = f+1
        if f % 70 ==0:
            print()

    # print("明文为\n" + plain)
