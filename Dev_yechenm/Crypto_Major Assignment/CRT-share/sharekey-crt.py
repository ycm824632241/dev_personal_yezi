import random
import CRT

def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)


def get_NM(d, t):
    N = 1
    M = 1
    for i in range(0, t):
        N = N * d[i]
    for i in range(len(d) - t + 1, len(d)):
        M = M * d[i]
    return N, M


def get_ki(d, K):
    ki = [1]*len(d)
    for i in range(0, len(d)):
        ki[i] = K % d[i]
    return ki

def crt_sharekey(k, d, t): #选取t个元素恢复明文
    k = k[0:t]
    d = d[0:t]
    # ki = K mod di
    result = CRT.crt(k, d)
    return result

def judge_d(m, num): #判断d是否互素
    flag = 1
    for i in range(0, num):
        for j in range(0, num):
            if (gcd(m[i], m[j]) != 1) & (i != j):
                flag = 0
                break
    return flag


def get_di(n,p):  #di生成
    d = [1] *n
    temp = random.randint(pow(10, p), pow(10, p+1))
    d[0] = temp
    i = 1
    while i < len(d):
        temp = random.randint(pow(10, p), pow(10, p+1))

        d[i] = temp
        if judge_d(d, i + 1) == 1:
            i = i + 1
    d.sort()
    return d


k = int(input("请输入秘密k（需要被拆分的原始秘密）:"))
t = int(input("请输入t（最少需要多少个子密钥才能恢复秘密）:"))
n = int(input("请输入n（需要生成的子密钥总数）:"))
flag = int(input("选择计算方式 1）t个密钥恢复 2）t-1个密钥恢复："))

p = int(len(str(k))/t)

d = get_di(n, p)
N, M = get_NM(d, t)
print("N的值为：")
print(N)
print("M的值为：")
print(M)

ki = get_ki(d, k)
if flag == 1:
    result = crt_sharekey(ki, d, t)
if flag == 2:
    result = crt_sharekey(ki, d, t-1)

print("最后恢复的明文为:")
print(result)
if result == k:
    print("恢复正确！")
else:
    print("恢复错误！")
