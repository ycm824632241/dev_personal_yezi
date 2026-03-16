import random
import math

def cul_mod(m,e,n):
    #快速模指数运算函数/m为底数，e为指数，n为模数 (L^e mod n)
    r = 1
    while e > 0:
        if (e % 2) == 1: # e为奇数
            r = (r * m) % n

        m = (m * m) % n
        e = e >> 1
    return r

def cul_fermat():
    #费马素性检测主要函数
    fm = open("integer.txt", "r")
    N = int(fm.read())
    print("读取整数:" + str(N))

    k = int(input("输入安全参数k: "))
    i = 1

    while i <= k: #共k次计算
        d = random.randint(2, N - 2)
        #生成随机数d
        print("k="+str(i)+" 生成的随机数:"+str(d),end=",")
        # 计算gcd(d,n)
        # h = math.gcd(d, N)
        h = pow(d,N-1,N)
        # 计算d^(n-1)mod n
        r = cul_mod(d, N - 1, N)

        if h != 1:
            # print("(%d,%d)=%d" % (d, N, h))
            print('\ngcd(d,n)!= 1,该数为合数')
            break
        elif(r != 1):
            # print("%d**%d(mod %d)=%d" % (d, N - 1, N, r))
            print('\nL^(n-1) mod n !=1,该数为合数')
            break
        else:
           # print("N = " + str(N))
           print('\n可能为素数')
           i += 1
    if(i == k+1):
           print("该数为素数的概率为: "+str( (1-1/(math.pow(2,k))) * 100)+"%" )

if __name__ == '__main__':
    cul_fermat()