from DES_Different import *

S_i_mask = [
            [
                [
                    -32 for beta in range(16)
                ]for alpha in range(64)
            ]for i in range(8)
]
def self_xor(num,wide):
    count=0
    for i in range(wide):
        if (num&1):
            count+=1
        num>>=1
    if(count%2==0):  #偶数个1异或就是0，
        return 0
    return 1         #奇数个1异或就是1，

def get_S_i_mask():
    for i in range(8):
        for alpha in range(64):
            for beta in range(16):
                for x in range(64):
                    if(self_xor(x & alpha,6)==self_xor(S(i,x) & beta,4)):
                        S_i_mask[i][alpha][beta] += 1
def print_S_i_mask(num):
    print('\t\t\t\t\tS{}线性分布表'.format(num))
    print('α\β\t',end='')
    for i in range(16):
        print(i,end='\t')
    print('\n')
    count = 0
    for alpha in S_i_mask[num-1]:
        print(count,end='\t\t')
        count +=1
        for NS in alpha:
            print(NS,end='\t')
        print('\n')

def get_best_linear(num):
    max = [0,0,0]  #(alpha,beta,NS)
    for i in range(1,64):
        for j in range(16):
            if abs(S_i_mask[num][i][j]) > abs(max[-1]):
                max[0],max[1],max[2] = i,j,S_i_mask[num][i][j]
    maxs=[]
    for i in range(1,64):
        try:
            maxs.append([i, S_i_mask[num][i].index(max[-1]), max[-1]])
        except ValueError:
            pass
    print('在第{}个S盒中：'.format(num+1))
    for item in maxs:
        a = int2bit6(item[0])
        b = int2bit4(item[1])
        ##要通过a和b确定秘钥位置，这是第num个盒子，
        #求(E(R0)xorK0)·a的位置
        alpha_loca = []
        beta_loca = []
        for i in range(6):
            if a[i]=='1':
                alpha_loca.append(num*6+i)   # 此时是左向右计数,从0开始计
        for i in range(4):
            if b[i]=='1':
                beta_loca.append(num*4+i)   # 此时是左向右计数
        R_local = []
        K_local = []
        F_local = []
        for i in alpha_loca:
            R_local.append(32 - E_box[i])     # 此时是从右开始计数，左到右分别是 31,30,29......2,1,0
            K_local.append(47 - i)
        for i in beta_loca:
            F_local.append(31-P_box.index(i+1))
        print('\tα={},β={},NS={},\t逼近式：P_low{r}⊕C_low{r}⊕P_h{f}⊕C_h{f}=K1{k}⊕K3{k}'.
              format(item[0],item[1],item[-1],r=R_local,f=F_local,k=K_local))



if __name__=='__main__':
    get_S_i_mask()
    # print_S_i_mask(1)
    print('最佳线性逼近式如下：')
    for i in range(8):
        get_best_linear(i)

