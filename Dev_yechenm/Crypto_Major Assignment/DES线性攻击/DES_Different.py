################################################################
#                       DES三轮差分分析                          #
################################################################
from DES import *

P_C = []  # 存放输入5组的明密文对，是16进制的
# S盒输入输出异或分布S[8][64][16]=[int(11..101),...]
Sxor_i_in_out = [
    [
        [
            [] for outxor in range(16)  # 然后是输出异或 ，最内层存的是B和B_,满足BxorB_
        ] for inxor in range(64)  # 然后是输入异或
    ] for i in range(8)  # 最外层是8个S盒
]
# P_1   P逆盒
P_1 = [
    9, 17, 23, 31, 13, 28, 2, 18,
    24, 16, 30, 6, 26, 20, 10, 1,
    8, 14, 25, 3, 4, 29, 11, 19,
    32, 12, 22, 7, 5, 27, 15, 21
]
diff_Key = [[] for i in range(8)]
int2bit6 = lambda num: '{:0>6}'.format(bin(num)[2:])  # 用于10进制数字转二进制字符串
int2bit4 = lambda num: '{:0>4}'.format(bin(num)[2:])
xor_bstr = lambda a, b: hex2bin(hex(int(a, 2) ^ int(b, 2))[2:])  # 两个二进制字符串异或，返回二进制字符串异或值


# 先写明白差分的基础模型
def ChiperOne(P1, C1, P2, C2):
    sbox = ['6', '4', 'c', '5', '0', '7', '2', 'e', '1', 'f', '3', 'd', '8', 'a', '9', 'b']
    sbox_1 = ['4', '8', '6', 'a', '1', '3', '0', '5', 'c', 'e', 'd', 'f', '2', 'b', '7', '9']
    p1 = hex2bin(P1)
    p2 = hex2bin(P2)
    p1p2 = xor_bstr(p1, p2)
    c1 = hex2bin(C1)
    c2 = hex2bin(C2)
    k2 = []
    # 穷举密钥k2，找到 让式子 p1p2 = S^-1[k2 xor c1] xor S^-1[k2 xor c2]成立的k2
    for i in range(15):
        k = hex_bin_box[hex(i)[-1]]
        # 为了异或和S盒，需要在int和hex和bstr间来回转换，不过为了看清楚逻辑，就先不考虑代码了
        if int(p1p2, 2) == int(sbox_1[int(xor_bstr(k, c1), 2)], 16) ^ int(sbox_1[int(xor_bstr(k, c2), 2)], 16):
            k2.append(k)
    k1 = []
    for k in k2:
        k1.append(xor_bstr(hex2bin(sbox_1[int(xor_bstr(k, c1), 2)]), p1))
    return k1, k2


def ChiperTwo(P1, C1, P2, C2):  # 使用异或可以不转成2进制串，操作16进制就行了
    # 关键：S盒的输出异或，如果输入异或是f，那么输出异或是d的概率是10/16,选择密文攻击情况下，取密文c1c2 = f，
    p1p2 = int(P1, 16) ^ int(P2, 16)  # 完全可以用int

    for i in range(15):
        count = 0
    pass


# 将输入的int过 S 盒，再转为int，返回int
def S(i, IN):
    bit6 = int2bit6(IN)
    location = int(bit6[0] + bit6[-1], 2) * 16 + int(bit6[1:-1], 2)
    return int(S_box[i][location])


# S盒的输入输出异或分布
def get_Sxor_i_in_out():
    # 每个S盒的输入输出异或分布，共八项，每项都是一个
    global Sxor_i_in_out
    for i in range(8):
        for B in range(64):
            for B_ in range(64):
                inxor = B ^ B_
                outxor = S(i, B) ^ S(i, B_)
                Sxor_i_in_out[i][inxor][outxor].append(B)


def DES_Diff(PC1, PC2):  # PC1=(P1,C1)

    # hexstr to binstr
    P1 = hex2bin(PC1[0].lower())  ### 出错位置：第一项索引是0，最后一项是-1，无语子
    C1 = hex2bin(PC1[-1].lower())
    P2 = hex2bin(PC2[0].lower())
    C2 = hex2bin(PC2[-1].lower())

    # 以下都是bin_str
    L0 = P1[:32];
    L0_ = P2[:32]

    L3 = C1[:32];
    R3 = C1[32:]
    L3_ = C2[:32];
    R3_ = C2[32:]  ### 出错位置：尽量不要复制粘贴写代码，浪费我一上午！！！！

    # 过E拓展，得到48bit的S盒预备输入
    E = translation(L3, E_box)  # bin_str
    E_ = translation(L3_, E_box)

    OUTxor = translation(xor_bstr(xor_bstr(L0, L0_), xor_bstr(R3, R3_)), P_1)  # deltaC = P_1(deltaL0^deltaR3)
    INxor = xor_bstr(E, E_)

    # 分组得到S盒的异或输入和输出
    En = [E[i:i + 6] for i in range(0, 48, 6)]
    INxor_n = [INxor[i:i + 6] for i in range(0, 48, 6)]
    OUTxor_n = [OUTxor[i:i + 4] for i in range(0, 32, 4)]

    global diff_Key
    for i in range(8):
        E_ten = int(En[i], 2)
        for B in Sxor_i_in_out[i][int(INxor_n[i], 2)][int(OUTxor_n[i], 2)]:
            diff_Key[i].append(B ^ E_ten)  # Sxor_i_in_out存的是int，最多的就是秘钥K3


def round3_DES(P, test_Key):
    # 拿到的test_Key是56位的,P是不需要过IP置换的，最后也不需要过IP逆置换
    # 获取三轮轮秘钥 Kn，没有用global关键字，应该没有问题，如果有问题回来看一下
    Cn = [test_Key[:28]]
    Dn = [test_Key[28:]]
    for i in range(3):
        Cn.append(Cn[-1][Kleft_shift[i]:] + Cn[-1][:Kleft_shift[i]])  # 注意轮秘钥K1的下标是1
        Dn.append(Dn[-1][Kleft_shift[i]:] + Dn[-1][:Kleft_shift[i]])
    Kn = [translation(Cn[i] + Dn[i], K56_48) for i in range(1, 4)]

    # 开始加密过程
    p = ''.join(hex_bin_box[i] for i in P)
    l = p[0:32]
    r = p[32:]
    for i in range(3):
        l, r = festial(l, r, Kn[i])
    return l + r


def get_key():
    # 先确定秘钥的48位，
    key_choice = [{} for i in range(8)]
    for i in range(8):
        for key in diff_Key[i]:
            count = 0
            for other in diff_Key[i]:
                if other == key:
                    count = count + 1
            key_choice[i][key] = count
    round3_Key = ''
    for i in range(8):
        for k in key_choice[i].keys():
            if key_choice[i][k] == 5:
                round3_Key += int2bit6(k)
    # 现在我们得到了48位的第三轮秘钥，通过秘钥生成方案，反向计算回去看看原始秘钥是什么
    print('round3_Key', round3_Key)

    temp_Key = ['2'] * 56
    # 先过PC2的逆
    for i in range(48):
        temp_Key[K56_48[i] - 1] = round3_Key[i]

    temp_Key = ''.join(temp_Key)

    temp_Key_l = temp_Key[:28]
    temp_Key_r = temp_Key[28:]
    shift = Kleft_shift[0] + Kleft_shift[1] + Kleft_shift[2]
    Key56_l = temp_Key_l[-shift:] + temp_Key_l[:-shift]
    Key56_r = temp_Key_r[-shift:] + temp_Key_r[:-shift]
    temp_Key56 = Key56_l + Key56_r
    # 穷举Key56的剩余位置，然后经过一次三轮加密，
    # 先找到需要猜测的秘钥位置,顺便初始化一下， 注意字符串是不可变的（不可以用下标索引来修改，但是可以下标访问）
    guess_Key = ['0'] * 56
    guess_loca = []
    for i in range(56):
        if temp_Key56[i] == '2':
            guess_loca.append(i)  # 注意此处下标从0开始算的
        else:
            guess_Key[i] = temp_Key56[i]

    right_Key56 = ''
    for i in range(2 ** 8):
        guess = '{:0>8}'.format(bin(i)[2:])
        for j in range(8):
            guess_Key[guess_loca[j]] = guess[j]
        test_Key = ''.join(guess_Key)
        # print(test_Key)
        # 接下来要用我们的test_Key去计算三轮秘钥，然后跑一次DES，如果可以把明文顺利加密为密文，就说明这个是对的秘钥
        if (round3_DES(P_C[0][0].lower(), test_Key)) == hex2bin(P_C[0][1].lower()):
            right_Key56 = test_Key
            break
    print('right_Key56', right_Key56)
    # 过PC1逆置换得到Key64的56个位置，剩余的位置是奇偶校验位
    temp_Key64 = ['1'] * 64  # 默认全是0，就是说如果某7bit的和是odd number，就可以改为1,这里使用偶校验
    for i in range(56):
        temp_Key64[K64_56[i] - 1] = right_Key56[i]  # 注意下标减1
    for i in range(8):
        sum = 0
        for j in range(7):
            sum = (sum + int(temp_Key64[i * 8 + j], 2)) % 2
        if not sum % 2 == 0:
            temp_Key64[i * 8 - 1] = '0'
    return ''.join(temp_Key64)


if __name__ == '__main__':
    # for i in range(32):
    #     print(31-i,end='  ')
    # filename = 'P_C.text'
    # with open(filename,encoding='UTF-8') as f:
    #     for row in f.readlines():
    #         P_C.append((row[5:21],row[27:-1]))  #比较笨的方法，注意检查一下，-1的索引对不对，因为-1是算进\n的
    # print(P_C)
    P_C = [('5E870BA0B559A8CF', '71BF939C0CEEE3B1'), ('E7C1F970B559A8CF', 'EAA6CE7BC9DB808B'),
           ('5D6F0803ED9FAC45', 'D99FDDD5A3016E53'), ('1EB2B007ED9FAC45', 'B49E2F61B4172078'),
           ('7ECF80BD2FE0EA99', 'C9BE22F6DA261B9A'), ('8B2CBE002FE0EA99', '2360C6F9ACD3982D'),
           ('97D2078984F010B4', '719849F28E5313BF'), ('4A5C783384F010B4', 'E4DDEEDB66776D42'),
           ('641E10E96186B8A0', '7918C1C6400F4AA2'), ('CA4E94596186B8A0', 'B8D0DC72CD2F6579')]
    get_Sxor_i_in_out()
    for i in range(0, 10, 2):
        DES_Diff(P_C[i], P_C[i + 1])  # (P1,C1) (P2,C2)
    Key64 = get_key()
    print('Key is ', Key64, hex(int(Key64, 2)))
    # f.close()


