"""DES加密主程序"""
"""DES_ciphertext.py"""

from DES_BOX import *
import re
import base64

def write_file(mess):
    try:
        f = open('DES.txt','w',encoding='utf-8')
        f.write(mess)
        f.close()
        print("文件输出成功！")
    except IOError:
        print('IO错误')

def read_file():
    try:
        f = open('DES.txt','r',encoding = 'utf-8')
        mess = f.read()
        f.close()
        print("文件读取成功！")
        return mess
    except IOError:
        print('文件加解密出错！！！')

def write_log():
    try:
        f = open('DES.txt','r',encoding = 'utf-8')
        mess = f.read()
        mess = mess.encode().hex()
        f.close()

        l = open('Log.txt','w',encoding = 'utf-8')
        l.write(mess)

    except IOError:
        print('日志出错')

#字符串转化为二进制
def str2bin(message):
    res = ""
    for i in message:  #对每个字符进行二进制转化
        tmp = bin(ord(i))[2:]  #字符转成ascii，再转成二进制，并去掉前面的0b
        for j in range(0,8-len(tmp)):   #补齐8位
            tmp = '0'+ tmp   #把输出的b给去掉
        res += tmp
    return res

#二进制转化为字符串
def bin2str(bin_str):
    res = ""
    tmp = re.findall(r'.{8}',bin_str)  #每8位表示一个字符
    for i in tmp:
        res += chr(int(i,2))  #base:将该字符串视作2进制转化为10进制
    return res

#IP盒处理
def ip_change(bin_str):
    res = ""
    for i in IP_table:
        res += bin_str[i-1]     #数组下标i-1
    return res

#IP逆盒处理
def ip_re_change(bin_str):
    res = ""
    for i in IP_re_table:
        res += bin_str[i-1]
    return res

#E盒置换
def e_str(bin_str):
    res = ""
    for i in E:
        res += bin_str[i-1]
    return res

#字符串异或操作
def str_xor(my_str1,my_str2):  #str，key
    res = ""
    for i in range(0,len(my_str1)):
        xor_res = int(my_str1[i],10)^int(my_str2[i],10)
        if xor_res == 1:
            res += '1'
        if xor_res == 0:
            res += '0'

    return res

#循环左移操作
def left_cycle(my_str,num):
    left_res = my_str[num:len(my_str)]
    #left_res = my_str[0:num]+left_res
    left_res =  left_res + my_str[0:num]
    return left_res

#秘钥的PC-1置换
def change_PC1(my_key):
    res = ""
    for i in PC_1:  #PC_1盒上的元素表示位置    只循环64次
        res += my_key[i-1]     #将密钥按照PC_1的位置顺序排列，
    return res

#秘钥的PC-2置换
def change_PC2(my_key):
    res  = ""
    for i in PC_2:
        res += my_key[i-1]
    return res

# S盒置换
def s_box(my_str):
    res = ""
    c = 0
    for i in range(0,len(my_str),6):#步长为6   表示分6为一组
        now_str = my_str[i:i+6]    #第i个分组
        row = int(now_str[0]+now_str[5],2)   #b1b6 =r   第r行
        col = int(now_str[1:5],2)   #第c列
        num = bin(S[c][row*16 + col])[2:]
        for f in range(0, 4 - len(num)):
            num = '0'+ num
        res += num
        c  += 1
    return res

# P盒置换
def p_box(bin_str):
    res = ""
    for i in  P:
        res += bin_str[i-1]
    return res

# F函数的实现
def fun_f(bin_str,key):
    first = e_str(bin_str)   #位选择函数将32位待加密str拓展至48位
    second = str_xor(first, key)  #将48位结果与子密钥Ki按位模2加    得到的结果分为8组（6*8）
    third = s_box(second)    #每组6位缩减位4位   S盒置换
    last = p_box(third)     #P盒换位处理  得到f函数的最终值
    return last

# 计算K1-K16
def get_key_list(key):
    key_list = []
    divide_output = change_PC1(key)
    key_C0 = divide_output[0:28]
    key_D0 = divide_output[28:]
    for i in SHIFT:   #左移位数
        key_c = left_cycle(key_C0, i)
        key_d = left_cycle(key_D0, i)
        key_i = change_PC2(key_c + key_d)
        key_list.append(key_i)

    return key_list

# 实现单个64位消息的加密
def des_encrypt_one(bin_mess,bin_key): #64位二进制加密的测试
    mes_ip_bin = ip_change(bin_mess)  #ip转换
    key_list = get_key_list(bin_key)  #生成子密钥
    mes_left = mes_ip_bin[0:32]
    mes_right = mes_ip_bin[32:]
    for i in range(0,15):
        mes_tmp = mes_right  #右边32位
        f_result = fun_f(mes_tmp, key_list[i])   #右32位与k的f函数值
        mes_right = str_xor(f_result,mes_left)  # R(n) = f函数的结果与L(n-1)异或
        mes_left = mes_tmp   #L(n) = R(n-1)

    f_result = fun_f(mes_right, key_list[15])  #第16次不用换位，故不用暂存右边
    mes_fin_left = str_xor(mes_left,f_result)
    mes_fin_right = mes_right

    ciphertext = ip_re_change(mes_fin_left + mes_fin_right)   #ip的逆

    return ciphertext   #返回单字符的加密结果

# 64位二进制解密的测试,注意秘钥反过来了
def des_decrypt_one(bin_mess,bin_key):
    mes_ip_bin = ip_change(bin_mess)
    #bin_key = input_key_judge(str2bin(key))
    key_lst = get_key_list(bin_key)
    lst = range(1,16)   #循环15次
    cipher_left = mes_ip_bin[0:32]
    cipher_right = mes_ip_bin[32:]
    for i in lst[::-1]:   #表示逆转列表调用
        mes_tmp = cipher_right
        cipher_right = str_xor(cipher_left,fun_f(cipher_right,key_lst[i]))
        cipher_left = mes_tmp
    fin_left = str_xor(cipher_left,fun_f(cipher_right,key_lst[0]))
    fin_right = cipher_right
    fin_output  = fin_left + fin_right
    bin_plain = ip_re_change(fin_output)
    res = bin2str(bin_plain)
    return res

#简单判断以及处理信息分组
def deal_mess(bin_mess):
    ans = len(bin_mess)
    if ans % 64 != 0:
        for i in range( 64 - (ans % 64)):           #不够64位补充0
            bin_mess += '0'
    return bin_mess

#查看秘钥是否为64位
def input_key_judge(bin_key):
    ans = len(bin_key)
    if len(bin_key) < 64:
        if ans % 64 != 0:
            for i in range(64 - (ans % 64)):  # 不够64位补充0
                bin_key += '0'
    else:
        bin_key = bin_key[0:64]    #秘钥超过64位的情况默认就是应该跟密文一样长
    return bin_key

# 实现所有消息的加密
def message_encrypt(message,key):
        bin_mess = deal_mess(str2bin(message)) #得到明文的二进制比特流  64的倍数
        res = ""
        bin_key = input_key_judge(str2bin(key))   #得到密钥得二进制比特流 64的倍数
        tmp = re.findall(r'.{64}',bin_mess)    #单词加密只能实现8个字符，匹配为每64一组的列表
        for i in tmp:
            res += des_encrypt_one(i, bin_key)  #将每个字符加密后的结果再连接起来
        return res

def message_decrypt(message,key):
    bin_mess = deal_mess(str2bin(message))
    res = ""
    bin_key = input_key_judge(str2bin(key))
    tmp = re.findall(r'.{64}',bin_mess)
    for i in tmp:
        res += des_decrypt_one(i,bin_key)
    return res

def begin_des():
    print("请选择功能：")
    print("1 - 使用DES加密")
    print("2 - 使用DES解密")
    mode = input()
    if mode == '1':
        print("请输入待加密信息:")
        message = input().replace(' ','')
        print("请输入秘钥 Key:")
        key = input().replace(' ','')
        s = message_encrypt(message, key)
        out_mess = bin2str(s)
        # print("密文:"+ out_mess)
        write_file(out_mess)
        write_log()
    elif mode == '2':
        print("请输入你的秘钥 Key:")
        key = input().replace(' ', '')
        message = read_file()
        s = message_decrypt(message, key)
        print("明文："+ s)
    else:
        print("请重新输入")

if __name__ == '__main__':
    while True:
        begin_des()
