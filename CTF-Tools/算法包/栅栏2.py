import math
def encrypt(message,key):
    translate_text =1
    for i in range(key):
        translate_text +=message[i::key]
    return(translate_text)


def decrypt(message,key):
    translate_text = ''
    n =math.ceil(len(message)/key)
    for i in range(n):
        translate_text +=message[i::n]
    return(translate_text)

if __name__=='__main__':
    print("1.栅栏密码加密")
    print("2.栅栏密码解密")
    mode =int(input('请选择：'))
    key =3
    if mode ==1:
        message =input('请输入需要加密的信息：').replace('','')
        translate_text =encrypt(message,key)
        print('加密结果：',translate_text)
    elif mode ==2:
        message =input('请输入需要解密的信息：')
        translate_text =decrypt(message,key)
        print('解密结果：',translate_text)