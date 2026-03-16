def caesar_cipher(text, shift, mode='encrypt'):
    """
    凯撒密码加解密函数。

    :param text: 需要加密或解密的文本
    :param shift: 偏移量（加密时向右移，解密时向左移）
    :param mode: 'encrypt'表示加密，'decrypt'表示解密
    :return: 加密或解密后的文本
    """
    if mode == 'decrypt':
        shift = -shift

    result = []
    for char in text:
        if char.isalpha():
            # 判断字符是大写还是小写
            offset = ord('A') if char.isupper() else ord('a')
            # 使用凯撒密码公式进行字符转换
            shifted = (ord(char) - offset + shift) % 26 + offset
            result.append(chr(shifted))
        else:
            # 非字母字符不变
            result.append(char)

    return ''.join(result)

# 示例用法
text = "Hello, World!"
shift = 3

# 加密
encrypted_text = caesar_cipher(text, shift, mode='encrypt')
print(f"加密后的文本: {encrypted_text}")

encrypted_text = 'KHOOR ZRUOG'

# 解密
decrypted_text = caesar_cipher(encrypted_text, shift, mode='decrypt')
print(f"解密后的文本: {decrypted_text}")
