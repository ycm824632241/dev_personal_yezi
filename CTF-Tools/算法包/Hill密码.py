import string
from sympy import Matrix, mod_inverse  # 更新了导入语句

# 定义字母表和映射
alphabet = string.ascii_uppercase
letter_to_num = {c: i for i, c in enumerate(alphabet)}
num_to_letter = {i: c for i, c in enumerate(alphabet)}

def clean_text(text):
    """移除非字母字符并转换为大写。"""
    return ''.join(filter(str.isalpha, text.upper()))

def text_to_numbers(text):
    """将文本转换为数字列表。"""
    return [letter_to_num[c] for c in text]

def numbers_to_text(numbers):
    """将数字列表转换回文本。"""
    return ''.join(num_to_letter[n % 26] for n in numbers)

def encrypt(plaintext, key_matrix):
    """使用 Hill 密码加密明文。"""
    plaintext = clean_text(plaintext)
    n = key_matrix.shape[0]

    # 如果必要，使用 'X' 填充明文
    if len(plaintext) % n != 0:
        plaintext += 'X' * (n - len(plaintext) % n)

    plaintext_numbers = text_to_numbers(plaintext)
    vectors = [plaintext_numbers[i:i+n] for i in range(0, len(plaintext_numbers), n)]
    ciphertext_numbers = []

    for vector in vectors:
        vector_matrix = Matrix(vector)
        result = key_matrix * vector_matrix % 26
        result = [int(num) % 26 for num in result]
        ciphertext_numbers.extend(result)

    ciphertext = numbers_to_text(ciphertext_numbers)
    return ciphertext

def decrypt(ciphertext, key_matrix):
    """使用 Hill 密码解密密文。"""
    ciphertext = clean_text(ciphertext)
    n = key_matrix.shape[0]
    ciphertext_numbers = text_to_numbers(ciphertext)
    vectors = [ciphertext_numbers[i:i+n] for i in range(0, len(ciphertext_numbers), n)]
    plaintext_numbers = []

    # 计算 key_matrix 模 26 的逆矩阵
    det = int(round(key_matrix.det())) % 26
    det_inv = mod_inverse(det, 26)
    if det_inv is None:
        raise ValueError("密钥矩阵在模 26 下不可逆")

    adjugate = key_matrix.adjugate()
    inverse_key_matrix = (det_inv * adjugate) % 26

    for vector in vectors:
        vector_matrix = Matrix(vector)
        result = inverse_key_matrix * vector_matrix % 26
        result = [int(num) % 26 for num in result]
        plaintext_numbers.extend(result)

    plaintext = numbers_to_text(plaintext_numbers)
    return plaintext

# 示例使用：
def main():
    # 示例密钥矩阵（应在模 26 下可逆）
    key_matrix = Matrix([[6, 24, 1], [13, 16, 10], [20, 17, 15]])
    plaintext = "ACT"
    print("明文:", plaintext)

    ciphertext = encrypt(plaintext, key_matrix)
    print("加密后的密文:", ciphertext)

    decrypted_text = decrypt(ciphertext, key_matrix)
    print("解密后的明文:", decrypted_text)

if __name__ == '__main__':
    main()
