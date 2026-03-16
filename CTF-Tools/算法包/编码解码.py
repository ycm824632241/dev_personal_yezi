# UTF-8 编码和解码示例
import base64
# 要编码的字符串
original_string = "你好，世界！"

# UTF-8 编码
utf8_encoded = b'\x66\x6c\x61\x67\x7b\x66\x69\x72\x73\x74\x62\x6c\x6f\x6f\x64\x7d'
print("UTF-8 编码后：", utf8_encoded)

# UTF-8 解码
decoded_string = utf8_encoded.decode('utf-8')
print("解码后的字符串：", decoded_string)


# 要编码的字符串
original_string = "你好，世界！"

# Base64 编码
utf8_encoded = original_string.encode('utf-8')  # 首先将字符串转为UTF-8字节序列
base64_encoded = b'NDFXaWVhblhBZjRWekFrVWhZd1N5N0w4RE5TTVY5NXV5akN0VDVnZVRLdzlvR0pHWGh4bzNOS3pEOEI3WGRBdHBoN1d0TkxITmpjQlRCTUZoZTd6VjRBMmk5MWo1ZUZKWFBrWjdHNEVtVUdYcmVvOXNvbWVVdnIxNHhqQzNYWTVKZ1FOUllKcjg='  # 使用Base64进行编码
print("Base64 编码后：", base64_encoded)

decoded1 = b'41WieanXAf4VzAkUhYwSy7L8DNSMV95uyjCtT5geTKw9oGJGXhxo3NKzD8B7XdAtph7WtNLHNjcBTBMFhe7zV4A2i91j5eFJXPkZ7G4EmUGXreo9someUvr14xjC3XY5JgQNRYJr8'

# Base64 解码
base64_decoded = base64.b64decode(decoded1)  # 解码Base64
decoded_string = base64_decoded.decode('utf-8')  # 将字节序列转换回字符串
print("解码后的字符串：", decoded_string)
