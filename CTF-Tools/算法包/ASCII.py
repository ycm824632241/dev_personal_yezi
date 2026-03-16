# 获取字符 'A' 的 ASCII 码
ascii_code = hex(ord('b'))
print(ascii_code)  # 输出 65

# 将 ASCII 码 65 转换为字符
character = chr(65)
print(character)  # 输出 'A'
A = [65, 179, 133, 200, 129, 224, 55, 57, 204, 138, 36, 56, 245, 52, 2, 195]
for c in A:
    print(hex(c),end='')