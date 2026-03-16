import libnum
from Crypto.Util.number import long_to_bytes

n=920139713
q=18443
p=49891
e=19

c= 822
d = libnum.invmod(e, (p - 1) * (q - 1)) 		#invmod(a, n) - 求a对于n的模逆,这里逆向加密过程中计算ψ(n)=(p-1)(q-1)，对ψ(n)保密,也就是对应根据ed=1modψ(n),求出d
m = pow(c, d, n)  						# pow(x, y[, z])--函数是计算 x 的 y 次方，如果 z 在存在，则再对结果进行取模，其结果等效于 pow(x,y) %z，对应前面解密算法中M=D(C)=C^d(mod n)
#print(m) #明文的十进制格式

print(m)
