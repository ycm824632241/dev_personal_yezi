from __future__ import annotations  # 新增：解决低版本Python类型注解泛型问题
from gmpy2 import mpz, powmod, random_state, is_prime, invert
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import os


# -------------------------- 1. 基础工具函数（统一大整数序列化） --------------------------
def int_to_bytes(n: mpz) -> bytes:
    """将大整数转为字节流（统一格式，确保发送方/接收方一致）"""
    if n == 0:
        return b'\x00'
    byte_length = (n.bit_length() + 7) // 8
    return n.to_bytes(byte_length, byteorder='big')


def bytes_to_int(b: bytes) -> mpz:
    """将字节流转为大整数（统一格式）"""
    return mpz(int.from_bytes(b, byteorder='big'))


# -------------------------- 2. GDH群实现 --------------------------
class GDHGroup:
    def __init__(self, security_param=160):
        self.rs = random_state()
        self.p = self._generate_safe_prime(2 * security_param)
        self.g = self._find_generator(self.p)
        self.q = (self.p - 1) // 2  # 子群阶（素数）

    def _generate_safe_prime(self, bits):
        while True:
            q_bytes = os.urandom((bits - 1 + 7) // 8)
            q = bytes_to_int(q_bytes)
            q = q & ((1 << (bits - 1)) - 1)
            if q > 1 and is_prime(q):
                p = 2 * q + 1
                if is_prime(p):
                    return p

    def _find_generator(self, p):
        while True:
            g_bytes = os.urandom((p.bit_length() - 1 + 7) // 8)
            g = bytes_to_int(g_bytes)
            g = g & ((1 << (p.bit_length() - 1)) - 1)
            if g > 1 and powmod(g, (p - 1) // 2, p) != 1:
                return g


# -------------------------- 3. 盲GDH签名（修复类型注解） --------------------------
class BlindGDHSignature:
    def __init__(self, gdh_group: GDHGroup):
        self.gdh = gdh_group

    def keygen(self) -> tuple[mpz, mpz]:
        """生成密钥对（x ∈ Z_q*，y = g^x）"""
        x_bytes = os.urandom((self.gdh.q.bit_length() + 7) // 8)
        x = bytes_to_int(x_bytes) % self.gdh.q
        x = x if x != 0 else 1  # 避免x=0
        y = powmod(self.gdh.g, x, self.gdh.p)
        return (x, y)

    def hash_to_group(self, data: bytes) -> mpz:
        """统一哈希到群G_p*：输入必须是字节流，输出∈[2, p-2]"""
        h = SHA256.new(data).digest()
        h_int = bytes_to_int(h)
        h_group = h_int % (self.gdh.p - 2) + 2
        return h_group

    def blind(self, data: bytes, pub_key: mpz) -> tuple[mpz, mpz]:
        """盲化：m̄ = hash_to_group(data) * g^r mod p"""
        # 生成r ∈ Z_q*
        r_bytes = os.urandom((self.gdh.q.bit_length() + 7) // 8)
        r = bytes_to_int(r_bytes) % self.gdh.q
        r = r if r != 0 else 1

        # 计算哈希（输入必须是字节流，与发送方一致）
        h_data = self.hash_to_group(data)
        g_r = powmod(self.gdh.g, r, self.gdh.p)
        blind_data = (h_data * g_r) % self.gdh.p
        return (blind_data, r)

    def sign(self, blind_data: mpz, priv_key: mpz) -> mpz:
        """签名：σ̄ = (m̄)^x mod p"""
        return powmod(blind_data, priv_key, self.gdh.p)

    def unblind(self, blind_sig: mpz, r: mpz, pub_key: mpz) -> mpz:
        """去盲：σ = σ̄ * y^(-r) mod p"""
        y_r = powmod(pub_key, r, self.gdh.p)
        y_r_inv = invert(y_r, self.gdh.p)
        return (blind_sig * y_r_inv) % self.gdh.p

    def verify(self, data: bytes, sig: mpz, pub_key: mpz) -> bool:
        """验证：σ == hash_to_group(data)^x mod p"""
        h_data = self.hash_to_group(data)
        x = self._get_x_from_y(pub_key)  # 仅演示用
        return sig == powmod(h_data, x, self.gdh.p)

    def _get_x_from_y(self, y: mpz) -> mpz:
        """从公钥反推私钥（仅演示，实际CDH难解）"""
        max_search = min(self.gdh.q, 10 ** 6)
        for x in range(1, max_search):
            if powmod(self.gdh.g, x, self.gdh.p) == y:
                return x
        raise ValueError(f"私钥未找到（搜索范围{max_search}）")


# -------------------------- 4. 1-out-of-n OT协议（修复类型注解） --------------------------
class OT1n:
    def __init__(self, gdh_group: GDHGroup):
        self.gdh = gdh_group
        self.blind_gdh = BlindGDHSignature(gdh_group)
        self.AES_KEY_LEN = 16  # AES-128
        self.AES_BLOCK_SIZE = AES.block_size  # 16字节

    def sender_init(self, secrets: list[str]) -> tuple[tuple[mpz, list[tuple[bytes, bytes]]], tuple[mpz, list[bytes]]]:
        """发送方初始化：生成密钥对、加密秘密、公开参数"""
        # 1. 生成GDH签名密钥对
        sender_priv_key, sender_pub_key = self.blind_gdh.keygen()
        # 2. 生成AES密钥并加密秘密（每个秘密对应一个AES密钥）
        aes_keys = [os.urandom(self.AES_KEY_LEN) for _ in secrets]
        ciphertexts = []
        for secret, k in zip(secrets, aes_keys):
            # AES-CBC加密（统一填充方式）
            cipher = AES.new(k, AES.MODE_CBC)
            secret_bytes = secret.encode('utf-8')
            secret_padded = pad(secret_bytes, self.AES_BLOCK_SIZE)  # 统一填充
            ct = cipher.encrypt(secret_padded)
            # 存储：IV（16字节） + 密文（字节流）
            ciphertexts.append((cipher.iv, ct))
        # 公开参数：(公钥, 密文列表)；私有参数：(私钥, AES密钥列表)
        public_params = (sender_pub_key, ciphertexts)
        private_params = (sender_priv_key, aes_keys)
        return (public_params, private_params)

    def receiver_query(self, sigma: int, public_params: tuple[mpz, list[tuple[bytes, bytes]]]) -> tuple[mpz, mpz, int]:
        """接收方查询：选择第σ个秘密，生成盲消息"""
        sender_pub_key, ciphertexts = public_params
        n = len(ciphertexts)
        assert 1 <= sigma <= n, f"σ必须在1~{n}（当前σ={sigma}）"

        # 提取第σ个密文：IV（字节） + 密文（字节）→ 序列化为字节流
        iv, ct = ciphertexts[sigma - 1]
        U_sigma = iv + ct  # U_σ是字节流，确保与发送方计算H(U_j)的输入一致

        # 盲化：对U_sigma（字节流）哈希后盲化
        blind_msg, r = self.blind_gdh.blind(U_sigma, sender_pub_key)
        return (blind_msg, r, sigma)

    def sender_response(self, blind_msg: mpz, private_params: tuple[mpz, list[bytes]],
                        public_params: tuple[mpz, list[tuple[bytes, bytes]]]) -> tuple[mpz, list[bytes]]:
        """发送方响应：生成Y_σ和加密的AES密钥{C_j}"""
        sender_priv_key, aes_keys = private_params
        sender_pub_key, ciphertexts = public_params
        n = len(ciphertexts)

        # 1. 生成发送方盲化因子r'（∈ Z_q*）
        r_prime_bytes = os.urandom((self.gdh.q.bit_length() + 7) // 8)
        r_prime = bytes_to_int(r_prime_bytes) % self.gdh.q
        r_prime = r_prime if r_prime != 0 else 1

        # 2. 计算Y_σ = (盲消息)^x * r' mod p
        blind_sig = self.blind_gdh.sign(blind_msg, sender_priv_key)
        Y_sigma = (blind_sig * r_prime) % self.gdh.p

        # 3. 计算每个C_j = K_j XOR k_j（核心：确保K_j计算与接收方一致）
        C_j_list = []
        for j in range(n):
            # 步骤1：提取第j个密文并序列化（与接收方U_σ格式完全一致）
            iv_j, ct_j = ciphertexts[j]
            U_j = iv_j + ct_j  # U_j是字节流（IV+CT）

            # 步骤2：计算H(U_j)（哈希输入是U_j字节流，与接收方一致）
            h_Uj = self.blind_gdh.hash_to_group(U_j)

            # 步骤3：计算H(U_j)^x mod p（发送方已知私钥x）
            h_Uj_x = powmod(h_Uj, sender_priv_key, self.gdh.p)

            # 步骤4：计算K_j = G(H(U_j)^x * r', j)（统一G的输入格式）
            arg = (h_Uj_x * r_prime) % self.gdh.p
            arg_bytes = int_to_bytes(arg)  # 大整数转字节流（统一格式）
            j_bytes = str(j).encode('utf-8')  # j是0-based索引，转字节流
            G_input = arg_bytes + b'_' + j_bytes  # 统一G输入格式
            K_j = SHA256.new(G_input).digest()[:self.AES_KEY_LEN]  # K_j与AES密钥同长

            # 步骤5：加密AES密钥
            C_j = bytes([a ^ b for a, b in zip(K_j, aes_keys[j])])
            C_j_list.append(C_j)

        return (Y_sigma, C_j_list)

    def receiver_decrypt(self, Y_sigma: mpz, C_j_list: list[bytes], r: mpz, sigma: int,
                         public_params: tuple[mpz, list[tuple[bytes, bytes]]]) -> str:
        """接收方解密：获取目标秘密m_σ"""
        sender_pub_key, ciphertexts = public_params
        j_target = sigma - 1  # 密文列表是0-based索引
        iv_sigma, ct_sigma = ciphertexts[j_target]

        # 1. 去盲：Y_σ * y^(-r) = H(U_σ)^x * r' mod p
        y_r = powmod(sender_pub_key, r, self.gdh.p)
        y_r_inv = invert(y_r, self.gdh.p)
        arg = (Y_sigma * y_r_inv) % self.gdh.p  # arg = H(U_σ)^x * r'

        # 2. 计算K_σ = G(arg, j_target)（与发送方G输入格式完全一致）
        arg_bytes = int_to_bytes(arg)  # 大整数转字节流（统一格式）
        j_bytes = str(j_target).encode('utf-8')  # j是0-based索引（关键！）
        G_input = arg_bytes + b'_' + j_bytes  # 与发送方G_input格式严格一致
        K_sigma = SHA256.new(G_input).digest()[:self.AES_KEY_LEN]

        # 3. 解密AES密钥：k_σ = C_σ XOR K_σ
        C_sigma = C_j_list[j_target]
        k_sigma = bytes([a ^ b for a, b in zip(K_sigma, C_sigma)])

        # 4. AES-CBC解密（统一解填充）
        try:
            cipher = AES.new(k_sigma, AES.MODE_CBC, iv=iv_sigma)
            secret_padded = cipher.decrypt(ct_sigma)
            secret = unpad(secret_padded, self.AES_BLOCK_SIZE).decode('utf-8')
            return secret
        except ValueError as e:
            # 调试信息：打印关键参数对比
            print("=" * 50)
            print("解密错误调试信息：")
            print(f"  目标j（0-based）: {j_target}")
            print(f"  arg（H(U_σ)^x * r'）: {arg}")
            print(f"  G_input字节流: {G_input.hex()}")
            print(f"  K_sigma: {K_sigma.hex()}")
            print(f"  C_sigma: {C_sigma.hex()}")
            print(f"  k_sigma: {k_sigma.hex()}")
            print(f"  IV: {iv_sigma.hex()}")
            print(f"  密文CT: {ct_sigma.hex()[:32]}...（省略部分）")
            print("=" * 50)
            raise  # 重新抛出错误，便于定位


# -------------------------- 5. k×1自适应OT协议 --------------------------
class OTk1(OT1n):
    def receiver_adaptive_query(self, sigma_list: list[int], public_params: tuple[mpz, list[tuple[bytes, bytes]]]) -> \
    list[tuple[mpz, mpz, int]]:
        queries = [self.receiver_query(sigma, public_params) for sigma in sigma_list]
        return queries

    def sender_adaptive_response(self, queries: list[tuple[mpz, mpz, int]], private_params: tuple[mpz, list[bytes]],
                                 public_params: tuple[mpz, list[tuple[bytes, bytes]]]) -> list[tuple[mpz, list[bytes]]]:
        responses = [self.sender_response(q[0], private_params, public_params) for q in queries]
        return responses

    def receiver_adaptive_decrypt(self, responses: list[tuple[mpz, list[bytes]]], queries: list[tuple[mpz, mpz, int]],
                                  public_params: tuple[mpz, list[tuple[bytes, bytes]]]) -> list[str]:
        secrets = []
        for resp, q in zip(responses, queries):
            Y_sigma, C_j_list = resp
            blind_msg, r, sigma = q
            secret = self.receiver_decrypt(Y_sigma, C_j_list, r, sigma, public_params)
            secrets.append(secret)
        return secrets


# -------------------------- 6. 测试代码 --------------------------
# -------------------------- 6. 测试代码（仅修改此部分，增加详细打印） --------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("基于盲GDH签名的不经意传输协议")
    print("=" * 60)

    # 1. 初始化GDH群（160位安全参数）
    print("\n1. 初始化GDH群...")
    gdh = GDHGroup(security_param=160)
    print(f"   群阶p（素数，前32位）: {hex(gdh.p)[:32]}...（完整长度：{gdh.p.bit_length()}位）")
    print(f"   生成元g（前32位）: {hex(gdh.g)[:32]}...（完整长度：{gdh.g.bit_length()}位）")
    print(f"   子群阶q（素数，前32位）: {hex(gdh.q)[:32]}...（完整长度：{gdh.q.bit_length()}位）")

    # 2. 测试1-out-of-3 OT协议（重点验证）
    print("\n2. 测试1-out-of-3 OT协议...")
    ot_1n = OT1n(gdh)
    # 发送方秘密（简单字符串，无特殊字符）
    secrets = [
        "secret1: 123456",
        "secret2: abcdef",
        "secret3: 7890ab"
    ]
    print(f"   发送方待传输秘密列表（共{len(secrets)}个）:")
    for idx, secret in enumerate(secrets, 1):
        print(f"     秘密{idx}: {secret}")

    # 发送方初始化
    print("\n   发送方初始化...")
    public_params, private_params = ot_1n.sender_init(secrets)
    sender_pub_key, ciphertexts = public_params
    sender_priv_key, aes_keys = private_params
    print(f"   发送方私钥x（前32位）: {hex(sender_priv_key)[:32]}...")
    print(f"   发送方公钥y = g^x（前32位）: {hex(sender_pub_key)[:32]}...")
    print(f"   生成的AES密钥列表（16字节/个）:")
    for idx, key in enumerate(aes_keys, 1):
        print(f"     AES密钥{idx}: {key.hex()}")
    print(f"   生成的密文列表（IV+CT）:")
    for idx, (iv, ct) in enumerate(ciphertexts, 1):
        print(f"     密文{idx} - IV: {iv.hex()}, CT（前32位）: {ct.hex()[:32]}...")

    # 接收方选择σ=2（1-based，对应j=1 0-based）
    sigma = 2
    print(f"\n   接收方选择: σ={sigma}（对应1-based索引，目标秘密：{secrets[sigma - 1]}）")
    print(f"   接收方开始生成查询...")
    query = ot_1n.receiver_query(sigma, public_params)
    blind_msg, r, sigma = query
    print(f"   接收方生成盲化因子r: {r}")
    print(f"   接收方生成盲消息blind_msg（前32位）: {hex(blind_msg)[:32]}...")

    # 发送方响应
    print("\n   发送方处理查询并生成响应...")
    Y_sigma, C_j_list = ot_1n.sender_response(blind_msg, private_params, public_params)
    print(f"   发送方生成响应参数Y_σ（前32位）: {hex(Y_sigma)[:32]}...")
    print(f"   发送方生成加密AES密钥列表C_j（共{len(C_j_list)}个）:")
    for idx, cj in enumerate(C_j_list, 1):
        print(f"     C_{idx}: {cj.hex()}")

    # 接收方解密
    print("\n   接收方开始解密...")
    m_sigma = ot_1n.receiver_decrypt(Y_sigma, C_j_list, r, sigma, public_params)
    print(f"   接收方解密得到的秘密: {m_sigma}")
    print(f"   预期秘密: {secrets[sigma - 1]}")

    # 验证结果
    assert m_sigma == secrets[sigma - 1], f"测试失败！预期{secrets[sigma - 1]}，实际{m_sigma}"
    print("✅ 1-out-of-n OT协议测试成功！")

    # 3. 测试k×1自适应OT协议
    print("\n3. 测试2×1自适应OT协议...")
    ot_k1 = OTk1(gdh)
    secrets_k = ["A", "B", "C", "D", "E"]
    print(f"   发送方待传输秘密列表（共{len(secrets_k)}个）: {secrets_k}")
    public_params_k, private_params_k = ot_k1.sender_init(secrets_k)
    sender_pub_key_k, ciphertexts_k = public_params_k
    sender_priv_key_k, aes_keys_k = private_params_k
    print(f"   自适应OT发送方公钥（前32位）: {hex(sender_pub_key_k)[:32]}...")
    print(f"   自适应OT生成AES密钥列表: {[k.hex() for k in aes_keys_k]}")

    # 接收方选择多个秘密
    sigma_list = [3, 5]
    print(f"\n   接收方自适应选择列表: σ_list={sigma_list}（1-based索引）")
    print(f"   对应的目标秘密: {[secrets_k[s - 1] for s in sigma_list]}")
    queries = ot_k1.receiver_adaptive_query(sigma_list, public_params_k)
    print(f"   接收方生成{len(queries)}个查询:")
    for idx, (b_msg, r_val, s_val) in enumerate(queries, 1):
        print(f"     查询{idx} - 盲化因子r: {r_val}, 盲消息（前32位）: {hex(b_msg)[:32]}...")

    # 发送方自适应响应
    print("\n   发送方生成自适应响应...")
    responses = ot_k1.sender_adaptive_response(queries, private_params_k, public_params_k)
    print(f"   发送方生成{len(responses)}个响应:")
    for idx, (Y_val, C_list) in enumerate(responses, 1):
        print(f"     响应{idx} - Y_σ（前32位）: {hex(Y_val)[:32]}..., C_j数量: {len(C_list)}")

    # 接收方自适应解密
    print("\n   接收方自适应解密...")
    secrets_received = ot_k1.receiver_adaptive_decrypt(responses, queries, public_params_k)
    print(f"   接收方解密得到的秘密列表: {secrets_received}")
    print(f"   预期秘密列表: {[secrets_k[s - 1] for s in sigma_list]}")

    # 验证结果
    assert secrets_received == [secrets_k[s - 1] for s in sigma_list], "k×1测试失败！"
    print("✅ k×1自适应OT协议测试成功！")
    print("\n" + "=" * 60)