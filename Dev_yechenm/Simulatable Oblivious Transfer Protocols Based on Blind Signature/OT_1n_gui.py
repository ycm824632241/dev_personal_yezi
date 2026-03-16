from __future__ import annotations  # 新增：解决低版本Python类型注解泛型问题
from gmpy2 import mpz, powmod, random_state, is_prime, invert
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import os
import sys
import time
from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QLabel, QTextEdit, QLineEdit, QGroupBox, QFormLayout)
from PyQt6.QtCore import QThread, pyqtSignal, QObject


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


# -------------------------- GUI Worker for long tasks --------------------------
class Worker(QObject):
    finished = pyqtSignal(object)
    log = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.gdh = None

    def run_gdh_init(self):
        try:
            self.log.emit("系统启动，开始在后台初始化GDH群参数（可能需要几十秒）...")
            start_time = time.time()
            self.gdh = GDHGroup(security_param=160)
            duration = time.time() - start_time
            self.log.emit(f"✅ GDH群参数初始化完成，耗时 {duration:.2f} 秒。")
            self.log.emit(f"   - 群阶p (前32位): {hex(self.gdh.p)[:32]}...")
            self.log.emit(f"   - 生成元g (前32位): {hex(self.gdh.g)[:32]}...")
            self.finished.emit(self.gdh)
        except Exception as e:
            self.error.emit(f"❌ GDH群初始化失败: {e}")


# -------------------------- PyQt6 GUI --------------------------
class OT_GUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("基于盲签名的不经意传输协议 (PyQt6)")
        self.setGeometry(100, 100, 1200, 800)

        # --- Protocol state ---
        self.gdh = None
        self.ot_protocol = None
        self.public_params = None
        self.private_params = None
        self.secrets = []
        self.query_data = None
        self.response_data = None

        # --- Layout ---
        main_layout = QHBoxLayout(self)
        left_layout = QVBoxLayout()

        # --- Widgets ---
        self.sender_group = self._create_sender_group()
        self.receiver_group = self._create_receiver_group()
        self.log_group = self._create_log_group()

        left_layout.addWidget(self.sender_group)
        left_layout.addWidget(self.receiver_group)
        left_layout.addStretch()

        main_layout.addLayout(left_layout, 1)
        main_layout.addWidget(self.log_group, 2)

        self._init_worker()

    def _init_worker(self):
        self.thread = QThread()
        self.worker = Worker()
        self.worker.moveToThread(self.thread)

        self.worker.log.connect(self.log)
        self.worker.error.connect(self.log)
        self.worker.finished.connect(self._on_gdh_init_finished)

        self.thread.started.connect(self.worker.run_gdh_init)
        self.thread.start()

    def _on_gdh_init_finished(self, gdh_instance):
        self.gdh = gdh_instance
        self.ot_protocol = OT1n(self.gdh)
        self.sender_init_button.setEnabled(True)
        self.thread.quit()

    def _create_sender_group(self):
        group = QGroupBox("发送方 (Sender)")
        layout = QFormLayout()

        self.secrets_text = QTextEdit()
        self.secrets_text.setPlaceholderText("每行一个秘密")
        self.secrets_text.setText("secret1: 123456\nsecret2: abcdef\nsecret3: 7890ab")
        layout.addRow(QLabel("输入秘密:"), self.secrets_text)

        hint_label = QLabel("一行为一个秘密，至少输入一个秘密")
        hint_label.setStyleSheet("color: gray; font-style: italic;")
        layout.addRow("", hint_label)

        self.sender_init_button = QPushButton("1. 初始化发送方")
        self.sender_init_button.setEnabled(False)
        self.sender_init_button.clicked.connect(self.run_sender_init)

        self.sender_resp_button = QPushButton("3. 生成响应")
        self.sender_resp_button.setEnabled(False)
        self.sender_resp_button.clicked.connect(self.run_sender_response)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.sender_init_button)
        button_layout.addWidget(self.sender_resp_button)
        layout.addRow(button_layout)

        group.setLayout(layout)
        return group

    def _create_receiver_group(self):
        group = QGroupBox("接收方 (Receiver)")
        layout = QFormLayout()

        self.sigma_entry = QLineEdit("2")
        layout.addRow(QLabel("选择秘密的索引 (σ):"), self.sigma_entry)

        self.receiver_query_button = QPushButton("2. 生成查询")
        self.receiver_query_button.setEnabled(False)
        self.receiver_query_button.clicked.connect(self.run_receiver_query)

        self.receiver_decrypt_button = QPushButton("4. 解密秘密")
        self.receiver_decrypt_button.setEnabled(False)
        self.receiver_decrypt_button.clicked.connect(self.run_receiver_decrypt)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.receiver_query_button)
        button_layout.addWidget(self.receiver_decrypt_button)
        layout.addRow(button_layout)

        group.setLayout(layout)
        return group

    def _create_log_group(self):
        group = QGroupBox("交互日志")
        layout = QVBoxLayout()
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text)
        group.setLayout(layout)
        return group

    def log(self, message):
        timestamp = time.strftime('%H:%M:%S')
        self.log_text.append(f"[{timestamp}] {message}")

    def run_sender_init(self):
        self.log("\n" + "="*20 + " 步骤 1: 发送方初始化 " + "="*20)
        secrets_str = self.secrets_text.toPlainText().strip()
        if not secrets_str:
            self.log("❌ 错误: 请输入至少一个秘密。")
            return
        self.secrets = secrets_str.split('\n')
        self.log(f"发送方持有 {len(self.secrets)} 个秘密: {self.secrets}")

        try:
            self.public_params, self.private_params = self.ot_protocol.sender_init(self.secrets)
            pub_key, ciphertexts = self.public_params
            priv_key, aes_keys = self.private_params

            self.log("发送方生成了签名密钥对。")
            self.log(f"  - 公钥 y (前32位): {hex(pub_key)[:32]}...")
            self.log("发送方为每个秘密生成了AES密钥并加密。")
            for i, key in enumerate(aes_keys):
                self.log(f"  - AES密钥 {i+1}: {key.hex()}")
            for i, (iv, ct) in enumerate(ciphertexts):
                self.log(f"  - 密文 {i+1} (IV+CT): {iv.hex()} + {ct.hex()[:32]}...")

            self.log("✅ 发送方初始化完成。现在接收方可以生成查询。")
            self.receiver_query_button.setEnabled(True)
            self.sender_resp_button.setEnabled(False)
            self.receiver_decrypt_button.setEnabled(False)
        except Exception as e:
            self.log(f"❌ 发送方初始化失败: {e}")

    def run_receiver_query(self):
        self.log("\n" + "="*20 + " 步骤 2: 接收方生成查询 " + "="*20)
        try:
            sigma = int(self.sigma_entry.text())
            if not (1 <= sigma <= len(self.secrets)):
                self.log(f"❌ 错误: σ 的值必须在 1 到 {len(self.secrets)} 之间。")
                return
        except ValueError:
            self.log("❌ 错误: σ 必须是一个整数。")
            return

        self.log(f"接收方选择获取第 {sigma} 个秘密。")
        try:
            self.query_data = self.ot_protocol.receiver_query(sigma, self.public_params)
            blind_msg, r, _ = self.query_data
            self.log("接收方已对选择的秘密标识进行盲化。")
            self.log(f"  - 盲化因子 r (前32位): {hex(r)[:32]}...")
            self.log(f"  - 盲消息 (前32位): {hex(blind_msg)[:32]}...")
            self.log("✅ 查询已生成。现在发送方可以生成响应。")
            self.sender_resp_button.setEnabled(True)
        except Exception as e:
            self.log(f"❌ 接收方查询失败: {e}")

    def run_sender_response(self):
        self.log("\n" + "="*20 + " 步骤 3: 发送方生成响应 " + "="*20)
        if not self.query_data:
            self.log("❌ 错误: 请先让接收方生成查询。")
            return

        blind_msg, _, _ = self.query_data
        self.log("发送方收到了盲消息，开始生成响应。")
        try:
            self.response_data = self.ot_protocol.sender_response(blind_msg, self.private_params, self.public_params)
            Y_sigma, C_j_list = self.response_data
            self.log("发送方已对盲消息签名并生成了加密的AES密钥。")
            self.log(f"  - Y_σ (前32位): {hex(Y_sigma)[:32]}...")
            for i, cj in enumerate(C_j_list):
                self.log(f"  - 加密的AES密钥 C_{i+1}: {cj.hex()}")
            self.log("✅ 响应已生成。现在接收方可以解密。")
            self.receiver_decrypt_button.setEnabled(True)
        except Exception as e:
            self.log(f"❌ 发送方响应失败: {e}")

    def run_receiver_decrypt(self):
        self.log("\n" + "="*20 + " 步骤 4: 接收方解密 " + "="*20)
        if not self.response_data:
            self.log("❌ 错误: 请先让发送方生成响应。")
            return

        Y_sigma, C_j_list = self.response_data
        _, r, sigma = self.query_data
        self.log(f"接收方使用自己的盲化因子 r 和收到的 Y_σ, C_j 列表来解密第 {sigma} 个秘密。")
        try:
            decrypted_secret = self.ot_protocol.receiver_decrypt(Y_sigma, C_j_list, r, sigma, self.public_params)
            self.log(f"🎉 解密成功！")
            self.log(f"   - 得到的秘密: {decrypted_secret}")

            expected_secret = self.secrets[sigma - 1]
            self.log(f"   - 预期的秘密: {expected_secret}")
            if decrypted_secret == expected_secret:
                self.log("✅ 验证成功：解密结果与预期一致！")
            else:
                self.log("❌ 验证失败：解密结果与预期不符！")
        except Exception as e:
            self.log(f"❌ 解密失败: {e}")

# -------------------------- 主程序入口修改 --------------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = OT_GUI()
    gui.show()
    sys.exit(app.exec())
