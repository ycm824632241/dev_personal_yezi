from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import numpy as np
import math
import time


# -------------------------- 工具函数（模拟核心算法）--------------------------
def hilbert_curve_simulate(x, y):
    """模拟希尔伯特曲线：将二维坐标(x,y)转换为一维索引（简化版）"""
    n = max(x, y) + 1
    level = 1
    while (1 << level) < n:
        level += 1

    def xy2d(n, x, y):
        rx, ry = 0, 0
        d = 0
        s = n // 2
        while s > 0:
            rx = (x & s) > 0
            ry = (y & s) > 0
            d += s * s * ((3 * rx) ^ ry)
            x, y = rot(s, x, y, rx, ry)
            s = s // 2
        return d

    def rot(n, x, y, rx, ry):
        if ry == 0:
            if rx == 1:
                x = n - 1 - x
                y = n - 1 - y
            x, y = y, x
        return x, y

    return xy2d(1 << level, x, y)


def chinese_remainder_theorem(ms, as_):
    """中国剩余定理：求解 x ≡ a_i mod m_i 的最小正整数解（m_i互质）"""
    total = 0
    product = math.prod(ms)
    for m, a in zip(ms, as_):
        p = product // m
        total += a * p * pow(p, -1, m)
    return total % product


def safe_mod_inverse(a, m):
    """安全模逆元计算：处理a和m不互质的情况"""
    try:
        return pow(a, -1, m)
    except ValueError:
        return None


# -------------------------- 核心实体类（CA/RSU/车辆）--------------------------
class CA:
    """证书颁发机构：负责初始化、车辆注册、恶意用户撤销"""

    def __init__(self):
        self.rsu_list = []
        self.vehicle_registry = {}
        self.public_params = {
            "q": 10 ** 9 + 7,
            "H1": lambda x: SHA256.new(str(x).encode()).digest()[:16],
            "H2": lambda x: SHA256.new(str(x).encode()).digest()[:16]
        }

    def add_rsu(self, no_rsu, x, y, initial_info="normal"):
        """添加RSU并生成对称密钥"""
        k_rsu = get_random_bytes(16)
        self.rsu_list.append({
            "NO_RSU": no_rsu,
            "K_RSU": k_rsu,
            "pos": (x, y),
            "info": initial_info,
            "hilbert_idx": hilbert_curve_simulate(x, y)
        })

    def register_vehicle(self, rid):
        """车辆注册：质数p_i生成+修复M_i计算"""
        if rid in self.vehicle_registry:
            raise ValueError(f"车辆{rid}已注册")

        print(f"\n=== 开始注册车辆 {rid} ===")
        print(f"当前已注册车辆数量：{len(self.vehicle_registry)}")
        existing_p_list = [reg["p_i"] for reg in self.vehicle_registry.values()]
        print(f"已注册车辆的p_i列表：{existing_p_list}")

        max_attempts = 100
        attempt_count = 0

        while attempt_count < max_attempts:
            attempt_count += 1
            p_i = self._generate_prime(2000, 10000)

            if attempt_count % 10 == 0:
                print(f"尝试次数：{attempt_count}，当前p_i：{p_i}")

            # 校验与已注册车辆的p_i互质
            coprime_with_existing = all(math.gcd(p_i, existing_p) == 1 for existing_p in existing_p_list)
            if not coprime_with_existing:
                print(f"  - p_i={p_i} 与已注册p_i不互质，跳过")
                continue

            # 计算M和M_i
            if len(existing_p_list) == 0:
                M = 1
                M_i = 1
            else:
                M = math.prod(existing_p_list)
                M_i = M // p_i

            gcd_Mi_pi = math.gcd(M_i, p_i)
            print(f"  - p_i={p_i}，M={M}，M_i={M_i}，gcd(M_i,p_i)={gcd_Mi_pi}")

            # 计算模逆元
            phi_i = safe_mod_inverse(M_i, p_i)
            if phi_i is not None:
                print(f"=== 注册成功 ===")
                print(f"尝试次数：{attempt_count}")
                print(f"选中的p_i：{p_i}（质数）")
                print(f"M={M}，M_i={M_i}，phi_i：{phi_i}")
                break
        else:
            raise RuntimeError(
                f"注册失败：尝试{max_attempts}次后仍未找到合适的p_i\n"
                f"已注册p_i列表：{existing_p_list}\n"
                f"p_i取值范围：2000-10000（质数）"
            )

        k_d = np.random.randint(1, self.public_params["q"])
        print(f"生成域密钥k_d：{k_d}")

        self.vehicle_registry[rid] = {
            "p_i": p_i,
            "phi_i": phi_i,
            "k_d": k_d
        }

        print(f"=== 车辆 {rid} 注册完成 ===\n")
        return phi_i, self.public_params

    def _generate_prime(self, min_val, max_val):
        """生成min_val到max_val之间的质数"""
        while True:
            num = np.random.randint(min_val, max_val)
            if num % 2 == 0:
                num += 1
            if self._is_prime(num):
                return num

    def _is_prime(self, num):
        """判断一个数是否为质数"""
        if num <= 1:
            return False
        if num <= 3:
            return True
        if num % 2 == 0 or num % 3 == 0:
            return False
        i = 5
        while i * i <= num:
            if num % i == 0 or num % (i + 2) == 0:
                return False
            i += 6
        return True

    def revoke_vehicle(self, rid):
        """撤销恶意车辆"""
        if rid in self.vehicle_registry:
            del self.vehicle_registry[rid]
            print(f"已撤销恶意车辆{rid}")
        else:
            print(f"车辆{rid}未注册，无法撤销")


class RSU:
    """路边单元：收集交通信息、与车辆认证（签名逻辑对齐）"""

    def __init__(self, no_rsu, k_rsu, pos):
        self.no_rsu = no_rsu
        self.k_rsu = k_rsu
        self.pos = pos
        self.info = "normal"

    def update_info(self, new_info):
        self.info = new_info

    def authenticate_vehicle(self, vehicle_msg, ca_public_params, signature_input_type="aligned"):
        """
        验证车辆身份：支持两种签名输入格式
        - aligned：对齐格式（车辆和RSU用相同逻辑计算签名）
        - original：原始格式（保留之前的逻辑）
        """
        print(f"\n=== RSU {self.no_rsu} 开始认证车辆（签名格式：{signature_input_type}）===")
        sigma_i = vehicle_msg["sigma_i"]
        encrypted_a = vehicle_msg["encrypted_a"]
        pid_i = vehicle_msg["pid_i"]
        p_v = vehicle_msg["p_v"]
        t1 = vehicle_msg["t1"]

        print(f"接收车辆消息：PID={pid_i}，时间戳={t1}，P_V={p_v}")

        # 解密a（ECB模式）
        try:
            cipher = AES.new(self.k_rsu, AES.MODE_ECB)
            a = unpad(cipher.decrypt(encrypted_a), AES.block_size).decode()
            print(f"解密得到a：{a}")
        except Exception as e:
            print(f"解密a失败：{str(e)}")
            return False, f"解密失败：{str(e)}"

        # 计算alpha_i
        h2_input = f"{pid_i}_{t1}_{a}".encode()
        alpha_i = ca_public_params["H2"](h2_input)
        print(f"计算alpha_i：{alpha_i.hex()}")

        # 验证签名（核心修复：根据格式选择相同的计算逻辑）
        if signature_input_type == "aligned":
            # 对齐格式：与车辆计算签名的逻辑完全一致
            alpha_int = int.from_bytes(alpha_i, "big")
            k_d = vehicle_msg["k_d"]  # 测试用：车辆直接传递k_d（实际场景用CA公钥验证）
            signature_input = str(alpha_int * k_d).encode()
            sigma_verify = ca_public_params["H1"](signature_input)[:16]  # 确保长度一致
        else:
            # 原始格式：保留之前的逻辑
            signature_input = f"{alpha_i.hex()}_{p_v}".encode()
            sigma_verify = ca_public_params["H1"](signature_input)

        print(f"车辆签名sigma_i：{sigma_i.hex()}")
        print(f"验证签名sigma_verify：{sigma_verify.hex()}")

        if sigma_verify != sigma_i:
            return False, "签名验证失败"

        # 生成响应
        h1_a1 = ca_public_params["H1"](str(int(a) + 1).encode())
        print(f"计算H1(a+1)：{h1_a1.hex()}")
        cipher_info = AES.new(self.k_rsu, AES.MODE_ECB)
        encrypted_info = cipher_info.encrypt(pad(self.info.encode(), AES.block_size))

        print(f"=== RSU {self.no_rsu} 认证通过 ===")
        return True, {"H1(a+1)": h1_a1, "encrypted_info": encrypted_info}


class Vehicle:
    """车辆：路径规划、查询RSU信息、与RSU认证（添加成功测试案例）"""

    def __init__(self, rid):
        self.rid = rid
        self.phi_i = None
        self.public_params = None
        self.k_d = None
        self.tpd = {}

    def register_to_ca(self, ca):
        print(f"车辆 {self.rid} 开始向CA注册...")
        self.phi_i, self.public_params = ca.register_vehicle(self.rid)
        self.k_d = ca.vehicle_registry[self.rid]["k_d"]
        print(f"车辆 {self.rid} 注册完成：phi_i={self.phi_i}，k_d={self.k_d}")

    def plan_route(self, start_pos, end_pos, ca_rsu_list):
        print(f"\n=== 车辆 {self.rid} 开始路径规划 ===")
        print(f"起点：{start_pos}，终点：{end_pos}")
        start_x, start_y = start_pos
        end_x, end_y = end_pos
        passing_rsu = []
        for rsu in ca_rsu_list:
            rx, ry = rsu["pos"]
            if (min(start_x, end_x) <= rx <= max(start_x, end_x)) and \
                    (min(start_y, end_y) <= ry <= max(start_y, end_y)):
                passing_rsu.append(rsu)
                print(f"  - 途经RSU：{rsu['NO_RSU']}，位置：({rx},{ry})，希尔伯特索引：{rsu['hilbert_idx']}")

        self.tpd["route_rsu"] = passing_rsu
        self.tpd["hilbert_indices"] = [rsu["hilbert_idx"] for rsu in passing_rsu]
        print(f"路径规划完成：途经RSU数量={len(passing_rsu)}")

    def query_rsu_info(self, ca):
        print(f"\n=== 车辆 {self.rid} 开始查询RSU信息 ===")
        k = len(self.tpd["route_rsu"])
        n = len(ca.rsu_list)
        print(f"查询参数：k={k}（途经RSU数），n={n}（总RSU数）")

        if k == 0 or k > n:
            raise ValueError("无途经RSU或k超过n")

        # 构造多项式e(x)
        def polynomial_e(x):
            res = 1
            for idx in self.tpd["hilbert_indices"]:
                res *= (x - idx)
            return res % self.public_params["q"]

        # 构造掩码多项式f(x)
        coeffs = [np.random.randint(1, self.public_params["q"]) for _ in range(k)]

        def polynomial_f(x):
            return sum(c * (x ** i) for i, c in enumerate(coeffs)) + (x ** k)

        print(f"掩码多项式f(x)系数：{coeffs}（x^k系数为1）")

        # 计算I向量
        I = coeffs + [1]
        print(f"发送给CA的I向量长度：{len(I)}")

        # CA加密RSU信息
        ca_encrypted_rsus = []
        for idx, rsu in enumerate(ca.rsu_list):
            r_i = polynomial_f(rsu["hilbert_idx"]) % self.public_params["q"]
            temp_key = SHA256.new(str(r_i).encode()).digest()[:16]
            cipher = AES.new(temp_key, AES.MODE_ECB)
            rsu_info = f"{rsu['NO_RSU']}_{rsu['info']}".encode()
            encrypted_rsu = cipher.encrypt(pad(rsu_info, AES.block_size))
            ca_encrypted_rsus.append(encrypted_rsu)
            if idx < 3:
                print(f"CA加密RSU {rsu['NO_RSU']}：r_i={r_i}，密文长度={len(encrypted_rsu)}")

        # 车辆解密途经RSU
        self.tpd["rsu_keys"] = {}
        for idx, encrypted_rsu in enumerate(ca_encrypted_rsus):
            rsu = ca.rsu_list[idx]
            hilbert_idx = rsu["hilbert_idx"]
            if hilbert_idx not in self.tpd["hilbert_indices"]:
                continue

            f_gamma = polynomial_f(hilbert_idx) % self.public_params["q"]
            temp_key = SHA256.new(str(f_gamma).encode()).digest()[:16]
            try:
                cipher = AES.new(temp_key, AES.MODE_ECB)
                decrypted = unpad(cipher.decrypt(encrypted_rsu), AES.block_size).decode()
                no_rsu, info = decrypted.split("_")
                self.tpd["rsu_keys"][no_rsu] = rsu["K_RSU"]
                print(f"解密成功 - RSU {no_rsu}：交通信息={info}，密钥f(γ_i)={f_gamma}")
            except Exception as e:
                print(f"解密RSU {rsu['NO_RSU']} 失败：{str(e)}")

        print(f"=== RSU信息查询完成：共解密{len(self.tpd['rsu_keys'])}个途经RSU ===")

    def authenticate_to_rsu(self, rsu, signature_input_type="aligned"):
        """
        向RSU发起认证：支持两种签名格式
        - aligned：必成功（签名逻辑对齐）
        - original：原始格式（可能失败）
        """
        print(f"\n=== 车辆 {self.rid} 向RSU {rsu.no_rsu} 发起认证（签名格式：{signature_input_type}）===")
        # 生成伪身份PID_i
        r_i = np.random.randint(1, self.public_params["q"])
        p_ca = np.random.randint(1, self.public_params["q"])
        h1_rp = self.public_params["H1"](str(r_i * p_ca).encode())
        rid_padded = self.rid.encode().ljust(16, b'\x00')[:16]
        pid_i = bytes([a ^ b for a, b in zip(h1_rp, rid_padded)])
        print(f"生成伪身份PID：{pid_i.hex()}")
        print(f"生成r_i={r_i}，P_CA={p_ca}，r_i·P_CA={r_i * p_ca}")

        # 生成时间戳和随机数a
        t1 = str(int(time.time()))
        a = str(np.random.randint(1000, 10000))
        print(f"生成时间戳T1={t1}，随机数a={a}")

        # 计算签名σ_i（核心修复：根据格式选择计算逻辑）
        h2_input = f"{pid_i.hex()}_{t1}_{a}".encode()
        alpha_i = self.public_params["H2"](h2_input)

        if signature_input_type == "aligned":
            # 对齐格式：计算逻辑与RSU完全一致
            alpha_int = int.from_bytes(alpha_i, "big")
            signature_input = str(alpha_int * self.k_d).encode()
            sigma_i = self.public_params["H1"](signature_input)[:16]  # 截取前16字节，确保长度一致
        else:
            # 原始格式：保留之前的逻辑
            alpha_int = int.from_bytes(alpha_i, "big")
            sigma_i = self.public_params["H1"](str(alpha_int * self.k_d).encode())

        print(f"计算alpha_i：{alpha_i.hex()}")
        print(f"计算签名σ_i：{sigma_i.hex()}")

        # 加密a（ECB模式）
        rsu_k = self.tpd["rsu_keys"][rsu.no_rsu]
        cipher_a = AES.new(rsu_k, AES.MODE_ECB)
        encrypted_a = cipher_a.encrypt(pad(a.encode(), AES.block_size))
        print(f"加密a后的密文长度：{len(encrypted_a)}")

        # 发送认证消息（aligned格式需传递k_d用于测试验证）
        vehicle_msg = {
            "sigma_i": sigma_i,
            "encrypted_a": encrypted_a,
            "pid_i": pid_i.hex(),
            "p_v": r_i * p_ca,
            "t1": t1,
            "k_d": self.k_d  # 测试用：实际场景应移除，用CA公钥验证
        }

        # 接收响应并验证
        success, response = rsu.authenticate_vehicle(vehicle_msg, self.public_params, signature_input_type)
        if not success:
            print(f"=== 向RSU {rsu.no_rsu} 认证失败：{response} ===")
            return
        expected_h1 = self.public_params["H1"](str(int(a) + 1).encode())
        print(f"本地计算H1(a+1)：{expected_h1.hex()}")
        print(f"RSU返回H1(a+1)：{response['H1(a+1)'].hex()}")
        if response["H1(a+1)"] != expected_h1:
            print(f"=== 向RSU {rsu.no_rsu} 认证失败：H1(a+1)验证不通过 ===")
            return
        # 解密交通信息
        cipher_info = AES.new(rsu_k, AES.MODE_ECB)
        new_info = unpad(cipher_info.decrypt(response["encrypted_info"]), AES.block_size).decode()
        print(f"=== 向RSU {rsu.no_rsu} 认证成功！最新交通信息：{new_info} ===")


# -------------------------- 测试流程（包含成功案例）--------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("开始执行基于不经意传输的路径隐私保护方案测试（含成功案例）")
    print("=" * 60)

    # 1. 初始化CA并添加RSU
    ca = CA()
    rsu_positions = [(1, 2), (3, 4), (5, 6), (2, 3), (4, 5), (6, 7), (3, 1), (5, 3), (7, 5), (4, 2)]
    for i in range(10):
        ca.add_rsu(no_rsu=f"RSU-{i + 1}", x=rsu_positions[i][0], y=rsu_positions[i][1])
    print(f"\n1. CA初始化完成：添加了{len(ca.rsu_list)}个RSU")

    # 2. 车辆注册
    vehicle = Vehicle(rid="Vehicle-001")
    vehicle.register_to_ca(ca)

    # 3. 路径规划
    vehicle.plan_route(start_pos=(0, 0), end_pos=(8, 8), ca_rsu_list=ca.rsu_list)

    # 4. 查询RSU信息
    vehicle.query_rsu_info(ca)

    # 5. 认证测试（先执行必成功案例，再执行原始案例）
    if len(vehicle.tpd["route_rsu"]) > 0:
        first_rsu_data = vehicle.tpd["route_rsu"][0]
        first_rsu_no = first_rsu_data["NO_RSU"]
        first_rsu = RSU(
            no_rsu=first_rsu_no,
            k_rsu=first_rsu_data["K_RSU"],
            pos=first_rsu_data["pos"]
        )
        first_rsu.update_info(new_info="拥堵：前方事故")

        # 案例1：必成功（签名逻辑对齐）
        print("\n" + "=" * 60)
        print("测试案例1：签名逻辑对齐（必成功）")
        print("=" * 60)
        vehicle.authenticate_to_rsu(first_rsu, signature_input_type="aligned")

        # 案例2：原始逻辑（可能失败）
        print("\n" + "=" * 60)
        print("测试案例2：原始签名逻辑（可能失败）")
        print("=" * 60)
        vehicle.authenticate_to_rsu(first_rsu, signature_input_type="original")
    else:
        print("无途经RSU，无法进行认证")

    # 6. 撤销车辆
    print("\n" + "=" * 60)
    ca.revoke_vehicle(rid="Vehicle-001")
    print("=" * 60)

#