from des_table import Des, P_Table, PC2_Table, LOOP_Table, PC1_Table
import random
import numpy as np
from collections import defaultdict
import copy
from tool import bin2int, bin2hex, int2bin, int2hex, hex2bin, hex2int, xor
import itertools as it
import time
import tqdm
import datetime

class DifferentialCryptanalysis:
    def __init__(self, des_instance: Des, num_of_diffs, test_count=5):
        self.des = des_instance
        self.N = des_instance.N
        self.test_count = test_count
        self.s_table = self.calculate_s_xor()
        self.num_of_diffs = num_of_diffs

        self.missing_positions1 = sorted([k for k in range(1, 57) if k not in PC2_Table])
        self.missing_positions2 = sorted([k for k in range(1, 65) if k not in PC1_Table])

        self.differential_des = Des(self.N)
        self.random_plain_texts = [bin2hex([random.randint(0, 1) for _ in range(64)], 16) for _ in range(self.test_count)]
        self.encrypted_texts = [self.des.encode(plain_text) for plain_text in self.random_plain_texts]
        self.guessed_key = None

        self.progress_bar = None

        self.differential_pairs = ['0080820060000000', '0000401006000000']
        self.probable_keys = [[] for _ in range(8)]
        self.key_counters = [defaultdict(int), defaultdict(int)]
        self.key_positions = [[1, 2, 3, 4], [0, 5, 6, 7]]

    def calculate_s_xor(self):
        s_xor = [[[[] for _ in range(16)] for _ in range(64)] for _ in range(8)]
        for i in range(8):
            for B in range(64):
                for BB in range(64):
                    in_xor = B ^ BB
                    out_xor = bin2int(self.des.Sx(int2bin(B, 6), i)) ^ bin2int(self.des.Sx(int2bin(BB, 6), i))
                    s_xor[i][in_xor][out_xor].append(B)
        return s_xor

    def debug_guessing(self, s_xor):
        for i in range(8):
            target_r0 = '0' * i + '6' + (7 - i) * '0'  # 2、4、6
            target_r0 = hex2bin(target_r0, 32)

            s_xor_i = s_xor[i][bin2int(self.des.E(target_r0)[i * 6:(i + 1) * 6])]
            max_len_s = max(len(s) for s in s_xor_i)
            guessed_m = int2hex(np.argmax([len(s) for s in s_xor_i]), 1)

            guessed_r0_out = hex2bin('0' * i + guessed_m + (7 - i) * '0', 32)
            guessed_r0_out = [guessed_r0_out[p - 1] for p in P_Table]

            l0 = guessed_r0_out
            r3 = guessed_r0_out

            print('L0: {}, R0: {}, R3: {}'.format(bin2hex(l0, 8), bin2hex(target_r0, 8), bin2hex(r3, 8)))

        print('完成')
        input()

    def analyze(self):
        print('==> 开始分析密钥')
        for _ in tqdm.trange(self.num_of_diffs):
            for i in range(2):
                self.analyze_single(self.differential_pairs[i], self.key_positions[i], i)
        key = self.find_key()  # 48bit
        print('==> 找到48bits密钥，开始还原初始密钥')
        self.progress_bar = tqdm.trange(2 ** len(self.missing_positions1))
        if not self.reverse_key_search(key):  # 64bit
            print('分析失败')
            exit(0)
        return self.guessed_key

    def analyze_single(self, differential_pair, positions, index):
        p, p_prime, t, t_prime = self.generate_pt(differential_pair)
        l0, r0 = copy.deepcopy(p[0:32]), copy.deepcopy(p[32:64])
        ll0, rr0 = copy.deepcopy(p_prime[0:32]), copy.deepcopy(p_prime[32:64])
        l5, r5 = copy.deepcopy(t[0:32]), copy.deepcopy(t[32:64])
        ll5, rr5 = copy.deepcopy(t_prime[0:32]), copy.deepcopy(t_prime[32:64])

        e = self.des.E(l5)
        ee = self.des.E(ll5)
        in_xor = xor(e, ee)

        out_xor = xor(r5, rr5)
        out_xor = list(np.array(out_xor)[np.argsort(P_Table)])

        ex = [bin2int(e[i * 6:(i + 1) * 6]) for i in range(8)]

        for i in positions:
            in_xor_val = bin2int(in_xor[i * 6:(i + 1) * 6])
            out_xor_val = bin2int(out_xor[i * 4:(i + 1) * 4])
            for b in self.s_table[i][in_xor_val][out_xor_val]:
                k = b ^ ex[i]
                self.probable_keys[i].append(k)

    def get_initial_key(self, key) -> bool:
        key = list(np.array(key)[np.argsort(PC2_Table)])
        for p in self.missing_positions1: key.insert(p-1, 0)  # 56bit
        offset = sum(LOOP_Table[0:self.N])
        combinations = list(it.product([0, 1], repeat=len(self.missing_positions1)))
        for comb in combinations:
            key_ = np.array(key)
            key_[np.array(self.missing_positions1)-1] = comb
            key_ = list(key_)
            t1 = key_[0:28-offset]
            t0 = key_[28-offset:28]
            t3 = key_[28:56-offset]
            t2 = key_[56-offset:56]
            key_ = t0 + t1 + t2 + t3  # 56bit
            # 56bit -> 64bit
            key_ = list(np.array(key_)[np.argsort(PC1_Table)])
            for i in self.missing_positions2:
                key_.insert(i-1, 0)
                for j in range(7):
                    key_[i-1] ^= key_[i-j-2]
            key_ = bin2hex(key_, 16)

            OK = True
            self.differential_des.set_key(key_)
            for __P, __T in zip(self.random_plain_texts, self.encrypted_texts):
                T = self.differential_des.encode(__P)
                P = self.differential_des.decode(__T)
                if __T != T and __P != P:
                    OK = False
                    break
            if OK:
                self.guessed_key = key_
                self.progress_bar.close()
                return True
            self.progress_bar.update(1)
        self.progress_bar.close()
        return False

    def reverse_key_search(self, key):  # 48bit -> 56bit -> 64bit
        key = hex2bin(key, 48)
        return self.get_initial_key(key)

    def find_key(self):
        key_map = [defaultdict(int) for _ in range(8)]
        key = [-1 for _ in range(8)]
        for i in range(8):
            pk = self.probable_keys[i]
            for k in pk:
                key_map[i][k] += 1
            m = max(key_map[i].values())
            temp = [k for k, v in key_map[i].items() if v == m]
            if len(temp) != 1:
                print('[0] 重新尝试!')
                exit(0)
            if key[i] != -1 and key[i] != temp[0]:
                print('[1] 重新尝试!')
                exit(0)
            key[i] = temp[0]

        key_ = []
        for i in range(8):
            key_.extend(int2bin(key[i], 6))
        key = bin2hex(key_, 16)
        return key

    def generate_pt(self, differential_pair):
        differential_pair = hex2bin(differential_pair, 64)
        p = [random.randint(0, 1) for _ in range(64)]
        p_prime = xor(p, differential_pair)
        t0, t1 = self.des.F(p[0:32], p[32:64])
        t_prime0, t_prime1 = self.des.F(p_prime[0:32], p_prime[32:64])
        t = t0 + t1
        t_prime = t_prime0 + t_prime1
        return p, p_prime, t, t_prime


if __name__ == '__main__':
    num_rounds = 5
    des_instance = Des(num_rounds)
    # des_instance.set_key('f93fde5a749fe21b')
    print('\n {}-轮 DES 差分攻击'.format(num_rounds))
    print('\n==> 创建DES')
    differential_cryptanalysis = DifferentialCryptanalysis(des_instance, 2**6, 10)
    start_time = time.time()
    key_found = differential_cryptanalysis.analyze()
    end_time = time.time()
    duration = datetime.timedelta(seconds=end_time - start_time)
    # print('==> Finish analysing, it spends {}'.format(duration))
    print('==> 分析完毕')

    num_tests = 1000
    print('\n初始化密钥信息')
    des_instance.get_key()
    print('\n预测的密钥为 {}, 测试 {} 个随机文本'.format(key_found, num_tests))
    d = Des(num_rounds)
    d.set_key(key_found)
    for i in tqdm.trange(num_tests):
        plaintext = bin2hex([random.randint(0, 1) for _ in range(64)], 16)
        ciphertext_gt = des_instance.encode(plaintext)  # groundtrue
        ciphertext_pre = d.encode(plaintext)  # predict
        plaintext_pre = d.decode(ciphertext_gt)
        if ciphertext_gt != ciphertext_pre or plaintext != plaintext_pre:
            print('\n攻击成功!')
            exit(0)
    print('\n所有测试均通过,攻击成功')
