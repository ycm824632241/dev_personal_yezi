from py_ecc.optimized_bls12_381 import G1, G2, pairing
import numpy as np

# ============ 基础双线性映射 ============
class BilinearMapping:
    """双线性映射类"""

    def __init__(self, matrix):
        """
        初始化双线性映射
        :param matrix: 表示映射的矩阵
        """
        self.matrix = np.array(matrix)
        print(f"✓ 双线性映射已初始化")
        print(f"  矩阵形状: {self.matrix.shape}\n")

    def apply(self, x, y):
        """
        应用双线性映射：f(x, y) = x^T * M * y
        :param x: 第一个向量
        :param y: 第二个向量
        :return: 映射结果
        """
        x = np.array(x)
        y = np.array(y)

        print(f"→ 计算双线性映射 f(x, y)")
        print(f"  向量 x: {x}")
        print(f"  向量 y: {y}")

        result = x @ self.matrix @ y

        print(f"  结果: {result}\n")
        return result


# ============ 辅助函数 ============
def extract_point_coords(pt):
    """
    安全地提取椭圆曲线点的坐标
    :param pt: 椭圆曲线点
    :return: (x, y, z) 射影坐标或字符串表示
    """
    if pt is None or pt == (0, 0, 0):
        return "无穷远点 (O)"

    if isinstance(pt, tuple) and len(pt) == 3:
        x, y, z = pt
        if z == 0:
            return "无穷远点 (O)"
        return f"({x}, {y}, {z})"

    return str(pt)


# ============ 椭圆曲线双线性映射 ============
class EllipticCurveBilinearMapping:
    """基于椭圆曲线的双线性映射类"""

    def __init__(self):
        """初始化椭圆曲线双线性映射"""
        print(f"✓ 椭圆曲线双线性映射已初始化")
        print(f"  使用曲线: BLS12-381\n")

    def apply(self, point_g1, point_g2):
        """
        应用双线性映射：e(P, Q)
        基于Weil配对或Tate配对
        :param point_g1: G1群上的点
        :param point_g2: G2群上的点
        :return: 配对结果
        """
        print(f"→ 计算椭圆曲线双线性映射 e(P, Q)")
        print(f"  G1点坐标: {extract_point_coords(point_g1)}")
        print(f"  G2点坐标: {extract_point_coords(point_g2)}")

        result = pairing(point_g2, point_g1)

        print(f"  配对结果: {result}\n")
        return result

    def scalar_multiply_g1(self, scalar, point=None):
        """
        G1上的标量乘法：[scalar]P
        :param scalar: 标量系数
        :param point: 基点（默认为G1生成元）
        :return: 标量乘法结果
        """
        if point is None:
            point = G1
        return scalar * point

    def scalar_multiply_g2(self, scalar, point=None):
        """
        G2上的标量乘法：[scalar]Q
        :param scalar: 标量系数
        :param point: 基点（默认为G2生成元）
        :return: 标量乘法结果
        """
        if point is None:
            point = G2
        return scalar * point

    def bilinearity_test(self, a, b, point_g1=None, point_g2=None):
        """
        测试双线性性质：e(aP, bQ) = e(P, Q)^(ab)
        :param a: 标量a
        :param b: 标量b
        :param point_g1: G1上的点P
        :param point_g2: G2上的点Q
        :return: 是否满足双线性性质
        """
        if point_g1 is None:
            point_g1 = G1
        if point_g2 is None:
            point_g2 = G2

        print(f"→ 双线性性质测试: e(aP, bQ) = e(P, Q)^(ab)")
        print(f"  a = {a}, b = {b}\n")

        # 计算左边：e(aP, bQ)
        ap = self.scalar_multiply_g1(a, point_g1)
        bq = self.scalar_multiply_g2(b, point_g2)
        left = self.apply(ap, bq)

        # 计算右边：e(P, Q)^(ab)
        e_pq = self.apply(point_g1, point_g2)
        right = e_pq ** (a * b)

        print(f"  左边 e(aP, bQ): {left}")
        print(f"  右边 e(P, Q)^(ab): {right}")
        print(f"  相等: {left == right}\n")

        return left == right

    def non_degeneracy_test(self):
        """
        测试非退化性质：存在P∈G1, Q∈G2 使得 e(P, Q) ≠ 1
        """
        print(f"→ 非退化性质测试: e(P, Q) ≠ 1")

        e_result = self.apply(G1, G2)
        is_non_degenerate = e_result != 1

        print(f"  e(G1, G2) = {e_result}")
        print(f"  非退化性满足: {is_non_degenerate}\n")

        return is_non_degenerate

    def alt_bilinearity_test(self, a, point_g1=None, point_g2=None):
        """
        测试双线性性质（另一形式）：e(P, aQ) = e(P, Q)^a
        :param a: 标量a
        :param point_g1: G1上的点P
        :param point_g2: G2上的点Q
        :return: 是否满足双线性性质
        """
        if point_g1 is None:
            point_g1 = G1
        if point_g2 is None:
            point_g2 = G2

        print(f"→ 双线性性质测试（另一形式）: e(P, aQ) = e(P, Q)^a")
        print(f"  a = {a}\n")

        # 计算左边：e(P, aQ)
        aq = self.scalar_multiply_g2(a, point_g2)
        left = self.apply(point_g1, aq)

        # 计算右边：e(P, Q)^a
        e_pq = self.apply(point_g1, point_g2)
        right = e_pq ** a

        print(f"  左边 e(P, aQ): {left}")
        print(f"  右边 e(P, Q)^a: {right}")
        print(f"  相等: {left == right}\n")

        return left == right


# ============ 示例用法 ============
if __name__ == "__main__":
    print("=" * 60)
    print("双线性映射示例")
    print("=" * 60 + "\n")

    # 基础矩阵映射
    matrix = [
        [1, 2, 3],
        [4, 5, 6],
        [7, 8, 9]
    ]

    bilinear = BilinearMapping(matrix)
    result = bilinear.apply([1, 0, 1], [2, 1, 3])

    print("=" * 60)
    print("椭圆曲线双线性映射示例（BLS12-381）")
    print("=" * 60 + "\n")

    bilinear_ec = EllipticCurveBilinearMapping()

    # 基本配对计算
    a = 12345
    b = 67890

    p_g1 = bilinear_ec.scalar_multiply_g1(a)
    q_g2 = bilinear_ec.scalar_multiply_g2(b)
    e_result = bilinear_ec.apply(p_g1, q_g2)

    print("=" * 60)
    print("双线性性质验证")
    print("=" * 60 + "\n")

    # 测试双线性性质
    bilinear_ec.bilinearity_test(5, 7)
    bilinear_ec.alt_bilinearity_test(11)

    print("=" * 60)
    print("非退化性质验证")
    print("=" * 60 + "\n")

    # 测试非退化性质
    bilinear_ec.non_degeneracy_test()

    print("=" * 60)
