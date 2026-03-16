import numpy as np
# from scipy import special # Unused
# from scipy.optimize import minimize # Unused
import matplotlib
# matplotlib.use('Agg')  # Commented out to allow interactive window showing
import matplotlib.pyplot as plt
from numpy.polynomial.chebyshev import cheb2poly
import argparse

# ===================== 1. Define the Objective Function (GeLU) =====================
def gelu(x):
    """Standard GeLU function implementation"""
    return 0.5 * x * (1 + np.tanh(np.sqrt(2 / np.pi) * (x + 0.044715 * x**3)))

def sigmoid(x):
    return 1 / (1 + np.exp(-x))

def tanh_act(x):
    return np.tanh(x)

def swish(x):
    return x / (1 + np.exp(-x))

def relu(x):
    return np.maximum(0, x)

FUNCTIONS = {
    'gelu': gelu,
    'sigmoid': sigmoid,
    'tanh': tanh_act,
    'swish': swish,
    'relu': relu
}

# ===================== 2. Piecewise Approximation Core Function =====================
def chebyshev_fit_interval(f, a, b, degree):
    """
    Fit the function f with Chebyshev polynomials on the interval [a,b]
    :param f: Objective function
    :param a: Left endpoint of the interval
    :param b: Right endpoint of the interval
    :param degree: Polynomial degree
    :return: Coefficients of the fitted polynomial (in ascending order), maximum error in the interval
    """
    # Step 1: Chebyshev node sampling (to minimize the Runge's phenomenon)
    n = degree + 1
    cheb_nodes = np.cos(np.pi * (2 * np.arange(n) + 1) / (2 * n))  # Chebyshev nodes in [-1,1]
    # Map to the interval [a,b]
    x_nodes = (a + b) / 2 + (b - a) / 2 * cheb_nodes
    y_nodes = f(x_nodes)

    # Step 2: Construct Chebyshev polynomial basis (from T_0 to T_degree)
    cheb_basis = np.polynomial.chebyshev.chebvander(cheb_nodes, degree)

    # Step 3: Solve for Chebyshev coefficients using least squares
    cheb_coeffs = np.linalg.lstsq(cheb_basis, y_nodes, rcond=None)[0]

    # Step 4: Convert to standard polynomial coefficients (in ascending order: x^0, x^1, ...)
    poly_coeffs = cheb2poly(cheb_coeffs)

    # Step 5: Map back to the original interval [a,b]
    # Variable substitution: t = (2x - a - b)/(b - a)
    # Construct the substituted polynomial
    def poly(x):
        t = (2 * x - a - b) / (b - a)  # Map to [-1,1]
        return np.polyval(poly_coeffs[::-1], t)  # polyval requires coefficients in descending order

    # Step 6: Validate the error (dense sampling)
    x_test = np.linspace(a, b, 1000)
    y_true = f(x_test)
    y_pred = poly(x_test)
    max_error = np.max(np.abs(y_true - y_pred))

    return poly_coeffs, max_error


def piecewise_chebyshev_fit(f, x_range, max_error_threshold, init_degree=5):
    """
    Adaptive piecewise Chebyshev fitting: if the interval error exceeds the threshold, it is split
    :param f: Objective function
    :param x_range: Fitting domain [x_min, x_max]
    :param max_error_threshold: Maximum allowable error
    :param init_degree: Initial polynomial degree
    :return: List of piecewise results, each element is (left endpoint, right endpoint, polynomial coefficients, interval error)
    """
    # Initialize the queue of intervals to be processed
    intervals = [(x_range[0], x_range[1], init_degree)]
    result = []

    while intervals:
        a, b, degree = intervals.pop(0)
        # Fit the current interval
        coeffs, max_err = chebyshev_fit_interval(f, a, b, degree)
        if max_err <= max_error_threshold:
            # Error meets the requirements, add to results
            result.append((a, b, coeffs, max_err))
        else:
            # Error exceeds the threshold, split into two sub-intervals
            mid = (a + b) / 2
            intervals.append((a, mid, degree))
            intervals.append((mid, b, degree))
            # Optional: increase the polynomial degree instead of splitting the interval
            # intervals.append((a, b, degree + 2))

    # Sort by the left endpoint
    result.sort(key=lambda x: x[0])
    return result


def format_polynomial(coeffs, a, b):
    """Formats the polynomial coefficients into a readable string."""
    # The polynomial is in terms of t = (2x - a - b) / (b - a)
    # The coefficients are for the polynomial in t, in ascending power order.
    t_poly_parts = []
    for i, c in enumerate(coeffs):
        if abs(c) > 1e-9:  # Threshold to ignore near-zero coefficients
            if i == 0:
                t_poly_parts.append(f"{c:.6f}")
            elif i == 1:
                t_poly_parts.append(f"{c:.6f} * t")
            else:
                t_poly_parts.append(f"{c:.6f} * t^{i}")

    t_poly_str = " + ".join(t_poly_parts).replace(" + -", " - ")

    return f"y(x) = {t_poly_str}   (where t = (2*x - {a:.2f} - {b:.2f}) / ({b-a:.2f}))"


# ===================== 3. Execute Fitting and Visualization =====================
if __name__ == "__main__":
    # Add argparse so user can expand interval or change degree/threshold from command line
    parser = argparse.ArgumentParser(description="Piecewise Chebyshev fit for GeLU; configurable range and degree")
    parser.add_argument("--func", type=str, default="gelu", choices=list(FUNCTIONS.keys()), help="Activation function to approximate (default: gelu) / 选择激活函数")
    parser.add_argument("--xmin", type=float, default=-4.0, help="Left endpoint of fitting interval (default -4)")
    parser.add_argument("--xmax", type=float, default=4.0, help="Right endpoint of fitting interval (default 4)")
    parser.add_argument("--degree", type=int, default=5, help="Initial polynomial degree (default 5)")
    parser.add_argument("--threshold", type=float, default=9e-2, help="Max error threshold (default 9e-2)")
    args = parser.parse_args()

    # Configuration parameters (adapted for ZKML scenario)
    x_min, x_max = args.xmin, args.xmax  # Effective domain of GeLU (default -4..4)
    max_error_threshold = args.threshold  # Error threshold
    init_degree = args.degree  # Initial polynomial degree

    target_func_name = args.func
    target_func = FUNCTIONS[target_func_name]
    print(f"Approximating function: {target_func_name}")

    # Perform piecewise fitting
    piecewise_result = piecewise_chebyshev_fit(
        target_func, [x_min, x_max], max_error_threshold, init_degree
    )

    # Output results
    print("=== Piecewise Polynomial Approximation Results / 分段多项式近似结果 ===")
    for i, (a, b, coeffs, err) in enumerate(piecewise_result):
        print(f"Interval {i+1} / 区间 {i+1}: [{a:.2f}, {b:.2f}]")
        # The coeffs from cheb2poly are in ascending order (coeffs[i] is coef for t^i)
        print(f"  Polynomial Coefficients (ascending powers of t) / 多项式系数 (t 的升幂): {coeffs.round(6)}")
        print(f"  Equation (in t) / 方程 (关于 t): {format_polynomial(coeffs, a, b)}")
        print(f"  Max Error in Interval / 区间内最大误差: {err:.6f}")

        # Expand polynomial in terms of x: t = m*x + c, where m = 2/(b-a), c = -(a+b)/(b-a)
        m = 2.0 / (b - a)
        c = -(a + b) / (b - a)
        # Create poly in t for numpy.poly1d (descending order)
        p_t = np.poly1d(coeffs[::-1])
        # Create linear poly for t(x)
        t_of_x = np.poly1d([m, c])
        # Compose to get polynomial in x
        p_x = p_t(t_of_x)
        # p_x.coeffs gives coefficients in descending order
        coeffs_x_desc = np.round(p_x.coeffs, 6).tolist()
        # Also provide ascending order if useful
        coeffs_x_asc = np.round(p_x.coeffs[::-1], 6).tolist()
        print(f"  Polynomial Coefficients in x (descending powers) / x 的多项式系数 (降幂): {coeffs_x_desc}")
        print(f"  Polynomial Coefficients in x (ascending powers) / x 的多项式系数 (升幂): {coeffs_x_asc}")
        # Human readable polynomial
        terms = []
        deg = len(p_x.coeffs) - 1
        for j, coef in enumerate(p_x.coeffs):
            power = deg - j
            if abs(coef) < 1e-12:
                continue
            coef_str = f"{coef:.6f}"
            if power == 0:
                terms.append(f"{coef_str}")
            elif power == 1:
                terms.append(f"{coef_str} * x")
            else:
                terms.append(f"{coef_str} * x^{power}")
        poly_x_str = " + ".join(terms).replace(" + -", " - ")
        print(f"  Expanded polynomial / 展开的多项式 y(x) = {poly_x_str}")

        print("-" * 50)

    # Visualize the approximation
    x_plot = np.linspace(x_min, x_max, 2000)
    y_true = target_func(x_plot)
    y_pred = np.zeros_like(x_plot)

    # 拼接各区间的近似值
    for a, b, coeffs, _ in piecewise_result:
        mask = (x_plot >= a) & (x_plot <= b)
        t = (2 * x_plot[mask] - a - b) / (b - a)  # 映射到[-1,1]
        y_pred[mask] = np.polyval(coeffs[::-1], t)

    # 绘图
    plt.figure(figsize=(12, 6))
    plt.subplot(121)
    plt.plot(x_plot, y_true, label=f"Original {target_func_name}", color="blue")
    plt.plot(x_plot, y_pred, label="Piecewise Approximation", color="red", linestyle="--")
    plt.xlabel("x")
    plt.ylabel(f"{target_func_name}(x)")
    plt.title(f"{target_func_name} Function vs. Piecewise Polynomial Approximation")
    plt.legend()
    plt.grid(True)

    plt.subplot(122)
    plt.plot(x_plot, np.abs(y_true - y_pred), color="green")
    plt.xlabel("x")
    plt.ylabel("Absolute Error")
    plt.title("Absolute Approximation Error (Max={:.4f})".format(np.max(np.abs(y_true - y_pred))))
    plt.grid(True)
    plt.tight_layout()

    # Show figure interactively
    print("Displaying approximation plot... / 正在显示近似图像...")
    try:
        plt.show()
    except Exception as e:
        print(f"Note: Could not open display window ({e}) / 注意：无法打开显示窗口 ({e})")

    # 输出ZK框架可用的查表格式（区间端点+系数）
    print("\n=== ZK Lookup Table Format (Interval Endpoints + Polynomial Coefficients) / ZK 查表格式（区间端点 + 多项式系数） ===")
    zk_table = []
    for a, b, coeffs, _ in piecewise_result:
        # 系数转为列表（降幂），保留6位小数
        coeff_list = [round(c, 6) for c in coeffs[::-1]]
        zk_table.append({
            "interval": [a, b],
            "poly_coeffs": coeff_list  # [x^d, x^(d-1), ..., x^0]
        })
    print(zk_table)
