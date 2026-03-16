def isqrt(n):
    """Compute the integer square root of a large integer n."""
    if n == 0:
        return 0
    x = n
    y = (x + n // x) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x

def fermat_factor(n):
    """Perform Fermat's factorization on n = p * q where p and q are close primes."""
    from math import ceil
    a = isqrt(n)
    if a * a < n:
        a += 1
    b2 = a * a - n
    while not is_perfect_square(b2):
        a += 1
        b2 = a * a - n
    b = isqrt(b2)
    p = a - b
    q = a + b
    return p, q

def is_perfect_square(k):
    """Check if k is a perfect square."""
    s = isqrt(k)
    return s * s == k

# Example usage:
n = int(86934482296048119190666062003494800588905656017203025617216654058378322103517)
p, q = fermat_factor(n)
print(f"n 的因数是：{p} 和 {q}")
