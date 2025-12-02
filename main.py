import numpy as np
import os

# Конфигурация параметров Kyber
n = 256        # Степень многочлена
k = 3          # Размерность модуля
q = 7681       # Модуль коэффициентов
eta = 4        # Параметр шума
du = 11        # Биты сжатия u
dv = 3         # Биты сжатия v
dt = 11        # Биты сжатия t

# Математические операции над многочленами
def poly_add(f, g):
    return (f + g) % q

def poly_sub(f, g):
    return (f - g) % q

def poly_mul(f, g):
    res = np.convolve(f, g)
    coeffs = np.zeros(n, dtype=int)
    for i in range(len(res)):
        coeffs[i % n] += res[i] * (1 if i < n else -1)
    return coeffs % q

def matvec_mul(A, s):
    t = np.zeros((k, n), dtype=int)
    for i in range(k):
        for j in range(k):
            t[i] = poly_add(t[i], poly_mul(A[i][j], s[j]))
    return t

def vec_dot(a, b):
    res = np.zeros(n, dtype=int)
    for i in range(k):
        res = poly_add(res, poly_mul(a[i], b[i]))
    return res

# Вспомогательные функции
def sample_noise():
    coeffs = np.zeros(n, dtype=int)
    for i in range(n):
        a = sum(np.random.randint(0, 2, eta))
        b = sum(np.random.randint(0, 2, eta))
        coeffs[i] = (a - b) % q
    return coeffs

def sample_matrix():
    return np.random.randint(0, q, (k, k, n))

def compress(x, d):
    scale = (2**d) / q
    return np.round(scale * x).astype(int) % (2**d)

def decompress(x, d):
    scale = q / (2**d)
    return np.round(scale * x).astype(int)

# Алгоритмы Kyber
def KeyGen():
    A = sample_matrix()
    s = np.array([sample_noise() for _ in range(k)])
    e = np.array([sample_noise() for _ in range(k)])
    As = matvec_mul(A, s)
    t_raw = np.array([poly_add(As[i], e[i]) for i in range(k)])
    t = np.array([compress(poly, dt) for poly in t_raw])
    pk = (t, A)
    sk = s
    return pk, sk

def Enc(pk, m_bits):
    t_compressed, A = pk
    t = np.array([decompress(poly, dt) for poly in t_compressed])
    m_poly = np.zeros(n, dtype=int)
    for i in range(n):
        if m_bits[i] == 1:
            m_poly[i] = int(np.round(q / 2))
    r = np.array([sample_noise() for _ in range(k)])
    e1 = np.array([sample_noise() for _ in range(k)])
    e2 = sample_noise()
    A_T = np.transpose(A, (1, 0, 2))
    Ar = matvec_mul(A_T, r)
    u_raw = np.array([poly_add(Ar[i], e1[i]) for i in range(k)])
    tr = vec_dot(t, r)
    v_raw = poly_add(poly_add(tr, e2), m_poly)
    u = np.array([compress(poly, du) for poly in u_raw])
    v = compress(v_raw, dv)
    return (u, v)

def Dec(sk, c):
    u_compressed, v_compressed = c
    u = np.array([decompress(poly, du) for poly in u_compressed])
    v = decompress(v_compressed, dv)
    s = sk
    su = vec_dot(s, u)
    m_noisy = poly_sub(v, su)
    decrypted_bits = []
    for val in m_noisy:
        bit = compress(val, 1)
        decrypted_bits.append(bit)
    return decrypted_bits

# Тестирование
def format_vector_summary(arr, name):
    flat = arr.flatten()
    return (f"{name}:\n"
            f"  Форма: {arr.shape}\n"
            f"  Диапазон: [{flat.min()}, {flat.max()}]\n"
            f"  Среднее: {flat.mean():.2f}\n"
            f"  Пример первых 5 элементов: {flat[:5]}\n")

def format_bits(bits, max_show=32):
    bits_str = ''.join(map(str, bits[:max_show]))
    if len(bits) > max_show:
        bits_str += f"... (всего {len(bits)} бит)"
    return bits_str
