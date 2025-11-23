import numpy as np
import os

# --- КОНФИГУРАЦИЯ ПАРАМЕТРОВ (из Table 1 в 634.pdf) ---
n = 256        # Степень многочлена (X^n + 1)
k = 3          # Размерность матрицы модуля (Module dimension)
q = 7681       # Модуль коэффициентов (ВНИМАНИЕ: 7681 согласно вашему PDF)
eta = 4        # Параметр биномиального распределения шума
du = 11        # Биты для сжатия u
dv = 3         # Биты для сжатия v
dt = 11        # Биты для сжатия t

# --- МАТЕМАТИЧЕСКОЕ ЯДРО ---

def poly_add(f, g):
    """Сложение двух многочленов по модулю q."""
    return (f + g) % q

def poly_sub(f, g):
    """Вычитание двух многочленов по модулю q."""
    return (f - g) % q

def poly_mul(f, g):
    """
    Умножение многочленов в кольце Rq = Zq[X] / (X^n + 1).
    Используем простую свертку с редукцией X^n = -1.
    В боевых версиях тут используется NTT (Number Theoretic Transform).
    """
    # Обычное умножение
    res = np.convolve(f, g)
    # Редукция по модулю X^n + 1
    # Коэффициенты c[i] при i >= n переносятся назад: c[i mod n] -= c[i]
    coeffs = np.zeros(n, dtype=int)
    for i in range(len(res)):
        coeffs[i % n] += res[i] * (1 if i < n else -1)
    return coeffs % q

def matvec_mul(A, s):
    """Умножение матрицы полиномов A (k x k) на вектор полиномов s (k)."""
    # Результат - вектор t размера k
    t = np.zeros((k, n), dtype=int)
    for i in range(k):
        for j in range(k):
            t[i] = poly_add(t[i], poly_mul(A[i][j], s[j]))
    return t

def vec_dot(a, b):
    """Скалярное произведение двух векторов полиномов (транспонированное умножение)."""
    res = np.zeros(n, dtype=int)
    for i in range(k):
        res = poly_add(res, poly_mul(a[i], b[i]))
    return res

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (Шум и Сжатие) ---

def sample_noise():
    """
    Генерация шума из центрированного биномиального распределения B_eta.
    Это упрощенная версия без криптостойкого PRNG, для учебных целей.
    """
    # B_eta = sum(a_i - b_i), где a_i, b_i - случайные биты.
    # Генерируем сразу n коэффициентов.
    coeffs = np.zeros(n, dtype=int)
    for i in range(n):
        a = sum(np.random.randint(0, 2, eta))
        b = sum(np.random.randint(0, 2, eta))
        coeffs[i] = (a - b) % q
    return coeffs

def sample_matrix():
    """Генерация случайной матрицы A (k x k) из равномерного распределения."""
    # В реальности A генерируется из seed (rho) через SHAKE-128.
    A = np.random.randint(0, q, (k, k, n))
    return A

def compress(x, d):
    """
    Функция Compress_q(x, d).
    Отбрасывает младшие биты, оставляя d бит.
    Формула: ⌈(2^d / q) * x⌋ mod 2^d
    """
    scale = (2**d) / q
    return np.round(scale * x).astype(int) % (2**d)

def decompress(x, d):
    """
    Функция Decompress_q(x, d).
    Восстанавливает число из сжатого формата.
    Формула: ⌈(q / 2^d) * x⌋
    """
    scale = q / (2**d)
    return np.round(scale * x).astype(int)

# --- ОСНОВНЫЕ АЛГОРИТМЫ KYBER (KeyGen, Enc, Dec) ---

def KeyGen():
    """
    Алгоритм 1: Генерация ключей.
    Математика: t = A*s + e (структура LWE).
    """
    # 1. Генерируем матрицу A (публичный параметр, общий для всех)
    A = sample_matrix() 
    
    # 2. Генерируем секретный вектор s и вектор ошибки e
    s = np.array([sample_noise() for _ in range(k)])
    e = np.array([sample_noise() for _ in range(k)])
    
    # 3. Вычисляем публичный ключ t = A * s + e
    # Это основа LWE: t выглядит случайным, если не знать s и e.
    As = matvec_mul(A, s)
    t_raw = np.array([poly_add(As[i], e[i]) for i in range(k)])
    
    # 4. Сжатие публичного ключа (опционально в теории, обязательно в Kyber)
    # t сжимается до dt бит для уменьшения размера ключа.
    t = np.array([compress(poly, dt) for poly in t_raw])
    
    pk = (t, A) # Публичный ключ (A обычно передается как seed, здесь явно)
    sk = s      # Секретный ключ
    
    return pk, sk

def Enc(pk, m_bits):
    """
    Алгоритм 2: Шифрование сообщения m.
    m_bits - список из 256 бит (0 или 1).
    Математика: u = A^T * r + e1; v = t^T * r + e2 + msg_encoding
    """
    t_compressed, A = pk
    
    # 1. Разжимаем t (так как он был сжат в KeyGen)
    t = np.array([decompress(poly, dt) for poly in t_compressed])
    
    # 2. Преобразуем сообщение в полином
    # Бит 1 кодируется как ceil(q/2), бит 0 как 0.
    # Это разносит 0 и 1 максимально далеко друг от друга в кольце Zq.
    m_poly = np.zeros(n, dtype=int)
    for i in range(n):
        if m_bits[i] == 1:
            m_poly[i] = int(np.round(q / 2))
            
    # 3. Генерируем эфемерный (одноразовый) секрет r и ошибки e1, e2
    r = np.array([sample_noise() for _ in range(k)])
    e1 = np.array([sample_noise() for _ in range(k)])
    e2 = sample_noise()
    
    # 4. Вычисляем первую часть шифртекста: u = A^T * r + e1
    # A^T - транспонированная матрица (индексы [j][i] вместо [i][j])
    A_T = np.transpose(A, (1, 0, 2)) 
    Ar = matvec_mul(A_T, r)
    u_raw = np.array([poly_add(Ar[i], e1[i]) for i in range(k)])
    
    # 5. Вычисляем вторую часть шифртекста: v = t^T * r + e2 + m
    # t^T * r - скалярное произведение векторов полиномов
    tr = vec_dot(t, r)
    v_raw = poly_add(poly_add(tr, e2), m_poly)
    
    # 6. Сжимаем шифртекст
    u = np.array([compress(poly, du) for poly in u_raw])
    v = compress(v_raw, dv)
    
    return (u, v)

def Dec(sk, c):
    """
    Алгоритм 3: Дешифрование.
    Математика: message ≈ v - s^T * u
    """
    u_compressed, v_compressed = c
    s = sk
    
    # 1. Разжимаем компоненты шифртекста
    u = np.array([decompress(poly, du) for poly in u_compressed])
    v = decompress(v_compressed, dv)
    
    # 2. Вычисляем "шумное" сообщение: M_noisy = v - s^T * u
    # Подставим уравнения из Enc:
    # v - s^T*u = (t^T*r + e2 + m) - s^T*(A^T*r + e1)
    #           ≈ (s^T*A^T*r + m) - s^T*A^T*r  (т.к. t ≈ As)
    #           ≈ m + шум
    su = vec_dot(s, u)
    m_noisy = poly_sub(v, su)
    
    # 3. Декодируем сообщение (Compress_q(x, 1))
    # Если число близко к q/2, это 1. Если к 0, это 0.
    decrypted_bits = []
    for val in m_noisy:
        # Проверка: ближе к 0 или к q/2?
        # Используем встроенную функцию compress с d=1, она делает именно это:
        # 0..q/4 -> 0, q/4..3q/4 -> 1, 3q/4..q -> 0
        bit = compress(val, 1)
        decrypted_bits.append(bit)
        
    return decrypted_bits

# --- ТЕСТИРОВАНИЕ С ЧИТАЕМЫМ ВЫВОДОМ ---

def format_vector_summary(arr, name):
    """Форматирует краткую статистику по вектору/матрице."""
    flat = arr.flatten()
    return (f"{name}:\n"
            f"  Форма: {arr.shape}\n"
            f"  Диапазон: [{flat.min()}, {flat.max()}]\n"
            f"  Среднее: {flat.mean():.2f}\n"
            f"  Пример первых 5 элементов: {flat[:5]}\n")

def format_bits(bits, max_show=32):
    """Форматирует биты для компактного отображения."""
    bits_str = ''.join(map(str, bits[:max_show]))
    if len(bits) > max_show:
        bits_str += f"... (всего {len(bits)} бит)"
    return bits_str

# Генерируем читаемое сообщение (первые 16 бит = 1, остальные = 0)
original_msg = [1]*16 + [0]*(n-16)
print("="*70)
print("KYBER.CPA - ДЕМОНСТРАЦИЯ РАБОТЫ")
print("="*70)

print("\n[ШАГ 1] ГЕНЕРАЦИЯ КЛЮЧЕЙ")
print("-"*70)
pk, sk = KeyGen()
t_comp, A = pk
print(format_vector_summary(A, "Матрица A (публичная)"))
print(format_vector_summary(sk, "Секретный ключ s"))
print(format_vector_summary(t_comp, "Публичный ключ t (сжатый)"))

print("\n[ШАГ 2] ШИФРОВАНИЕ")
print("-"*70)
print(f"Исходное сообщение (биты): {format_bits(original_msg)}")
ciphertext = Enc(pk, original_msg)
u_enc, v_enc = ciphertext
print(format_vector_summary(u_enc, "Шифртекст u (сжатый)"))
print(format_vector_summary(v_enc, "Шифртекст v (сжатый)"))

print("\n[ШАГ 3] ДЕШИФРОВАНИЕ")
print("-"*70)
decrypted_msg = Dec(sk, ciphertext)
print(f"Расшифрованное сообщение:  {format_bits(decrypted_msg)}")

print("\n[РЕЗУЛЬТАТ]")
print("="*70)
if original_msg == decrypted_msg:
    print("✓ УСПЕХ! Сообщение расшифровано без ошибок.")
else:
    errors = sum([1 for i in range(n) if original_msg[i] != decrypted_msg[i]])
    print(f"✗ ОШИБКА! Неверных бит: {errors}/{n} ({100*errors/n:.2f}%)")
    
print("\nРазмеры передаваемых данных:")
print(f"  Публичный ключ: {k * n * dt // 8} байт (t) + seed для A")
print(f"  Шифртекст: {k * n * du // 8 + n * dv // 8} байт")
print(f"  Секретный ключ: {k * n * 12 // 8} байт (примерно)")
print("="*70)
