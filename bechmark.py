# benchmark.py
import time
import numpy as np
from main import KeyGen, Enc, Dec, n, k, q, eta, du, dv, dt

def benchmark_function(func, *args, iterations=100):
    """Измеряет производительность функции"""
    times = []
    
    print(f"Запуск {iterations} итераций для {func.__name__}...", end=" ", flush=True)
    
    for i in range(iterations):
        start = time.perf_counter()
        result = func(*args)
        end = time.perf_counter()
        times.append((end - start) * 1000)  # Конвертируем в миллисекунды
        
        # Прогресс бар (каждые 10%)
        if (i + 1) % (iterations // 10) == 0:
            print(f"{((i+1)/iterations)*100:.0f}%", end=" ", flush=True)
    
    print("✓")
    
    times = np.array(times)
    return {
        'mean': np.mean(times),
        'median': np.median(times),
        'std': np.std(times),
        'min': np.min(times),
        'max': np.max(times),
        'total': np.sum(times),
        'result': result  # Для передачи в следующую функцию
    }

def print_stats(name, stats, iterations):
    """Красивый вывод статистики"""
    print(f"\n{'='*70}")
    print(f"  {name}")
    print(f"{'='*70}")
    print(f"  Итераций:           {iterations}")
    print(f"  Среднее время:      {stats['mean']:.4f} мс")
    print(f"  Медиана:            {stats['median']:.4f} мс")
    print(f"  Мин / Макс:         {stats['min']:.4f} мс / {stats['max']:.4f} мс")
    print(f"  Станд. отклонение:  {stats['std']:.4f} мс")
    print(f"  Пропускная способ:  {1000/stats['mean']:.2f} операций/сек")
    print(f"  Общее время:        {stats['total']/1000:.2f} сек")
    print(f"{'='*70}")

def main():
    print("\n" + "█"*70)
    print("█" + " "*22 + "KYBER BENCHMARK SUITE" + " "*26 + "█")
    print("█"*70)
    
    print(f"\nПараметры безопасности:")
    print(f"  n={n}, k={k}, q={q}, eta={eta}, du={du}, dv={dv}, dt={dt}")
    
    iterations = 100
    print(f"\nКоличество итераций на функцию: {iterations}")
    
    # 1. ГЕНЕРАЦИЯ КЛЮЧЕЙ
    print("\n" + "-"*70)
    print("[1/3] Бенчмарк KeyGen()")
    print("-"*70)
    keygen_stats = benchmark_function(KeyGen, iterations=iterations)
    print_stats("ГЕНЕРАЦИЯ КЛЮЧЕЙ (KeyGen)", keygen_stats, iterations)
    
    pk, sk = keygen_stats['result']
    
    # 2. ШИФРОВАНИЕ
    print("\n" + "-"*70)
    print("[2/3] Бенчмарк Enc()")
    print("-"*70)
    test_message = [1] * 128 + [0] * (n - 128)  # Тестовое сообщение
    enc_stats = benchmark_function(Enc, pk, test_message, iterations=iterations)
    print_stats("ШИФРОВАНИЕ (Enc)", enc_stats, iterations)
    
    ciphertext = enc_stats['result']
    
    # 3. ДЕШИФРОВАНИЕ
    print("\n" + "-"*70)
    print("[3/3] Бенчмарк Dec()")
    print("-"*70)
    dec_stats = benchmark_function(Dec, sk, ciphertext, iterations=iterations)
    print_stats("ДЕШИФРОВАНИЕ (Dec)", dec_stats, iterations)
    
    # ПРОВЕРКА КОРРЕКТНОСТИ
    decrypted = dec_stats['result']
    errors = sum(1 for i in range(n) if test_message[i] != decrypted[i])
    
    print("\n" + "█"*70)
    print("█" + " "*25 + "ИТОГОВАЯ СВОДКА" + " "*29 + "█")
    print("█"*70)
    print(f"\n  Корректность дешифрования: {'✓ УСПЕХ' if errors == 0 else f'✗ ОШИБОК: {errors}/{n}'}")
    print(f"\n  Общая производительность:")
    print(f"    KeyGen:  {1000/keygen_stats['mean']:>7.2f} оп/сек  ({keygen_stats['mean']:.3f} мс)")
    print(f"    Enc:     {1000/enc_stats['mean']:>7.2f} оп/сек  ({enc_stats['mean']:.3f} мс)")
    print(f"    Dec:     {1000/dec_stats['mean']:>7.2f} оп/сек  ({dec_stats['mean']:.3f} мс)")
    
    full_cycle = keygen_stats['mean'] + enc_stats['mean'] + dec_stats['mean']
    print(f"\n  Полный цикл (KeyGen+Enc+Dec): {full_cycle:.3f} мс")
    print(f"  Пропускная способность цикла:  {1000/full_cycle:.2f} циклов/сек")
    
    # ТЕОРЕТИЧЕСКИЕ РАЗМЕРЫ
    pk_size = (k * n * dt // 8) + 32
    sk_size = k * n * 12 // 8
    ct_size = (k * n * du // 8) + (n * dv // 8)
    
    print(f"\n  Размеры данных (байты):")
    print(f"    Публичный ключ:    ~{pk_size} байт")
    print(f"    Секретный ключ:    ~{sk_size} байт")
    print(f"    Шифртекст:          {ct_size} байт")
    print(f"    Сообщение:          {n//8} байт ({n} бит)")
    
    print("\n" + "█"*70 + "\n")

if __name__ == "__main__":
    main()
