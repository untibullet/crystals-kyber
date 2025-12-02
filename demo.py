from main import *

# Демонстрация работы
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