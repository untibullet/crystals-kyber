# kyber_gui.py
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import json
import base64
import numpy as np
import tracemalloc
from main import KeyGen, Enc, Dec, n, k, q, eta, du, dv, dt

class KyberGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CRYSTALS-Kyber GUI (Education Mode)")
        self.root.geometry("750x700")
        
        # Запуск отслеживания памяти
        tracemalloc.start()
        
        # 1. Панель параметров (НОВОЕ)
        self._setup_info_panel()
        
        # Создаем notebook с вкладками
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Вкладки
        self.tab_keygen = ttk.Frame(self.notebook)
        self.tab_encrypt = ttk.Frame(self.notebook)
        self.tab_decrypt = ttk.Frame(self.notebook)
        
        self.notebook.add(self.tab_keygen, text='Генерация ключей')
        self.notebook.add(self.tab_encrypt, text='Шифрование')
        self.notebook.add(self.tab_decrypt, text='Дешифрование')
        
        self._setup_keygen_tab()
        self._setup_encrypt_tab()
        self._setup_decrypt_tab()
        
        # 2. Статус бар для RAM (НОВОЕ)
        self.status_bar = ttk.Label(root, text="RAM Usage: Calculating...", relief=tk.SUNKEN, anchor='e')
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self._update_ram_usage()

    def _setup_info_panel(self):
        """Панель основных параметров алгоритма"""
        frame = ttk.LabelFrame(self.root, text="Параметры безопасности (Kyber-768)", padding="5")
        frame.pack(fill='x', padx=10, pady=5)
        
        params = f"n = {n} (степень полинома) | k = {k} (ранг модуля) | q = {q} (модуль) | eta = {eta} (шум)"
        ttk.Label(frame, text=params, font=('Consolas', 10)).pack()

    def _setup_keygen_tab(self):
        frame = ttk.Frame(self.tab_keygen, padding="10")
        frame.pack(fill='both', expand=True)
        
        ttk.Button(frame, text="Сгенерировать ключи", command=self._generate_keys).pack(pady=5)
        
        # Публичный ключ
        pk_size = (k * n * dt // 8) + 32 # 32 байта на seed (обычно)
        ttk.Label(frame, text="Публичный ключ (t + seed):").pack(anchor='w')
        self.pk_text = scrolledtext.ScrolledText(frame, height=6, wrap=tk.WORD)
        self.pk_text.pack(fill='both', expand=True)
        # Метка размера (НОВОЕ)
        ttk.Label(frame, text=f"Теоретический размер: ~{pk_size} байт", 
                 foreground="gray").pack(anchor='e')
        ttk.Button(frame, text="Копировать PK", 
                   command=lambda: self._copy_to_clipboard(self.pk_text)).pack(pady=2)
        
        # Секретный ключ
        sk_size = k * n * 12 // 8 # Примерный размер упакованного ключа
        ttk.Label(frame, text="Секретный ключ (s):").pack(anchor='w', pady=(5,0))
        self.sk_text = scrolledtext.ScrolledText(frame, height=6, wrap=tk.WORD)
        self.sk_text.pack(fill='both', expand=True)
        # Метка размера (НОВОЕ)
        ttk.Label(frame, text=f"Теоретический размер: ~{sk_size} байт", 
                 foreground="gray").pack(anchor='e')
        ttk.Button(frame, text="Копировать SK", 
                   command=lambda: self._copy_to_clipboard(self.sk_text)).pack(pady=2)

    def _setup_encrypt_tab(self):
        frame = ttk.Frame(self.tab_encrypt, padding="10")
        frame.pack(fill='both', expand=True)
        
        ttk.Label(frame, text="Публичный ключ:").pack(anchor='w')
        self.pk_enc_text = scrolledtext.ScrolledText(frame, height=4, wrap=tk.WORD)
        self.pk_enc_text.pack(fill='both', expand=True)
        
        ttk.Label(frame, text=f"Сообщение ({n} бит):").pack(anchor='w', pady=(5,0))
        self.msg_text = scrolledtext.ScrolledText(frame, height=3, wrap=tk.WORD)
        self.msg_text.pack(fill='both', expand=True)
        
        ttk.Button(frame, text="Зашифровать", command=self._encrypt_message).pack(pady=5)
        
        # Шифртекст
        ct_size = (k * n * du // 8) + (n * dv // 8)
        ttk.Label(frame, text="Шифртекст (u, v):").pack(anchor='w')
        self.ct_text = scrolledtext.ScrolledText(frame, height=4, wrap=tk.WORD)
        self.ct_text.pack(fill='both', expand=True)
        # Метка размера (НОВОЕ)
        ttk.Label(frame, text=f"Теоретический размер: {ct_size} байт", 
                 foreground="gray").pack(anchor='e')
        ttk.Button(frame, text="Копировать CT", 
                   command=lambda: self._copy_to_clipboard(self.ct_text)).pack(pady=2)

    def _setup_decrypt_tab(self):
        frame = ttk.Frame(self.tab_decrypt, padding="10")
        frame.pack(fill='both', expand=True)
        
        ttk.Label(frame, text="Секретный ключ:").pack(anchor='w')
        self.sk_dec_text = scrolledtext.ScrolledText(frame, height=5, wrap=tk.WORD)
        self.sk_dec_text.pack(fill='both', expand=True)
        
        ttk.Label(frame, text="Шифртекст:").pack(anchor='w', pady=(5,0))
        self.ct_dec_text = scrolledtext.ScrolledText(frame, height=5, wrap=tk.WORD)
        self.ct_dec_text.pack(fill='both', expand=True)
        
        ttk.Button(frame, text="Дешифровать", command=self._decrypt_message).pack(pady=10)
        
        ttk.Label(frame, text="Результат:").pack(anchor='w')
        self.dec_msg_text = scrolledtext.ScrolledText(frame, height=4, wrap=tk.WORD)
        self.dec_msg_text.pack(fill='both', expand=True)

    def _update_ram_usage(self):
        """Обновление информации об оперативной памяти"""
        current, peak = tracemalloc.get_traced_memory()
        # Конвертируем в МБ
        current_mb = current / 10**6
        peak_mb = peak / 10**6
        self.status_bar.config(text=f"RAM (Python Alloc): {current_mb:.2f} MB | Peak: {peak_mb:.2f} MB")
        # Обновляем каждые 1000 мс (1 секунда)
        self.root.after(1000, self._update_ram_usage)

    def _generate_keys(self):
        try:
            pk, sk = KeyGen()
            pk_dict = {'t': pk[0].tolist(), 'A': pk[1].tolist()}
            sk_dict = sk.tolist()
            
            pk_str = base64.b64encode(json.dumps(pk_dict).encode()).decode()
            sk_str = base64.b64encode(json.dumps(sk_dict).encode()).decode()
            
            self.pk_text.delete('1.0', tk.END); self.pk_text.insert('1.0', pk_str)
            self.sk_text.delete('1.0', tk.END); self.sk_text.insert('1.0', sk_str)
            messagebox.showinfo("Успех", "Ключи сгенерированы!")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def _encrypt_message(self):
        try:
            pk_str = self.pk_enc_text.get('1.0', tk.END).strip()
            msg_str = self.msg_text.get('1.0', tk.END).strip().replace(' ', '').replace('\n', '')
            
            if not pk_str or not msg_str: return
            
            pk_dict = json.loads(base64.b64decode(pk_str).decode())
            # ВАЖНО: Оборачиваем списки обратно в np.array
            pk = (
                np.array(pk_dict['t']), 
                np.array(pk_dict['A'])
            )
            
            # Преобразование сообщения в биты
            msg_bits = [int(b) for b in msg_str]
            
            if len(msg_bits) < n:
                # Дополняем нулями справа, если длина меньше n (256)
                msg_bits.extend([0] * (n - len(msg_bits)))
            elif len(msg_bits) > n:
                # Обрезаем, если больше (на всякий случай)
                msg_bits = msg_bits[:n]
            
            ciphertext = Enc(pk, msg_bits)
            ct_dict = {'u': ciphertext[0].tolist(), 'v': ciphertext[1].tolist()}
            ct_str = base64.b64encode(json.dumps(ct_dict).encode()).decode()
            
            self.ct_text.delete('1.0', tk.END); self.ct_text.insert('1.0', ct_str)
            messagebox.showinfo("Успех", "Зашифровано!")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def _decrypt_message(self):
        try:
            sk_str = self.sk_dec_text.get('1.0', tk.END).strip()
            ct_str = self.ct_dec_text.get('1.0', tk.END).strip()
            
            if not sk_str or not ct_str: return
            
            # ВАЖНО: Оборачиваем списки обратно в np.array
            sk = np.array(json.loads(base64.b64decode(sk_str).decode()))
            ct_dict = json.loads(base64.b64decode(ct_str).decode())
            ciphertext = (
                np.array(ct_dict['u']), 
                np.array(ct_dict['v'])
            )
            
            decrypted_bits = Dec(sk, ciphertext)
            msg_str = ''.join(map(str, decrypted_bits))
            
            self.dec_msg_text.delete('1.0', tk.END); self.dec_msg_text.insert('1.0', msg_str)
            messagebox.showinfo("Успех", "Расшифровано!")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def _copy_to_clipboard(self, widget):
        content = widget.get('1.0', tk.END).strip()
        if content:
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            messagebox.showinfo("Info", "Скопировано!")

if __name__ == "__main__":
    root = tk.Tk()
    app = KyberGUI(root)
    root.mainloop()
