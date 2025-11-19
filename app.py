import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import crypto_core  # Bizim yazdığımız kripto motorunu import ediyoruz!
import os

class SecureApp(tk.Tk):

    def __init__(self):
        super().__init__()

        self.title("Secure Encryption Tool")
        self.geometry("550x550") # Pencere boyutu
        self.minsize(500, 500) # Minimum boyut

        # Ana stil ayarları
        style = ttk.Style(self)
        style.configure("TButton", padding=6, relief="flat")
        style.configure("TFrame", padding=10)
        style.configure("TRadiobutton", padding=5)

        # --- 1. PAROLA BÖLÜMÜ (Tüm modlar için ortak) ---
        password_frame = ttk.Frame(self)
        password_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(password_frame, text="Master Password:").pack(side=tk.LEFT, padx=5)
        self.password_entry = ttk.Entry(password_frame, show="*")
        self.password_entry.pack(side=tk.LEFT, fill='x', expand=True)

        # --- 2. MOD SEÇİMİ (Radio Butonlar) ---
        self.mode_var = tk.StringVar(value="text")
        mode_frame = ttk.Frame(self, padding=(10, 5))
        mode_frame.pack(fill='x')
        
        ttk.Label(mode_frame, text="Mode:").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(mode_frame, text="Text Mode", variable=self.mode_var, value="text", command=self.switch_mode).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(mode_frame, text="File Mode", variable=self.mode_var, value="file", command=self.switch_mode).pack(side=tk.LEFT, padx=5)

        # --- 3. MODLARA ÖZEL PENCERELER (Frame) ---
        self.container = ttk.Frame(self)
        self.container.pack(fill='both', expand=True)

        # İki ana frame'i (text ve file) üst üste koyuyoruz
        self.text_frame = ttk.Frame(self.container)
        self.file_frame = ttk.Frame(self.container)

        self.text_frame.grid(row=0, column=0, sticky="nsew")
        self.file_frame.grid(row=0, column=0, sticky="nsew")
        
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        # Bu framelerin içini dolduran fonksiyonları çağır
        self.create_text_widgets()
        self.create_file_widgets()

        # --- 4. DURUM ÇUBUĞU (Alttaki mesaj) ---
        self.status_var = tk.StringVar(value="Ready. Log file: secure_app.log")
        status_bar = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=5)
        status_bar.pack(side=tk.BOTTOM, fill='x')

        # Başlangıçta "text" modunu göster
        self.switch_mode()

    def create_text_widgets(self):
        """Metin modu için gerekli arayüz elemanlarını (widget) oluşturur."""
        ttk.Label(self.text_frame, text="Input Text (Plaintext):").pack(pady=(5,0), anchor=tk.W)
        self.text_input = tk.Text(self.text_frame, height=8, width=50, wrap=tk.WORD, relief=tk.SOLID, borderwidth=1)
        self.text_input.pack(pady=5, fill='both', expand=True)

        ttk.Label(self.text_frame, text="Output (Ciphertext / Decrypted):").pack(pady=(10,0), anchor=tk.W)
        self.text_output = tk.Text(self.text_frame, height=8, width=50, wrap=tk.WORD, relief=tk.SOLID, borderwidth=1)
        self.text_output.pack(pady=5, fill='both', expand=True)

        # Butonları içeren frame
        btn_frame = ttk.Frame(self.text_frame, padding=0)
        btn_frame.pack(pady=5, fill='x')
        
        ttk.Button(btn_frame, text="Encrypt Text", command=self.encrypt_text_action).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Decrypt Text", command=self.decrypt_text_action).pack(side=tk.LEFT, padx=5)
        
        # --- YENİ ÖZELLİK: PANO BUTONU ---
        ttk.Button(btn_frame, text="Copy Output", command=self.copy_to_clipboard).pack(side=tk.RIGHT, padx=5)

    def create_file_widgets(self):
        """Dosya modu için gerekli arayüz elemanlarını (widget) oluşturur."""
        file_container = ttk.Frame(self.file_frame)
        file_container.pack(pady=20, fill='x')

        self.file_path_var = tk.StringVar(value="No file selected.")
        self.selected_file_label = ttk.Label(file_container, textvariable=self.file_path_var, font=("Helvetica", 10, "italic"))
        self.selected_file_label.pack(pady=10)

        ttk.Button(file_container, text="Browse for File...", command=self.browse_file).pack(pady=10)

        file_btn_frame = ttk.Frame(file_container)
        file_btn_frame.pack(pady=20)
        ttk.Button(file_btn_frame, text="Encrypt File", command=self.encrypt_file_action).pack(side=tk.LEFT, padx=10)
        ttk.Button(file_btn_frame, text="Decrypt File", command=self.decrypt_file_action).pack(side=tk.LEFT, padx=10)

    # --- YARDIMCI VE AKSİYON FONKSİYONLARI ---

    def get_password(self):
        """Parolayı alır ve boş olup olmadığını kontrol eder."""
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Password Error", "Please enter a master password.")
            self.status_var.set("Error: Password cannot be empty.")
            return None
        return password

    def switch_mode(self):
        """Radyo butona göre Text veya File frame'ini öne çıkarır."""
        mode = self.mode_var.get()
        if mode == "text":
            self.file_frame.grid_remove()
            self.text_frame.grid()
            self.status_var.set("Text Mode activated.")
        elif mode == "file":
            self.text_frame.grid_remove()
            self.file_frame.grid()
            self.status_var.set("File Mode activated.")

    def copy_to_clipboard(self):
        """YENİ ÖZELLİK: Çıktı kutusundaki metni panoya kopyalar."""
        try:
            self.clipboard_clear()
            self.clipboard_append(self.text_output.get("1.0", tk.END).strip())
            self.status_var.set("Output copied to clipboard!")
        except Exception as e:
            self.status_var.set(f"Error copying to clipboard: {e}")

    def browse_file(self):
        """Dosya seçme penceresini açar."""
        # filedialog.askopenfilename, Mac'in doğal dosya seçme penceresini açar
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path_var.set(file_path)
            self.status_var.set(f"Selected file: {os.path.basename(file_path)}")
        else:
            self.file_path_var.set("No file selected.")
            self.status_var.set("File selection cancelled.")

    # --- Kripto Çekirdeğini (crypto_core) Çağıran Fonksiyonlar ---

    def encrypt_text_action(self):
        password = self.get_password()
        if not password: return
        
        plaintext = self.text_input.get("1.0", tk.END).strip()
        if not plaintext:
            messagebox.showwarning("Input Error", "Input text cannot be empty.")
            return

        self.status_var.set("Encrypting text... (This may take a second)")
        self.update_idletasks() # Arayüzü güncel tut
        
        result = crypto_core.encrypt_text(password, plaintext)
        
        self.text_output.delete("1.0", tk.END) # Önceki çıktıyı temizle
        if result:
            self.text_output.insert("1.0", result)
            self.status_var.set("Text encrypted successfully. (Log updated)")
        else:
            self.status_var.set("Error during encryption. Check log.")
            messagebox.showerror("Error", "An error occurred during encryption. Check 'secure_app.log' for details.")

    def decrypt_text_action(self):
        password = self.get_password()
        if not password: return

        packaged_data = self.text_output.get("1.0", tk.END).strip()
        if not packaged_data:
            messagebox.showwarning("Input Error", "Output/Input field is empty.")
            return
            
        self.status_var.set("Decrypting text... (This may take a second)")
        self.update_idletasks()

        result = crypto_core.decrypt_text(password, packaged_data)
        
        if "[HATA]" in result:
            self.status_var.set("Decryption FAILED. Wrong password or corrupted data.")
            messagebox.showerror("Decryption Failed", "Wrong password or data is corrupted. (Log updated)")
        else:
            self.text_output.delete("1.0", tk.END)
            self.text_output.insert("1.0", result)
            self.status_var.set("Text decrypted successfully. (Log updated)")

    def encrypt_file_action(self):
        password = self.get_password()
        if not password: return

        file_path = self.file_path_var.get()
        if file_path == "No file selected.":
            messagebox.showwarning("File Error", "Please browse and select a file first.")
            return

        self.status_var.set(f"Encrypting file... (This may take a second)")
        self.update_idletasks()
        
        result_path = crypto_core.encrypt_file(password, file_path)
        
        if result_path and "[HATA]" not in result_path:
            self.status_var.set(f"File encrypted and saved to: {result_path}")
            messagebox.showinfo("Success", f"File encrypted successfully!\nSaved as: {result_path}")
        else:
            self.status_var.set("Error during file encryption. Check log.")
            messagebox.showerror("Error", "An error occurred during file encryption. Check 'secure_app.log' for details.")

    def decrypt_file_action(self):
        password = self.get_password()
        if not password: return

        file_path = self.file_path_var.get()
        if file_path == "No file selected.":
            messagebox.showwarning("File Error", "Please browse and select a file first.")
            return
        if not file_path.endswith(".enc"):
            messagebox.showwarning("File Error", "Please select a '.enc' file to decrypt.")
            return
            
        self.status_var.set(f"Decrypting file... (This may take a second)")
        self.update_idletasks()

        result_path = crypto_core.decrypt_file(password, file_path)

        if result_path and "[HATA]" not in result_path:
            self.status_var.set(f"File decrypted and saved to: {result_path}")
            messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as: {result_path}")
        else:
            self.status_var.set("Decryption FAILED. Wrong password or corrupted data.")
            messagebox.showerror("Decryption Failed", "Wrong password or file is corrupted. (Log updated)")


if __name__ == "__main__":
    app = SecureApp()
    app.mainloop()