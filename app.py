import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import crypto_core
import db_manager

class SecureApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Vault & Encryption Tool")
        self.geometry("850x650")
        db_manager.init_db()
        
        # Son işlemi takip etmek için durum değişkeni
        self.last_action = None 

        # Layout Ayarları
        main_paned = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        main_paned.pack(fill='both', expand=True)

        self.left_frame = ttk.Frame(main_paned, padding=10)
        self.right_frame = ttk.Frame(main_paned, padding=10)
        main_paned.add(self.left_frame, weight=3)
        main_paned.add(self.right_frame, weight=1)

        self.setup_left_panel()
        self.setup_right_panel()
        self.refresh_note_list()

    def setup_left_panel(self):
        # Üst Kısım: Parola ve Mod
        ttk.Label(self.left_frame, text="Master Password:").pack(anchor=tk.W)
        self.password_entry = ttk.Entry(self.left_frame, show="*")
        self.password_entry.pack(fill='x', pady=5)

        self.mode_var = tk.StringVar(value="text")
        m_frame = ttk.Frame(self.left_frame)
        m_frame.pack(fill='x', pady=5)
        ttk.Radiobutton(m_frame, text="Text Mode", variable=self.mode_var, value="text", command=self.toggle_mode).pack(side=tk.LEFT)
        ttk.Radiobutton(m_frame, text="File Mode", variable=self.mode_var, value="file", command=self.toggle_mode).pack(side=tk.LEFT, padx=15)

        # --- TEXT UI ---
        self.text_ui = ttk.Frame(self.left_frame)
        ttk.Label(self.text_ui, text="Original:").pack(anchor=tk.W)
        self.text_input = tk.Text(self.text_ui, height=7)
        self.text_input.pack(fill='both', expand=True, pady=5)

        ttk.Label(self.text_ui, text="Encrypted:").pack(anchor=tk.W)
        self.text_output = tk.Text(self.text_ui, height=7)
        self.text_output.pack(fill='both', expand=True, pady=5)

        db_f = ttk.Frame(self.text_ui)
        db_f.pack(fill='x', pady=5)
        ttk.Label(db_f, text="Note Title:").pack(side=tk.LEFT)
        self.title_entry = ttk.Entry(db_f)
        self.title_entry.pack(side=tk.LEFT, fill='x', expand=True, padx=5)

        btn_f = ttk.Frame(self.text_ui)
        btn_f.pack(fill='x', pady=5)
        ttk.Button(btn_f, text="Encrypt & Save", command=self.encrypt_and_save).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_f, text="Decrypt Text", command=self.decrypt_action).pack(side=tk.LEFT, padx=2)
        
        # YENİ: Kopyalama Butonu
        ttk.Button(btn_f, text="Copy Clipboard", command=self.copy_to_clipboard).pack(side=tk.LEFT, padx=2)

        # --- FILE UI ---
        self.file_ui = ttk.Frame(self.left_frame)
        ttk.Label(self.file_ui, text="File Path:").pack(anchor=tk.W)
        self.file_path_entry = ttk.Entry(self.file_ui)
        self.file_path_entry.pack(fill='x', pady=5)
        ttk.Button(self.file_ui, text="Browse File", command=self.browse_file).pack(pady=5)
        
        f_btn_f = ttk.Frame(self.file_ui)
        f_btn_f.pack(pady=10)
        ttk.Button(f_btn_f, text="Encrypt File", command=self.encrypt_file_action).pack(side=tk.LEFT, padx=5)
        ttk.Button(f_btn_f, text="Decrypt File", command=self.decrypt_file_action).pack(side=tk.LEFT, padx=5)

        self.toggle_mode()

    def setup_right_panel(self):
        ttk.Label(self.right_frame, text="Database Notes").pack()
        self.notes_listbox = tk.Listbox(self.right_frame)
        self.notes_listbox.pack(fill='both', expand=True, pady=5)
        ttk.Button(self.right_frame, text="Load", command=self.load_note).pack(fill='x', pady=2)
        ttk.Button(self.right_frame, text="Delete", command=self.delete_note).pack(fill='x', pady=2)

    # YENİ: Kopyalama Fonksiyonu
    def copy_to_clipboard(self):
        if self.last_action == "encrypt":
            # Şifreleme yapıldıysa 'Input' (Original) alanını kopyala
            content = self.text_input.get("1.0", tk.END).strip()
            msg = "Giriş metni (Original) kopyalandı."
        elif self.last_action == "decrypt":
            # Deşifreleme yapıldıysa 'Output' (çözülen metin Original kutusuna gider) alanını kopyala
            content = self.text_input.get("1.0", tk.END).strip()
            msg = "Çözülen metin (Output) kopyalandı."
        else:
            messagebox.showwarning("Uyarı", "Lütfen önce bir işlem yapın.")
            return

        if content:
            self.clipboard_clear()
            self.clipboard_append(content)
            messagebox.showinfo("Başarılı", msg)

    def toggle_mode(self):
        if self.mode_var.get() == "text":
            self.file_ui.pack_forget()
            self.text_ui.pack(fill='both', expand=True)
        else:
            self.text_ui.pack_forget()
            self.file_ui.pack(fill='both', expand=True)

    def browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, path)

    def encrypt_and_save(self):
        pw, txt, title = self.password_entry.get(), self.text_input.get("1.0", tk.END).strip(), self.title_entry.get().strip()
        if not pw or not txt: return
        enc = crypto_core.encrypt_text(pw, txt)
        self.text_output.delete("1.0", tk.END)
        self.text_output.insert("1.0", enc)
        
        self.last_action = "encrypt" # Durumu güncelle
        
        if title:
            db_manager.save_note(title, enc)
            self.refresh_note_list()

    def decrypt_action(self):
        pw, data = self.password_entry.get(), self.text_output.get("1.0", tk.END).strip()
        if not pw or not data: return
        res = crypto_core.decrypt_text(pw, data)
        if "[HATA]" not in res:
            self.text_input.delete("1.0", tk.END)
            self.text_input.insert("1.0", res)
            
            self.last_action = "decrypt" # Durumu güncelle
        else: messagebox.showerror("Error", res)

    def encrypt_file_action(self):
        pw, path = self.password_entry.get(), self.file_path_entry.get()
        if pw and path:
            res = crypto_core.encrypt_file(pw, path)
            if res: messagebox.showinfo("Success", f"File encrypted: {res}")

    def decrypt_file_action(self):
        pw, path = self.password_entry.get(), self.file_path_entry.get()
        if pw and path:
            res = crypto_core.decrypt_file(pw, path)
            if "[HATA]" not in str(res): messagebox.showinfo("Success", f"File decrypted: {res}")
            else: messagebox.showerror("Error", "Decryption failed.")

    def load_note(self):
        sel = self.notes_listbox.curselection()
        if sel:
            self.text_output.delete("1.0", tk.END)
            self.text_output.insert("1.0", db_manager.get_note_content(self.note_ids[sel[0]]))

    def delete_note(self):
        sel = self.notes_listbox.curselection()
        if sel and messagebox.askyesno("Confirm", "Delete this note?"):
            db_manager.delete_note(self.note_ids[sel[0]])
            self.refresh_note_list()

    def refresh_note_list(self):
        self.notes_listbox.delete(0, tk.END)
        self.note_ids = [n[0] for n in db_manager.get_all_notes()]
        for n in db_manager.get_all_notes(): self.notes_listbox.insert(tk.END, n[1])

if __name__ == "__main__":
    SecureApp().mainloop()