import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import sqlite3
import os
import base64

class FileEncryptionApp:
    def __init__(self, master):
        self.master = master
        self.master.title("File Encryption and Decryption")

        self.filename_label = tk.Label(master, text="File:")
        self.filename_label.grid(row=0, column=0, padx=10, pady=10)

        self.filename_entry = tk.Entry(master, state="disabled", width=30)
        self.filename_entry.grid(row=0, column=1, padx=10, pady=10)

        self.browse_button = tk.Button(master, text="Browse", command=self.browse_file)
        self.browse_button.grid(row=0, column=2, padx=10, pady=10)

        self.password_label = tk.Label(master, text="Password:")
        self.password_label.grid(row=1, column=0, padx=10, pady=10)

        self.password_entry = tk.Entry(master, show="*")
        self.password_entry.grid(row=1, column=1, padx=10, pady=10)

        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt_file)
        self.encrypt_button.grid(row=2, column=0, columnspan=2, pady=10)

        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.decrypt_file)
        self.decrypt_button.grid(row=3, column=0, columnspan=2, pady=10)

        # Create database table if not exists
        self.create_database()

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        self.filename_entry.config(state="normal")
        self.filename_entry.delete(0, tk.END)
        self.filename_entry.insert(0, file_path)
        self.filename_entry.config(state="disabled")

    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            salt=salt,
            iterations=100000,
            length=32,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def hash_password(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            salt=salt,
            iterations=100000,
            length=32,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return base64.urlsafe_b64encode(key)

    def create_database(self):
        conn = sqlite3.connect('file_encryption.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS encrypted_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT,
                password_hash TEXT,
                salt TEXT,
                iv TEXT,
                original_extension TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def insert_file_data(self, filename, password, salt, iv, original_extension):
        password_hash = self.hash_password(password, salt)
        conn = sqlite3.connect('file_encryption.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO encrypted_files (filename, password_hash, salt, iv, original_extension) VALUES (?, ?, ?, ?, ?)',
                       (filename, password_hash, salt, iv, original_extension))
        conn.commit()
        conn.close()

    def verify_password(self, password, salt, stored_password_hash):
        hashed_password = self.hash_password(password, salt)
        return hashed_password == stored_password_hash

    def encrypt_file(self):
        file_path = self.filename_entry.get()
        password = self.password_entry.get()

        if not file_path or not password:
            messagebox.showerror("Error", "File path and password cannot be empty.")
            return

        salt = os.urandom(16)
        iv = os.urandom(16)
        key = self.derive_key(password, salt)

        original_extension = os.path.splitext(file_path)[1]

        encrypted_file_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc")])

        if encrypted_file_path:
            with open(file_path, 'rb') as f_in:
                plaintext = f_in.read()

            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()

            self.insert_file_data(encrypted_file_path, password, salt, iv, original_extension)
            with open(encrypted_file_path, 'wb') as f_out:
                f_out.write(ciphertext)

            messagebox.showinfo("Success", "File encrypted successfully.")
        else:
            messagebox.showwarning("Warning", "Encryption canceled.")

    def decrypt_file(self):
        file_path = self.filename_entry.get()
        password = self.password_entry.get()

        if not file_path or not password:
            messagebox.showerror("Error", "File path and password cannot be empty.")
            return

        stored_password_hash, salt, iv, original_extension = self.retrieve_file_data(file_path)

        if stored_password_hash and iv:
            if self.verify_password(password, salt, stored_password_hash):
                key = self.derive_key(password, salt)  # Initialize the key variable

                decrypted_file_path = filedialog.asksaveasfilename(defaultextension=original_extension, filetypes=[("All Files", "*.*")])

                if decrypted_file_path:
                    with open(file_path, 'rb') as f_in:
                        ciphertext = f_in.read()

                    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                    decryptor = cipher.decryptor()
                    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

                    with open(decrypted_file_path, 'wb') as f_out:
                        f_out.write(plaintext)

                    messagebox.showinfo("Success", "File decrypted successfully.")

                    # Deletes the .enc file after successful decryption
                    os.remove(file_path)
                else:
                    messagebox.showwarning("Warning", "Decryption canceled.")
            else:
                messagebox.showerror("Error", "Incorrect password. Decryption failed.")
        else:
            messagebox.showerror("Error", "Failed to retrieve password hash, IV, and original extension for decryption.")

    def retrieve_file_data(self, filename):
        conn = sqlite3.connect('file_encryption.db')
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash, salt, iv, original_extension FROM encrypted_files WHERE filename=?', (filename,))
        result = cursor.fetchone()
        conn.close()

        if result:
            return result
        else:
            return None

if __name__ == "__main__":
    app = tk.Tk()
    file_app = FileEncryptionApp(app)
    app.mainloop()
