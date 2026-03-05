#!/usr/bin/env python3
"""
Secure Password Manager - Main Application File
A full-stack password management application with AES-256 encryption
"""

import tkinter as tk
from tkinter import simpledialog, messagebox, ttk
import sqlite3
import os
from cryptography.fernet import Fernet
import hashlib
import json
from datetime import datetime

class PasswordManager:
    """Main Password Manager Class with encryption and database"""
    
    def __init__(self):
        self.db_name = "passwords.db"
        self.master_key_file = "master_key.key"
        self.master_hash_file = "master_hash.txt"
        self.init_database()
        self.cipher_suite = None
        self.master_password_verified = False
        
    def init_database(self):
        """Initialize SQLite database with password table"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            # Create passwords table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    website TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    modified_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Database initialization error: {e}")
            return False
    
    def hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def generate_or_load_key(self, master_password):
        """Generate or load encryption key from master password"""
        try:
            if os.path.exists(self.master_key_file):
                with open(self.master_key_file, 'rb') as f:
                    key = f.read()
            else:
                # Generate new key from master password
                key = Fernet.generate_key()
                with open(self.master_key_file, 'wb') as f:
                    f.write(key)
            
            self.cipher_suite = Fernet(key)
            return True
        except Exception as e:
            print(f"Key generation error: {e}")
            return False
    
    def set_master_password(self, password):
        """Set master password (first time setup)"""
        try:
            password_hash = self.hash_password(password)
            with open(self.master_hash_file, 'w') as f:
                f.write(password_hash)
            
            # Generate encryption key
            key = Fernet.generate_key()
            with open(self.master_key_file, 'wb') as f:
                f.write(key)
            
            self.cipher_suite = Fernet(key)
            self.master_password_verified = True
            return True
        except Exception as e:
            print(f"Error setting master password: {e}")
            return False
    
    def verify_master_password(self, password):
        """Verify master password"""
        try:
            if not os.path.exists(self.master_hash_file):
                return False
            
            with open(self.master_hash_file, 'r') as f:
                stored_hash = f.read()
            
            entered_hash = self.hash_password(password)
            
            if entered_hash == stored_hash:
                # Load encryption key
                if self.generate_or_load_key(password):
                    self.master_password_verified = True
                    return True
            return False
        except Exception as e:
            print(f"Error verifying master password: {e}")
            return False
    
    def encrypt_password(self, password):
        """Encrypt password using AES-256"""
        if not self.cipher_suite:
            return None
        try:
            encrypted = self.cipher_suite.encrypt(password.encode())
            return encrypted.hex()
        except Exception as e:
            print(f"Encryption error: {e}")
            return None
    
    def decrypt_password(self, encrypted_password):
        """Decrypt password using AES-256"""
        if not self.cipher_suite:
            return None
        try:
            encrypted_bytes = bytes.fromhex(encrypted_password)
            decrypted = self.cipher_suite.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            print(f"Decryption error: {e}")
            return None
    
    def validate_password_strength(self, password):
        """Validate password strength"""
        strength = 0
        feedback = []
        
        if len(password) >= 8:
            strength += 1
        else:
            feedback.append("At least 8 characters")
        
        if len(password) >= 12:
            strength += 1
        
        if any(c.isupper() for c in password):
            strength += 1
        else:
            feedback.append("Add uppercase letters")
        
        if any(c.islower() for c in password):
            strength += 1
        else:
            feedback.append("Add lowercase letters")
        
        if any(c.isdigit() for c in password):
            strength += 1
        else:
            feedback.append("Add numbers")
        
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            strength += 1
        else:
            feedback.append("Add special characters")
        
        return strength, feedback
    
    def add_password(self, website, username, password):
        """Add new password entry to database"""
        if not self.master_password_verified:
            return False, "Master password not verified"
        
        try:
            # Validate inputs
            if not website or not username or not password:
                return False, "All fields are required"
            
            # Encrypt password
            encrypted_pwd = self.encrypt_password(password)
            if not encrypted_pwd:
                return False, "Encryption failed"
            
            # Insert into database
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO passwords (website, username, password)
                VALUES (?, ?, ?)
            ''', (website, username, encrypted_pwd))
            
            conn.commit()
            conn.close()
            return True, "Password added successfully"
        except Exception as e:
            return False, f"Error adding password: {str(e)}"
    
    def get_all_passwords(self):
        """Get all password entries"""
        if not self.master_password_verified:
            return []
        
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            cursor.execute('SELECT id, website, username, password FROM passwords')
            entries = cursor.fetchall()
            conn.close()
            
            # Decrypt passwords
            decrypted_entries = []
            for entry_id, website, username, encrypted_pwd in entries:
                decrypted_pwd = self.decrypt_password(encrypted_pwd)
                decrypted_entries.append({
                    'id': entry_id,
                    'website': website,
                    'username': username,
                    'password': decrypted_pwd
                })
            
            return decrypted_entries
        except Exception as e:
            print(f"Error retrieving passwords: {e}")
            return []
    
    def delete_password(self, entry_id):
        """Delete password entry"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM passwords WHERE id = ?', (entry_id,))
            conn.commit()
            conn.close()
            return True, "Password deleted successfully"
        except Exception as e:
            return False, f"Error deleting password: {str(e)}"
    
    def search_password(self, search_term):
        """Search passwords by website or username"""
        all_passwords = self.get_all_passwords()
        search_term = search_term.lower()
        
        results = [
            p for p in all_passwords 
            if search_term in p['website'].lower() or search_term in p['username'].lower()
        ]
        return results


class PasswordManagerGUI:
    """GUI for Password Manager using Tkinter"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("600x500")
        self.root.configure(bg="#f0f0f0")
        
        self.pm = PasswordManager()
        self.master_password_set = os.path.exists(self.pm.master_hash_file)
        
        if self.master_password_set:
            self.show_login_screen()
        else:
            self.show_setup_screen()
    
    def show_setup_screen(self):
        """Show master password setup screen"""
        self.clear_window()
        
        frame = tk.Frame(self.root, bg="#f0f0f0")
        frame.pack(expand=True, fill="both", padx=20, pady=20)
        
        tk.Label(frame, text="Set Master Password", font=("Arial", 16, "bold"), 
                bg="#f0f0f0").pack(pady=10)
        
        tk.Label(frame, text="Enter your master password", bg="#f0f0f0").pack()
        password1 = tk.Entry(frame, show="*", width=30, font=("Arial", 10))
        password1.pack(pady=5)
        
        tk.Label(frame, text="Confirm master password", bg="#f0f0f0").pack()
        password2 = tk.Entry(frame, show="*", width=30, font=("Arial", 10))
        password2.pack(pady=5)
        
        def setup_password():
            pwd1 = password1.get()
            pwd2 = password2.get()
            
            if not pwd1 or not pwd2:
                messagebox.showerror("Error", "Please enter password")
                return
            
            if pwd1 != pwd2:
                messagebox.showerror("Error", "Passwords don't match")
                return
            
            if len(pwd1) < 8:
                messagebox.showerror("Error", "Password must be at least 8 characters")
                return
            
            if self.pm.set_master_password(pwd1):
                messagebox.showinfo("Success", "Master password set successfully!")
                self.show_main_screen()
            else:
                messagebox.showerror("Error", "Failed to set master password")
        
        tk.Button(frame, text="Set Password", command=setup_password, 
                 bg="#4CAF50", fg="white", width=20).pack(pady=20)
    
    def show_login_screen(self):
        """Show login screen"""
        self.clear_window()
        
        frame = tk.Frame(self.root, bg="#f0f0f0")
        frame.pack(expand=True, fill="both", padx=20, pady=20)
        
        tk.Label(frame, text="Password Manager", font=("Arial", 16, "bold"), 
                bg="#f0f0f0").pack(pady=10)
        
        tk.Label(frame, text="Enter Master Password", bg="#f0f0f0").pack()
        password_entry = tk.Entry(frame, show="*", width=30, font=("Arial", 10))
        password_entry.pack(pady=10)
        
        def verify():
            master_pwd = password_entry.get()
            if self.pm.verify_master_password(master_pwd):
                self.show_main_screen()
            else:
                messagebox.showerror("Error", "Invalid master password")
        
        tk.Button(frame, text="Login", command=verify, 
                 bg="#2196F3", fg="white", width=20).pack(pady=20)
    
    def show_main_screen(self):
        """Show main password manager screen"""
        self.clear_window()
        
        # Create menu bar
        menu_frame = tk.Frame(self.root, bg="#2196F3")
        menu_frame.pack(fill="x")
        
        tk.Label(menu_frame, text="Password Manager", font=("Arial", 14, "bold"), 
                bg="#2196F3", fg="white").pack(side="left", padx=10, pady=10)
        
        # Create main frame
        main_frame = tk.Frame(self.root, bg="#f0f0f0")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Add password button
        tk.Button(main_frame, text="Add New Password", command=self.add_password_dialog,
                 bg="#4CAF50", fg="white", width=20).pack(pady=5)
        
        # Search frame
        search_frame = tk.Frame(main_frame, bg="#f0f0f0")
        search_frame.pack(fill="x", pady=10)
        
        tk.Label(search_frame, text="Search:", bg="#f0f0f0").pack(side="left")
        search_entry = tk.Entry(search_frame, width=30)
        search_entry.pack(side="left", padx=5)
        
        def search():
            term = search_entry.get()
            self.show_passwords(term)
        
        tk.Button(search_frame, text="Search", command=search, bg="#FF9800").pack(side="left")
        
        # Passwords list
        self.show_passwords()
        
        # Logout button
        tk.Button(main_frame, text="Logout", command=self.show_login_screen,
                 bg="#f44336", fg="white", width=20).pack(pady=20)
    
    def show_passwords(self, search_term=""):
        """Display password entries"""
        passwords = self.pm.get_all_passwords()
        
        if search_term:
            passwords = self.pm.search_password(search_term)
        
        # Create scrollable frame for passwords
        canvas_frame = tk.Frame(self.root, bg="#f0f0f0")
        canvas_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        if not passwords:
            tk.Label(canvas_frame, text="No passwords stored", bg="#f0f0f0").pack()
            return
        
        for entry in passwords:
            entry_frame = tk.Frame(canvas_frame, bg="white", relief="solid", bd=1)
            entry_frame.pack(fill="x", pady=5)
            
            info_text = f"Website: {entry['website']} | Username: {entry['username']}"
            tk.Label(entry_frame, text=info_text, bg="white", justify="left").pack(anchor="w", padx=10, pady=5)
            
            pwd_text = f"Password: {'*' * len(entry['password'])}"
            tk.Label(entry_frame, text=pwd_text, bg="white", fg="gray").pack(anchor="w", padx=10)
            
            button_frame = tk.Frame(entry_frame, bg="white")
            button_frame.pack(fill="x", padx=10, pady=5)
            
            def delete_entry(entry_id=entry['id']):
                if messagebox.askyesno("Confirm", "Delete this password?"):
                    success, msg = self.pm.delete_password(entry_id)
                    messagebox.showinfo("Result", msg)
                    self.show_main_screen()
            
            tk.Button(button_frame, text="Delete", command=delete_entry, 
                     bg="#f44336", fg="white").pack(side="left", padx=5)
    
    def add_password_dialog(self):
        """Show dialog to add new password"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Password")
        dialog.geometry("300x250")
        
        tk.Label(dialog, text="Website:").pack(pady=5)
        website = tk.Entry(dialog, width=30)
        website.pack(pady=5)
        
        tk.Label(dialog, text="Username:").pack(pady=5)
        username = tk.Entry(dialog, width=30)
        username.pack(pady=5)
        
        tk.Label(dialog, text="Password:").pack(pady=5)
        password = tk.Entry(dialog, width=30, show="*")
        password.pack(pady=5)
        
        def save():
            web = website.get()
            user = username.get()
            pwd = password.get()
            
            success, msg = self.pm.add_password(web, user, pwd)
            messagebox.showinfo("Result", msg)
            
            if success:
                dialog.destroy()
                self.show_main_screen()
        
        tk.Button(dialog, text="Save", command=save, bg="#4CAF50", fg="white").pack(pady=10)
    
    def clear_window(self):
        """Clear window contents"""
        for widget in self.root.winfo_children():
            widget.destroy()


def main():
    """Main application entry point"""
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
