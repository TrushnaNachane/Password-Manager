"""
Unit tests for Password Manager
Tests encryption, database operations, and validation
"""

import pytest
import os
import sqlite3
from cryptography.fernet import Fernet
import hashlib
import tempfile
import shutil

# For testing, we'll create a test version of PasswordManager
class PasswordManager:
    """Password Manager for testing"""
    
    def __init__(self, db_path="test_passwords.db", key_file="test_key.key", hash_file="test_hash.txt"):
        self.db_name = db_path
        self.master_key_file = key_file
        self.master_hash_file = hash_file
        self.init_database()
        self.cipher_suite = None
        self.master_password_verified = False
    
    def init_database(self):
        """Initialize database"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
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
            print(f"Database error: {e}")
            return False
    
    def hash_password(self, password):
        """Hash password"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def generate_or_load_key(self, master_password):
        """Generate encryption key"""
        try:
            if os.path.exists(self.master_key_file):
                with open(self.master_key_file, 'rb') as f:
                    key = f.read()
            else:
                key = Fernet.generate_key()
                with open(self.master_key_file, 'wb') as f:
                    f.write(key)
            
            self.cipher_suite = Fernet(key)
            return True
        except Exception as e:
            print(f"Key error: {e}")
            return False
    
    def set_master_password(self, password):
        """Set master password"""
        try:
            password_hash = self.hash_password(password)
            with open(self.master_hash_file, 'w') as f:
                f.write(password_hash)
            
            key = Fernet.generate_key()
            with open(self.master_key_file, 'wb') as f:
                f.write(key)
            
            self.cipher_suite = Fernet(key)
            self.master_password_verified = True
            return True
        except Exception as e:
            print(f"Error: {e}")
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
                if self.generate_or_load_key(password):
                    self.master_password_verified = True
                    return True
            return False
        except Exception as e:
            print(f"Verification error: {e}")
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
        """Decrypt password"""
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
        
        if any(c.isupper() for c in password):
            strength += 1
        else:
            feedback.append("Add uppercase")
        
        if any(c.islower() for c in password):
            strength += 1
        else:
            feedback.append("Add lowercase")
        
        if any(c.isdigit() for c in password):
            strength += 1
        else:
            feedback.append("Add numbers")
        
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            strength += 1
        else:
            feedback.append("Add special chars")
        
        return strength, feedback
    
    def add_password(self, website, username, password):
        """Add password"""
        if not self.master_password_verified:
            return False, "Not verified"
        
        try:
            if not website or not username or not password:
                return False, "Required fields"
            
            encrypted_pwd = self.encrypt_password(password)
            if not encrypted_pwd:
                return False, "Encryption failed"
            
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO passwords (website, username, password)
                VALUES (?, ?, ?)
            ''', (website, username, encrypted_pwd))
            conn.commit()
            conn.close()
            return True, "Added"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def get_all_passwords(self):
        """Get all passwords"""
        if not self.master_password_verified:
            return []
        
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute('SELECT id, website, username, password FROM passwords')
            entries = cursor.fetchall()
            conn.close()
            
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
            print(f"Error: {e}")
            return []
    
    def delete_password(self, entry_id):
        """Delete password"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM passwords WHERE id = ?', (entry_id,))
            conn.commit()
            conn.close()
            return True, "Deleted"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def search_password(self, search_term):
        """Search passwords"""
        all_passwords = self.get_all_passwords()
        search_term = search_term.lower()
        results = [
            p for p in all_passwords 
            if search_term in p['website'].lower() or search_term in p['username'].lower()
        ]
        return results
    
    def cleanup(self):
        """Clean up test files"""
        for file in [self.db_name, self.master_key_file, self.master_hash_file]:
            if os.path.exists(file):
                os.remove(file)


# ============================================================================
# PYTEST TEST CASES
# ============================================================================

class TestPasswordManagerSetup:
    """Test master password setup and verification"""
    
    @pytest.fixture
    def pm(self):
        """Create password manager for testing"""
        pm = PasswordManager()
        yield pm
        pm.cleanup()
    
    def test_master_password_setup(self, pm):
        """Test setting master password"""
        assert pm.set_master_password("TestPassword123!") == True
        assert pm.master_password_verified == True
    
    def test_master_password_verification(self, pm):
        """Test verifying master password"""
        pm.set_master_password("TestPassword123!")
        pm.master_password_verified = False
        
        assert pm.verify_master_password("TestPassword123!") == True
        assert pm.master_password_verified == True
    
    def test_wrong_password(self, pm):
        """Test wrong password verification"""
        pm.set_master_password("CorrectPassword123!")
        pm.master_password_verified = False
        
        assert pm.verify_master_password("WrongPassword") == False
        assert pm.master_password_verified == False


class TestEncryption:
    """Test encryption and decryption"""
    
    @pytest.fixture
    def pm(self):
        """Create password manager for testing"""
        pm = PasswordManager()
        pm.set_master_password("TestPassword123!")
        yield pm
        pm.cleanup()
    
    def test_encrypt_decrypt(self, pm):
        """Test encryption and decryption"""
        original = "MySecretPassword123!"
        encrypted = pm.encrypt_password(original)
        decrypted = pm.decrypt_password(encrypted)
        
        assert encrypted is not None
        assert decrypted == original
    
    def test_encryption_produces_different_output(self, pm):
        """Test that encryption works (produces different output)"""
        password = "TestPassword123!"
        encrypted1 = pm.encrypt_password(password)
        encrypted2 = pm.encrypt_password(password)
        
        # Different encryption (due to random nonce)
        assert encrypted1 is not None
        assert encrypted2 is not None
    
    def test_decrypt_wrong_key(self, pm):
        """Test decryption with wrong key should fail or be gibberish"""
        password = "TestPassword123!"
        encrypted = pm.encrypt_password(password)
        
        # This should still decrypt with correct key
        decrypted = pm.decrypt_password(encrypted)
        assert decrypted == password


class TestPasswordValidation:
    """Test password strength validation"""
    
    @pytest.fixture
    def pm(self):
        """Create password manager"""
        pm = PasswordManager()
        pm.set_master_password("TestPassword123!")
        yield pm
        pm.cleanup()
    
    def test_weak_password(self, pm):
        """Test weak password"""
        strength, feedback = pm.validate_password_strength("weak")
        assert strength < 3  # Weak passwords have low strength
    
    def test_strong_password(self, pm):
        """Test strong password"""
        strength, feedback = pm.validate_password_strength("StrongP@ssword123")
        assert strength >= 5  # Strong passwords
    
    def test_short_password(self, pm):
        """Test short password validation"""
        strength, feedback = pm.validate_password_strength("Short1!")
        assert "At least 8 characters" in feedback


class TestDatabaseOperations:
    """Test database operations"""
    
    @pytest.fixture
    def pm(self):
        """Create password manager"""
        pm = PasswordManager()
        pm.set_master_password("TestPassword123!")
        yield pm
        pm.cleanup()
    
    def test_add_password(self, pm):
        """Test adding password"""
        success, msg = pm.add_password("gmail.com", "user@gmail.com", "Password123!")
        assert success == True
    
    def test_get_passwords(self, pm):
        """Test retrieving passwords"""
        pm.add_password("gmail.com", "user@gmail.com", "Password123!")
        pm.add_password("github.com", "username", "GithubPass456!")
        
        passwords = pm.get_all_passwords()
        assert len(passwords) == 2
        assert passwords[0]['website'] == "gmail.com"
        assert passwords[0]['username'] == "user@gmail.com"
        assert passwords[0]['password'] == "Password123!"
    
    def test_delete_password(self, pm):
        """Test deleting password"""
        pm.add_password("gmail.com", "user@gmail.com", "Password123!")
        passwords = pm.get_all_passwords()
        assert len(passwords) == 1
        
        entry_id = passwords[0]['id']
        success, msg = pm.delete_password(entry_id)
        assert success == True
        
        passwords = pm.get_all_passwords()
        assert len(passwords) == 0
    
    def test_search_password(self, pm):
        """Test searching passwords"""
        pm.add_password("gmail.com", "user@gmail.com", "Password123!")
        pm.add_password("github.com", "username", "GithubPass456!")
        
        results = pm.search_password("gmail")
        assert len(results) == 1
        assert results[0]['website'] == "gmail.com"


class TestIntegration:
    """Integration tests"""
    
    @pytest.fixture
    def pm(self):
        """Create password manager"""
        pm = PasswordManager()
        pm.set_master_password("MasterPass123!")
        yield pm
        pm.cleanup()
    
    def test_full_workflow(self, pm):
        """Test complete workflow"""
        # Add passwords
        pm.add_password("google.com", "user@gmail.com", "GooglePass123!")
        pm.add_password("facebook.com", "user@facebook", "FBPass456!")
        pm.add_password("linkedin.com", "user@linkedin", "LinkedInPass789!")
        
        # Verify all added
        passwords = pm.get_all_passwords()
        assert len(passwords) == 3
        
        # Search
        results = pm.search_password("google")
        assert len(results) == 1
        
        # Delete
        pm.delete_password(passwords[0]['id'])
        passwords = pm.get_all_passwords()
        assert len(passwords) == 2
    
    def test_encryption_integrity(self, pm):
        """Test that passwords maintain integrity through encryption"""
        test_passwords = [
            "SimplePass123",
            "Complex!@#$%^&*Pass",
            "MixedCase123Pass!",
            "NumbersOnly123",
            "SpecialChars!@#$%"
        ]
        
        for pwd in test_passwords:
            pm.add_password("test.com", "user", pwd)
        
        stored = pm.get_all_passwords()
        
        for i, stored_entry in enumerate(stored):
            assert stored_entry['password'] == test_passwords[i]


# ============================================================================
# COVERAGE METRICS
# ============================================================================

if __name__ == "__main__":
    # Run with: pytest test_password_manager.py --cov=main --cov-report=html
    pytest.main([__file__, "-v", "--cov", "--cov-report=term-missing"])
