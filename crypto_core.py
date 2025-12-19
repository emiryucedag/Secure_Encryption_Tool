import logging
import base64
import os
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Loglama Kurulumu 
logging.basicConfig(
    filename='secure_app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

ITERATIONS = 1000000

def get_key(password, salt):
    return PBKDF2(password.encode('utf-8'), salt, dkLen=32, count=ITERATIONS)

def encrypt_text(password, text):
    try:
        salt = get_random_bytes(16)
        key = get_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
        combined = salt + cipher.nonce + tag + ciphertext
        
        # LOG 
        logging.info("Metin şifreleme işlemi başarılı.")
        return base64.b64encode(combined).decode('utf-8')
    except Exception as e:
        logging.error(f"Metin şifreleme hatası: {e}")
        return None

def decrypt_text(password, packaged_data):
    try:
        data = base64.b64decode(packaged_data)
        salt, nonce, tag, ciphertext = data[:16], data[16:32], data[32:48], data[48:]
        key = get_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        result = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
        
        # LOG 
        logging.info("Metin çözme işlemi başarılı.")
        return result
    except Exception:
        logging.warning("Şifre çözme başarısız: Yanlış parola veya bozuk veri.")
        return "[HATA] Parola yanlış veya veri bozulmuş."

def encrypt_file(password, input_path):
    try:
        with open(input_path, 'rb') as f:
            data = f.read()
        salt = get_random_bytes(16)
        key = get_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        output_path = input_path + ".enc"
        with open(output_path, 'wb') as f:
            for x in (salt, cipher.nonce, tag, ciphertext):
                f.write(x)
        logging.info(f"Dosya şifrelendi: {output_path}")
        return output_path
    except Exception as e:
        logging.error(f"Dosya şifreleme hatası: {e}")
        return None

def decrypt_file(password, input_path):
    try:
        with open(input_path, 'rb') as f:
            salt = f.read(16)
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()
        key = get_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        output_path = input_path.replace(".enc", ".dec")
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        logging.info(f"Dosya çözüldü: {output_path}")
        return output_path
    except Exception:
        logging.error("Dosya çözme hatası veya yanlış parola.")
        return "[HATA] Dosya çözülemedi."