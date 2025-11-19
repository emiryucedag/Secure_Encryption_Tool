import logging
import base64
import os  # Salt için 'get_random_bytes' yerine 'os.urandom' da kullanılabilir
import filecmp # BUNU EKLE

# Kripto kütüphanelerini import edelim
from Crypto.Protocol.KDF import PBKDF2  # Paroladan anahtar türetmek için [cite: 17, 30]
from Crypto.Cipher import AES           # AES şifreleme algoritması için [cite: 18]
from Crypto.Random import get_random_bytes # Güvenli rastgele veri üretmek için

# --- YENİ ÖZELLİK: LOGLAMA KURULUMU  ---
# Proje klasöründe 'secure_app.log' adında bir dosya oluşturacak.
logging.basicConfig(
    filename='secure_app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logging.info("Uygulama başlatıldı ve loglama yapılandırıldı.")
# -------------------------------------------------

def get_key_from_password(password_str, salt):
    """
    Kullanıcının girdiği paroladan (string) ve bir salt (bytes) kullanarak 
    güvenli bir 32-byte (256-bit) anahtar türetir. [cite: 37]
    """
    try:
        logging.info("Anahtar türetme işlemi başlıyor...")
        password_bytes = password_str.encode('utf-8')
        
        # PBKDF2 fonksiyonunu 1 milyon iterasyon ile kullanıyoruz [cite: 35]
        key = PBKDF2(password_bytes, salt, dkLen=32, count=1000000)
        
        logging.info("Anahtar başarıyla türetildi.")
        return key
    except Exception as e:
        logging.error(f"Anahtar türetme sırasında hata: {e}")
        return None

def encrypt_text(password, text_to_encrypt):
    """
    Verilen metni, parolayı kullanarak AES-GCM ile şifreler.
    Çıktıyı Base64 formatında paketler. [cite: 20]
    """
    try:
        logging.info("Metin şifreleme işlemi başlatıldı.")
        
        # 1. Güvenli bir Salt oluştur (16 byte) [cite: 33]
        salt = get_random_bytes(16)
        
        # 2. Paroladan anahtarı türet
        key = get_key_from_password(password, salt)
        if key is None:
            raise Exception("Anahtar türetilemedi.")

        # 3. AES-GCM şifreleyici nesnesini oluştur [cite: 19]
        # Her şifrelemede yeni bir nonce (tek seferlik sayı) üretilir [cite: 45]
        cipher = AES.new(key, AES.MODE_GCM)
        
        # 4. Veriyi şifrele ve bütünlük etiketini (tag) al [cite: 47, 48]
        text_bytes = text_to_encrypt.encode('utf-8')
        ciphertext, tag = cipher.encrypt_and_digest(text_bytes)
        
        # 5. Tüm parçaları Base64 ile paketle [cite: 56]
        # Format: salt:nonce:tag:ciphertext
        encoded_parts = [
            base64.b64encode(salt).decode('utf-8'),
            base64.b64encode(cipher.nonce).decode('utf-8'),
            base64.b64encode(tag).decode('utf-8'),
            base64.b64encode(ciphertext).decode('utf-8')
        ]
        
        packaged_data = ":".join(encoded_parts)
        logging.info("Metin başarıyla şifrelendi ve paketlendi.")
        return packaged_data
        
    except Exception as e:
        logging.error(f"Metin şifreleme sırasında hata: {e}")
        return None

def decrypt_text(password, packaged_data):
    """
    Verilen Base64 paketini ve parolayı kullanarak metni çözer.
    """
    try:
        logging.info("Metin şifre çözme işlemi başlatıldı.")
        
        # 1. Paketi Base64'ten çöz ve parçalara ayır
        parts = packaged_data.split(":")
        salt = base64.b64decode(parts[0])
        nonce = base64.b64decode(parts[1])
        tag = base64.b64decode(parts[2])
        ciphertext = base64.b64decode(parts[3])
        
        # 2. Anahtarı, gelen salt ve parola ile YENİDEN türet
        key = get_key_from_password(password, salt)
        if key is None:
            raise Exception("Anahtar türetilemedi (çözme).")
            
        # 3. Şifre çözücü nesneyi, gelen nonce ile oluştur
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # 4. Veriyi çöz ve BÜTÜNLÜĞÜNÜ KONTROL ET (verify) [cite: 49, 50]
        # Eğer parola yanlışsa veya veri bozulmuşsa, bu adım "ValueError" fırlatır.
        decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        
        decrypted_text = decrypted_bytes.decode('utf-8')
        logging.info("Metin başarıyla çözüldü ve doğrulandı.")
        return decrypted_text

    except (ValueError, KeyError):
        # Bu hata, parolanın yanlış olduğunu VEYA verinin bozulduğunu gösterir [cite: 51]
        logging.warning("Şifre çözme BAŞARISIZ! Parola yanlış veya veri bozuk.")
        return "[HATA] Parola yanlış veya veri bozulmuş."
    except Exception as e:
        logging.error(f"Metin şifre çözme sırasında genel hata: {e}")
        return f"[HATA] Beklenmedik bir sorun oluştu: {e}"
    
# ... (logging, get_key_from_password, encrypt_text, decrypt_text fonksiyonları burada)

def encrypt_file(password, input_file_path):
    """
    Bir dosyayı okur, AES-GCM ile şifreler ve şifreli paketi 
    'orijinal_dosya_adı.enc' olarak kaydeder.
    """
    try:
        logging.info(f"Dosya şifreleme işlemi başlatıldı: {input_file_path}")
        
        # 1. Dosyayı binary modda oku ('rb')
        with open(input_file_path, 'rb') as f:
            file_data_bytes = f.read()

        # 2. Güvenli bir Salt oluştur
        salt = get_random_bytes(16)
        
        # 3. Paroladan anahtarı türet
        key = get_key_from_password(password, salt)
        if key is None:
            raise Exception("Anahtar türetilemedi (dosya).")

        # 4. AES-GCM şifreleyici nesnesini oluştur
        cipher = AES.new(key, AES.MODE_GCM)
        
        # 5. Dosya verisini şifrele (veri zaten bytes formatında)
        ciphertext, tag = cipher.encrypt_and_digest(file_data_bytes)
        
        # 6. Tüm parçaları Base64 ile paketle
        encoded_parts = [
            base64.b64encode(salt).decode('utf-8'),
            base64.b64encode(cipher.nonce).decode('utf-8'),
            base64.b64encode(tag).decode('utf-8'),
            base64.b64encode(ciphertext).decode('utf-8')
        ]
        packaged_data = ":".join(encoded_parts)
        
        # 7. Şifreli paketi yeni bir dosyaya yaz (.enc uzantılı)
        output_file_path = f"{input_file_path}.enc"
        with open(output_file_path, 'w') as f:
            f.write(packaged_data)
            
        logging.info(f"Dosya başarıyla şifrelendi ve kaydedildi: {output_file_path}")
        return output_file_path
        
    except FileNotFoundError:
        logging.error(f"Dosya bulunamadı: {input_file_path}")
        return None
    except Exception as e:
        logging.error(f"Dosya şifreleme sırasında hata: {e}")
        return None

def decrypt_file(password, input_file_path):
    """
    Bir '.enc' dosyasını okur, parolayı kullanarak çözer ve 
    'orijinal_dosya_adı.dec' olarak (çözülmüş) kaydeder.
    """
    try:
        logging.info(f"Dosya şifre çözme işlemi başlatıldı: {input_file_path}")
        
        # 1. Şifreli Base64 paketini dosyadan oku ('r')
        with open(input_file_path, 'r') as f:
            packaged_data = f.read()

        # 2. Paketi Base64'ten çöz ve parçalara ayır
        parts = packaged_data.split(":")
        salt = base64.b64decode(parts[0])
        nonce = base64.b64decode(parts[1])
        tag = base64.b64decode(parts[2])
        ciphertext = base64.b64decode(parts[3])
        
        # 3. Anahtarı yeniden türet
        key = get_key_from_password(password, salt)
        if key is None:
            raise Exception("Anahtar türetilemedi (dosya çözme).")
            
        # 4. Şifre çözücü nesneyi oluştur
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # 5. Veriyi çöz ve doğrula (sonuç 'bytes' olacaktır)
        decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        
        # 6. Çözülmüş 'bytes' verisini yeni bir dosyaya 'wb' (write binary) modunda yaz
        # .enc uzantısını kaldırıp .dec (decrypted) ekleyelim
        output_file_path = input_file_path.replace(".enc", ".dec")
        with open(output_file_path, 'wb') as f:
            f.write(decrypted_bytes)
            
        logging.info(f"Dosya başarıyla çözüldü ve kaydedildi: {output_file_path}")
        return output_file_path

    except (ValueError, KeyError):
        logging.warning(f"Dosya çözme BAŞARISIZ! Parola yanlış veya dosya bozuk: {input_file_path}")
        return "[HATA] Parola yanlış veya dosya bozulmuş."
    except FileNotFoundError:
        logging.error(f"Dosya bulunamadı: {input_file_path}")
        return "[HATA] Şifreli dosya bulunamadı."
    except Exception as e:
        logging.error(f"Dosya şifre çözme sırasında genel hata: {e}")
        return f"[HATA] Beklenmedik bir sorun oluştu: {e}"


# --- KODUMUZU TEST ETMEK İÇİN ANA ÇALIŞTIRMA BLOĞU ---
if __name__ == "__main__":
    
    print("--- Kripto Çekirdeği Testi Başlatıldı ---")
    
    parola = "CokGuvEnli123!"
    metin = "Bu, ara rapor için şifrelenecek gizli bir mesajdır."
    
    # --- TEST 1: BAŞARILI METİN ŞİFRELEME VE ÇÖZME ---
    print("\n[Test 1] Başarılı metin şifreleme/çözme testi...")
    encrypted_data = encrypt_text(parola, metin)
    
    if encrypted_data:
        print(f"Orijinal Metin: {metin}")
        # print(f"Şifrelenmiş Paket: {encrypted_data}") # Çok uzun, gizleyebiliriz
        
        decrypted_text = decrypt_text(parola, encrypted_data)
        print(f"Çözülmüş Metin: {decrypted_text}")
        
        assert metin == decrypted_text
        print("Test 1 BAŞARILI!")
    else:
        print("Test 1 BAŞARISIZ! (Şifreleme hatası)")

    # --- TEST 2: YANLIŞ PAROLA (METİN) TESTİ ---
    print("\n[Test 2] Yanlış parola (metin) testi...")
    yanlis_parola = "SifreyiUnuttum:("
    
    decrypted_text_fail = decrypt_text(yanlis_parola, encrypted_data)
    print(f"Yanlış Parola ile Çözme Denemesi Sonucu: {decrypted_text_fail}")
    assert "HATA" in decrypted_text_fail
    print("Test 2 BAŞARILI! (Hata doğru şekilde yakalandı)")
    
    # --- YENİ TEST 3: BAŞARILI DOSYA ŞİFRELEME VE ÇÖZME ---
    print("\n[Test 3] Başarılı dosya şifreleme/çözme testi...")
    
    # Test için geçici bir dosya oluşturalım
    test_file_path = "test_dosyasi.txt"
    test_file_content = "Bu çok gizli bir dosyadır. Kimse okumamalı."
    with open(test_file_path, "w") as f:
        f.write(test_file_content)
    
    # Dosyayı şifrele
    encrypted_file = encrypt_file(parola, test_file_path)
    if encrypted_file:
        print(f"Orijinal dosya '{test_file_path}' şifrelendi -> '{encrypted_file}'")
        
        # Dosyayı çöz
        decrypted_file = decrypt_file(parola, encrypted_file)
        if decrypted_file:
            print(f"Şifreli dosya '{encrypted_file}' çözüldü -> '{decrypted_file}'")
            
            # Orijinal dosya ile çözülen dosyanın içeriği aynı mı?
            assert filecmp.cmp(test_file_path, decrypted_file)
            print("Test 3 BAŞARILI! (Dosya içerikleri eşleşti)")
        else:
            print("Test 3 BAŞARISIZ! (Dosya çözme hatası)")
    else:
        print("Test 3 BAŞARISIZ! (Dosya şifreleme hatası)")
        
    # --- YENİ TEST 4: YANLIŞ PAROLA (DOSYA) TESTİ ---
    print("\n[Test 4] Yanlış parola (dosya) testi...")
    decrypted_file_fail = decrypt_file(yanlis_parola, encrypted_file)
    print(f"Yanlış Parola ile Dosya Çözme Denemesi Sonucu: {decrypted_file_fail}")
    assert "HATA" in decrypted_file_fail
    print("Test 4 BAŞARILI! (Hata doğru şekilde yakalandı)")


    # --- Test sonrası temizlik ---
    print("\nTest dosyaları temizleniyor...")
    try:
        os.remove(test_file_path)
        os.remove(encrypted_file)
        os.remove(decrypted_file)
        print("Temizlik tamamlandı.")
    except Exception as e:
        print(f"Temizlik sırasında hata (dosyalar zaten silinmiş olabilir): {e}")
    
    print("\n--- Testler Tamamlandı ---")
    print("Log dosyasını kontrol et: 'secure_app.log'")
    
    print("--- Kripto Çekirdeği Testi Başlatıldı ---")
    
    parola = "CokGuvEnli123!"
    metin = "Bu, ara rapor için şifrelenecek gizli bir mesajdır."
    
    # --- TEST 1: BAŞARILI ŞİFRELEME VE ÇÖZME ---
    print("\n[Test 1] Başarılı şifreleme/çözme testi...")
    encrypted_data = encrypt_text(parola, metin)
    
    if encrypted_data:
        print(f"Orijinal Metin: {metin}")
        print(f"Şifrelenmiş Paket: {encrypted_data}")
        
        decrypted_text = decrypt_text(parola, encrypted_data)
        print(f"Çözülmüş Metin: {decrypted_text}")
        
        assert metin == decrypted_text # Kodun doğru çalıştığını kontrol et
        print("Test 1 BAŞARILI!")
    else:
        print("Test 1 BAŞARISIZ! (Şifreleme hatası)")

    # --- TEST 2: YANLIŞ PAROLA TESTİ ---
    print("\n[Test 2] Yanlış parola testi...")
    yanlis_parola = "SifreyiUnuttum:("
    
    decrypted_text_fail = decrypt_text(yanlis_parola, encrypted_data)
    print(f"Yanlış Parola ile Çözme Denemesi Sonucu: {decrypted_text_fail}")
    assert "HATA" in decrypted_text_fail
    print("Test 2 BAŞARILI! (Hata doğru şekilde yakalandı)")
    
    print("\n--- Testler Tamamlandı ---")
    print("\nLog dosyasını kontrol et: 'secure_app.log'")