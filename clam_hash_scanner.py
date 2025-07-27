import hashlib

def load_clamav_hashes(hdb_path):
    hashes = set()
    try:
        with open(hdb_path, "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 2:
                    hashes.add(parts[1].lower())  # MD5 hash
    except Exception as e:
        print(f"Hash veritabanı okunamadı: {e}")
    return hashes

def scan_file_with_clam_hashes(file_path, clam_hashes):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            file_hash = hashlib.md5(data).hexdigest().lower()
            return file_hash in clam_hashes
    except Exception as e:
        print(f"Dosya taranamadı: {e}")
        return False
