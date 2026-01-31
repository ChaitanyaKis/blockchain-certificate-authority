import hashlib
import hmac
import base64
from cryptography.fernet import Fernet

# ---------- HASHING ----------
def sha256_hash(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

# ---------- HMAC AUTH ----------
def generate_hmac(message: str, secret: bytes) -> str:
    return hmac.new(secret, message.encode("utf-8"), hashlib.sha256).hexdigest()

def verify_hmac(message: str, signature: str, secret: bytes) -> bool:
    expected = generate_hmac(message, secret)
    return hmac.compare_digest(expected, signature)

# ---------- SYMMETRIC ENCRYPTION ----------
def get_cipher(master_key: bytes) -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(master_key).digest())
    return Fernet(key)

def encrypt(text: str, cipher: Fernet) -> bytes:
    return cipher.encrypt(text.encode("utf-8"))

def decrypt(token: bytes, cipher: Fernet) -> str:
    return cipher.decrypt(token).decode("utf-8")
