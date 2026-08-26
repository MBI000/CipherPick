import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# --- SHA-256 ---
def generate_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# --- AES (Fernet) ---
def generate_aes_key() -> bytes:
    return Fernet.generate_key()

def aes_encrypt(data: bytes, key: bytes) -> bytes:
    try:
        f = Fernet(key)
        return f.encrypt(data)
    except Exception as e:
        raise ValueError(f"Encryption failed: {e}")

def aes_decrypt(token: bytes, key: bytes) -> bytes:
    try:
        f = Fernet(key)
        return f.decrypt(token)
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")

# --- RSA ---
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_private, pem_public

def rsa_encrypt(data: bytes, pem_public: bytes) -> bytes:
    try:
        public_key = serialization.load_pem_public_key(pem_public)
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    except Exception as e:
        raise ValueError(f"RSA Encryption failed: {e}")

def rsa_decrypt(ciphertext: bytes, pem_private: bytes) -> bytes:
    try:
        private_key = serialization.load_pem_private_key(pem_private, password=None)
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
    except Exception as e:
        raise ValueError(f"RSA Decryption failed: {e}")
