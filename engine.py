import os
from kyber_py.ml_kem import ML_KEM_768
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class HybridVaultEngine:
    @staticmethod
    def generate_user_keypair():
        """Generates classical X25519 and Post-Quantum ML-KEM-768 key pairs."""
        # 1. Classical Keypair (Curve25519)
        x_priv = x25519.X25519PrivateKey.generate()
        x_pub = x_priv.public_key()

        # 2. Quantum Keypair (NIST FIPS 203 ML-KEM-768)
        pq_encap_key, pq_decap_key = ML_KEM_768.keygen()

        return {
            "public_keys": {
                "x25519_pub": x_pub.public_bytes_raw().hex(),
                "ml_kem_pub": pq_encap_key.hex()
            },
            "private_keys": {
                "x25519_priv": x_priv.private_bytes_raw().hex(),
                "ml_kem_priv": pq_decap_key.hex()
            }
        }

    @staticmethod
    def encrypt_payload(recipient_x25519_pub_hex: str, recipient_ml_kem_pub_hex: str, plaintext: bytes):
        recip_x25519 = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(recipient_x25519_pub_hex))
        recip_mlkem = bytes.fromhex(recipient_ml_kem_pub_hex)

        # 1. Ephemeral Classical Exchange
        ephemeral_x_priv = x25519.X25519PrivateKey.generate()
        ephemeral_x_pub = ephemeral_x_priv.public_key()
        classical_shared = ephemeral_x_priv.exchange(recip_x25519)

        # 2. Quantum Encapsulation
        pq_shared, pq_ciphertext = ML_KEM_768.encaps(recip_mlkem)

        # 3. Hybrid Key Derivation Function (HKDF)
        session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"pqc-vault-user-v1"
        ).derive(classical_shared + pq_shared)

        # 4. AES-256-GCM Encryption
        aesgcm = AESGCM(session_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        return {
            "ephemeral_x25519_pub": ephemeral_x_pub.public_bytes_raw().hex(),
            "pq_ciphertext": pq_ciphertext.hex(),
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex()
        }

    @staticmethod
    def decrypt_payload(user_x25519_priv_hex: str, user_ml_kem_priv_hex: str, packet: dict):
        # 1. Classical Shared Secret Decapsulation
        user_x_priv = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(user_x25519_priv_hex))
        ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(packet["ephemeral_x25519_pub"]))
        classical_shared = user_x_priv.exchange(ephemeral_pub)

        # 2. Quantum Shared Secret Decapsulation
        pq_decap_key = bytes.fromhex(user_ml_kem_priv_hex)
        pq_ciphertext = bytes.fromhex(packet["pq_ciphertext"])
        pq_shared = ML_KEM_768.decaps(pq_decap_key, pq_ciphertext)

        # 3. Derive Symmetric Session Key
        session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"pqc-vault-user-v1"
        ).derive(classical_shared + pq_shared)

        # 4. AES-256-GCM Decryption
        aesgcm = AESGCM(session_key)
        return aesgcm.decrypt(bytes.fromhex(packet["nonce"]), bytes.fromhex(packet["ciphertext"]), None)