from pydantic import BaseModel
from typing import Optional

class KeyPairResponse(BaseModel):
    x25519_pub: str
    ml_kem_pub: str

class EncryptRequest(BaseModel):
    recipient_x25519_pub: str
    recipient_ml_kem_pub: str
    plaintext: str

class EncryptedPacket(BaseModel):
    ephemeral_x25519_pub: str
    pq_ciphertext: str
    nonce: str
    ciphertext: str

class DecryptRequest(BaseModel):
    ephemeral_x25519_pub: str
    pq_ciphertext: str
    nonce: str
    ciphertext: str

class DecryptResponse(BaseModel):
    status: str
    decrypted_text: Optional[str] = None
    error: Optional[str] = None

class TamperTestRequest(BaseModel):
    ephemeral_x25519_pub: str
    pq_ciphertext: str
    nonce: str
    ciphertext: str