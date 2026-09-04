import hashlib
import json
import os
import re
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from engine import HybridVaultEngine
import db

@asynccontextmanager
async def lifespan(app: FastAPI):
    if os.environ.get("TURSO_DATABASE_URL") and os.environ.get("TURSO_AUTH_TOKEN"):
        try:
            db.init_db()
        except Exception as e:
            print(f"[Turso Init Warning] {e}")
    yield

app = FastAPI(title="Post-Quantum Cross-Device Notepad", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def compute_key_fingerprint(x25519_priv: str, ml_kem_priv: str) -> str:
    """Computes a strict SHA-256 checksum over the raw private key material."""
    payload = f"{x25519_priv.strip()}:{ml_kem_priv.strip()}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

def clean_and_parse_master_key(raw_input: str) -> dict:
    if not raw_input:
        raise ValueError("Master key string is completely empty.")

    cleaned = (
        str(raw_input)
        .replace('“', '"')
        .replace('”', '"')
        .replace('‘', "'")
        .replace('’', "'")
        .replace('&quot;', '"')
        .replace('\\"', '"')
        .replace('`', '')
        .strip()
    )

    match = re.search(r'\{[\s\S]*\}', cleaned)
    clean_str = match.group(0) if match else cleaned

    try:
        keys = json.loads(clean_str)
    except Exception as e:
        raise ValueError(f"Corrupted or invalid JSON format: {e}")

    if not isinstance(keys, dict):
        raise ValueError("Master key must be a valid JSON dictionary.")

    if "x25519_priv" not in keys or "ml_kem_priv" not in keys:
        raise ValueError("Master key is missing required cryptographic key pairs.")

    x25519 = str(keys["x25519_priv"]).strip()
    ml_kem = str(keys["ml_kem_priv"]).strip()

    if not re.fullmatch(r'[0-9a-fA-F]+', x25519):
        raise ValueError("x25519_priv contains invalid characters. Must be strict hexadecimal.")
    if not re.fullmatch(r'[0-9a-fA-F]+', ml_kem):
        raise ValueError("ml_kem_priv contains invalid characters. Must be strict hexadecimal.")

    if len(x25519) != 64:
        raise ValueError(f"x25519_priv length tampered. Expected 64 hex chars, got {len(x25519)}.")

    return {
        "x25519_priv": x25519,
        "ml_kem_priv": ml_kem,
        "fingerprint": compute_key_fingerprint(x25519, ml_kem)
    }

class CheckUserReq(BaseModel):
    username: str

class RegisterReq(BaseModel):
    username: str
    password: str

class LoginReq(BaseModel):
    username: str
    password: str
    master_key: str

class SaveNoteReq(BaseModel):
    username: str
    password: str
    master_key: str
    note_id: str
    title: str
    content: str

class DeleteNoteReq(BaseModel):
    username: str
    password: str
    master_key: str
    note_id: str

@app.get("/")
@app.get("/api")
def root():
    return {"status": "online", "system": "Post-Quantum Cryptographic Vault"}

@app.post("/check-user")
@app.post("/api/check-user")
def check_user(req: CheckUserReq):
    return {"exists": db.user_exists(req.username.strip().lower())}

@app.post("/register")
@app.post("/api/register")
def register_user(req: RegisterReq):
    clean_user = req.username.strip().lower()
    if not clean_user or not req.password:
        raise HTTPException(status_code=400, detail="Username and password are required.")

    if db.user_exists(clean_user):
        raise HTTPException(status_code=400, detail=f"Username '{clean_user}' already exists.")

    keys = HybridVaultEngine.generate_user_keypair()
    x25519_priv = keys["private_keys"]["x25519_priv"]
    ml_kem_priv = keys["private_keys"]["ml_kem_priv"]

    key_fingerprint = compute_key_fingerprint(x25519_priv, ml_kem_priv)

    verification_payload = json.dumps({
        "pass": req.password,
        "key_fingerprint": key_fingerprint
    })

    encrypted_pass_packet = HybridVaultEngine.encrypt_payload(
        recipient_x25519_pub_hex=keys["public_keys"]["x25519_pub"],
        recipient_ml_kem_pub_hex=keys["public_keys"]["ml_kem_pub"],
        plaintext=verification_payload.encode("utf-8")
    )

    db.create_user(
        username=clean_user,
        x25519_pub=keys["public_keys"]["x25519_pub"],
        ml_kem_pub=keys["public_keys"]["ml_kem_pub"],
        ephemeral_x25519_pub=encrypted_pass_packet["ephemeral_x25519_pub"],
        pq_ciphertext=encrypted_pass_packet["pq_ciphertext"],
        salt=encrypted_pass_packet["salt"],
        nonce=encrypted_pass_packet["nonce"],
        ciphertext=encrypted_pass_packet["ciphertext"]
    )

    return {
        "status": "registered",
        "username": clean_user,
        "master_key": json.dumps(keys["private_keys"])
    }

@app.post("/login")
@app.post("/api/login")
def login_user(req: LoginReq):
    clean_user = req.username.strip().lower()
    user = db.get_user(clean_user)
    if not user:
        raise HTTPException(status_code=404, detail=f"User '{clean_user}' not found.")

    try:
        priv_keys = clean_and_parse_master_key(req.master_key)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Tampered Key Detected: {str(e)}")

    try:
        decrypted_bytes = HybridVaultEngine.decrypt_payload(
            user_x25519_priv_hex=priv_keys["x25519_priv"],
            user_ml_kem_priv_hex=priv_keys["ml_kem_priv"],
            packet=user["encrypted_password_packet"]
        )
        decrypted_payload = json.loads(decrypted_bytes.decode("utf-8"))
    except Exception as e:
        raise HTTPException(status_code=400, detail="Master key invalid: Cryptographic decapsulation failed.")

    if decrypted_payload.get("key_fingerprint") != priv_keys["fingerprint"]:
        raise HTTPException(status_code=401, detail="Key integrity failure: Master key has been modified.")

    if decrypted_payload.get("pass") != req.password:
        raise HTTPException(status_code=401, detail="Incorrect password.")

    raw_notes = db.get_user_notes(clean_user)
    decrypted_notes = []
    for note in raw_notes:
        try:
            note_bytes = HybridVaultEngine.decrypt_payload(
                user_x25519_priv_hex=priv_keys["x25519_priv"],
                user_ml_kem_priv_hex=priv_keys["ml_kem_priv"],
                packet=note["encrypted_packet"]
            )
            raw_data = json.loads(note_bytes.decode("utf-8"))
            decrypted_notes.append({
                "id": note["note_id"],
                "title": raw_data.get("title", "Untitled Note"),
                "content": raw_data.get("content", ""),
                "updated_at": note.get("updated_at")
            })
        except Exception:
            continue

    return {
        "status": "authenticated",
        "username": clean_user,
        "notes": decrypted_notes
    }

@app.post("/save-note")
@app.post("/api/save-note")
def save_note(req: SaveNoteReq):
    clean_user = req.username.strip().lower()
    user = db.get_user(clean_user)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    try:
        priv_keys = clean_and_parse_master_key(req.master_key)
        decrypted_bytes = HybridVaultEngine.decrypt_payload(
            user_x25519_priv_hex=priv_keys["x25519_priv"],
            user_ml_kem_priv_hex=priv_keys["ml_kem_priv"],
            packet=user["encrypted_password_packet"]
        )
        decrypted_payload = json.loads(decrypted_bytes.decode("utf-8"))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Authentication error: {str(e)}")

    if decrypted_payload.get("pass") != req.password or decrypted_payload.get("key_fingerprint") != priv_keys["fingerprint"]:
        raise HTTPException(status_code=401, detail="Unauthorized: Key or password mismatch.")

    payload_json = json.dumps({"title": req.title, "content": req.content})

    encrypted_packet = HybridVaultEngine.encrypt_payload(
        recipient_x25519_pub_hex=user["public_keys"]["x25519_pub"],
        recipient_ml_kem_pub_hex=user["public_keys"]["ml_kem_pub"],
        plaintext=payload_json.encode("utf-8")
    )

    db.save_user_note(
        username=clean_user,
        note_id=req.note_id,
        ephemeral_x25519_pub=encrypted_packet["ephemeral_x25519_pub"],
        pq_ciphertext=encrypted_packet["pq_ciphertext"],
        salt=encrypted_packet["salt"],
        nonce=encrypted_packet["nonce"],
        ciphertext=encrypted_packet["ciphertext"]
    )

    return {"status": "saved", "note_id": req.note_id}

@app.post("/delete-note")
@app.post("/api/delete-note")
def delete_note(req: DeleteNoteReq):
    clean_user = req.username.strip().lower()
    user = db.get_user(clean_user)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    db.delete_user_note(clean_user, req.note_id)
    return {"status": "deleted"}