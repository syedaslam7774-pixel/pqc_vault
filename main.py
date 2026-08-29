import json
import os
import re
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from engine import HybridVaultEngine
import db

# Initialize the database and create tables
db.init_db()

app = FastAPI(title="Post-Quantum Cross-Device Notepad")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def clean_and_parse_master_key(raw_input: str) -> dict:
    if not raw_input:
        raise ValueError("Master key is empty.")
    match = re.search(r'\{.*\}', raw_input, re.DOTALL)
    clean_str = match.group(0) if match else raw_input.strip()
    try:
        keys = json.loads(clean_str)
        if "x25519_priv" in keys and "ml_kem_priv" in keys:
            return keys
    except Exception:
        pass
    raise ValueError("Could not find valid keypair inside the provided master key text.")

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

@app.post("/api/check-user")
def check_user(req: CheckUserReq):
    return {"exists": db.user_exists(req.username)}

@app.post("/api/register")
def register_user(req: RegisterReq):
    if db.user_exists(req.username):
        raise HTTPException(status_code=400, detail="Username already exists.")

    keys = HybridVaultEngine.generate_user_keypair()

    # Encrypt password with random salt
    encrypted_pass_packet = HybridVaultEngine.encrypt_payload(
        recipient_x25519_pub_hex=keys["public_keys"]["x25519_pub"],
        recipient_ml_kem_pub_hex=keys["public_keys"]["ml_kem_pub"],
        plaintext=req.password.encode("utf-8")
    )

    db.create_user(
        username=req.username,
        x25519_pub=keys["public_keys"]["x25519_pub"],
        ml_kem_pub=keys["public_keys"]["ml_kem_pub"],
        ephemeral_x25519_pub=encrypted_pass_packet["ephemeral_x25519_pub"],
        pq_ciphertext=encrypted_pass_packet["pq_ciphertext"],
        salt=encrypted_pass_packet["salt"],
        nonce=encrypted_pass_packet["nonce"],
        ciphertext=encrypted_pass_packet["ciphertext"]
    )

    # Return unsalted, raw master keypair to the user
    return {
        "status": "registered",
        "username": req.username,
        "master_key": json.dumps(keys["private_keys"])
    }

@app.post("/api/login")
def login_user(req: LoginReq):
    user = db.get_user(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    try:
        priv_keys = clean_and_parse_master_key(req.master_key)
        decrypted_pass_bytes = HybridVaultEngine.decrypt_payload(
            user_x25519_priv_hex=priv_keys["x25519_priv"],
            user_ml_kem_priv_hex=priv_keys["ml_kem_priv"],
            packet=user["encrypted_password_packet"]
        )
        stored_password = decrypted_pass_bytes.decode("utf-8")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Master Key provided.")

    if stored_password != req.password:
        raise HTTPException(status_code=401, detail="Incorrect password.")

    raw_notes = db.get_user_notes(req.username)
    decrypted_notes = []
    for note in raw_notes:
        try:
            decrypted_bytes = HybridVaultEngine.decrypt_payload(
                user_x25519_priv_hex=priv_keys["x25519_priv"],
                user_ml_kem_priv_hex=priv_keys["ml_kem_priv"],
                packet=note["encrypted_packet"]
            )
            raw_payload = json.loads(decrypted_bytes.decode("utf-8"))
            decrypted_notes.append({
                "id": note["note_id"],
                "title": raw_payload.get("title", "Untitled Note"),
                "content": raw_payload.get("content", ""),
                "updated_at": note.get("updated_at")
            })
        except Exception:
            continue

    return {
        "status": "authenticated",
        "username": req.username,
        "notes": decrypted_notes
    }

@app.post("/api/save-note")
def save_note(req: SaveNoteReq):
    user = db.get_user(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    try:
        priv_keys = clean_and_parse_master_key(req.master_key)
        decrypted_pass = HybridVaultEngine.decrypt_payload(
            user_x25519_priv_hex=priv_keys["x25519_priv"],
            user_ml_kem_priv_hex=priv_keys["ml_kem_priv"],
            packet=user["encrypted_password_packet"]
        ).decode("utf-8")
    except Exception:
        raise HTTPException(status_code=400, detail="Decryption error.")

    if decrypted_pass != req.password:
        raise HTTPException(status_code=401, detail="Unauthorized")

    payload_json = json.dumps({"title": req.title, "content": req.content})

    encrypted_packet = HybridVaultEngine.encrypt_payload(
        recipient_x25519_pub_hex=user["public_keys"]["x25519_pub"],
        recipient_ml_kem_pub_hex=user["public_keys"]["ml_kem_pub"],
        plaintext=payload_json.encode("utf-8")
    )

    db.save_user_note(
        username=req.username,
        note_id=req.note_id,
        ephemeral_x25519_pub=encrypted_packet["ephemeral_x25519_pub"],
        pq_ciphertext=encrypted_packet["pq_ciphertext"],
        salt=encrypted_packet["salt"],
        nonce=encrypted_packet["nonce"],
        ciphertext=encrypted_packet["ciphertext"]
    )

    return {"status": "saved", "note_id": req.note_id}

@app.post("/api/delete-note")
def delete_note(req: DeleteNoteReq):
    user = db.get_user(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    db.delete_user_note(req.username, req.note_id)
    return {"status": "deleted"}

os.makedirs("static", exist_ok=True)
if os.path.exists("static") and not os.environ.get("VERCEL"):
    app.mount("/", StaticFiles(directory="static", html=True), name="static")