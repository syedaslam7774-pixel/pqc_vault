import json
import os
import re
import time
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from engine import HybridVaultEngine

app = FastAPI(title="Post-Quantum Cross-Device Notepad")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_FILE = "/tmp/vault_db.json" if os.environ.get("VERCEL") else "vault_db.json"

def load_db():
    if not os.path.exists(DB_FILE):
        return {"users": {}}
    with open(DB_FILE, "r") as f:
        try:
            return json.load(f)
        except Exception:
            return {"users": {}}

def save_db(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=2)

def clean_and_parse_master_key(raw_input: str) -> dict:
    """Extracts valid JSON keypair even if surrounded by unwanted text/labels."""
    if not raw_input:
        raise ValueError("Master key is empty.")
    
    # Extract outermost JSON object if extra text surrounds it
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
    db = load_db()
    return {"exists": req.username in db["users"]}

@app.post("/api/register")
def register_user(req: RegisterReq):
    db = load_db()
    if req.username in db["users"]:
        raise HTTPException(status_code=400, detail="Username already exists.")

    keys = HybridVaultEngine.generate_user_keypair()

    encrypted_pass_packet = HybridVaultEngine.encrypt_payload(
        recipient_x25519_pub_hex=keys["public_keys"]["x25519_pub"],
        recipient_ml_kem_pub_hex=keys["public_keys"]["ml_kem_pub"],
        plaintext=req.password.encode("utf-8")
    )

    db["users"][req.username] = {
        "public_keys": keys["public_keys"],
        "encrypted_password_packet": encrypted_pass_packet,
        "notes": {}
    }
    save_db(db)

    return {
        "status": "registered",
        "username": req.username,
        "master_key": json.dumps(keys["private_keys"])
    }

@app.post("/api/login")
def login_user(req: LoginReq):
    db = load_db()
    user = db["users"].get(req.username)
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

    decrypted_notes = []
    user_notes = user.get("notes", {})
    for note_id, note_data in user_notes.items():
        try:
            decrypted_bytes = HybridVaultEngine.decrypt_payload(
                user_x25519_priv_hex=priv_keys["x25519_priv"],
                user_ml_kem_priv_hex=priv_keys["ml_kem_priv"],
                packet=note_data["encrypted_packet"]
            )
            raw_payload = json.loads(decrypted_bytes.decode("utf-8"))
            decrypted_notes.append({
                "id": note_id,
                "title": raw_payload.get("title", "Untitled Note"),
                "content": raw_payload.get("content", ""),
                "updated_at": note_data.get("updated_at", int(time.time()))
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
    db = load_db()
    user = db["users"].get(req.username)
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

    if "notes" not in user:
        user["notes"] = {}

    user["notes"][req.note_id] = {
        "encrypted_packet": encrypted_packet,
        "updated_at": int(time.time())
    }
    save_db(db)

    return {"status": "saved", "note_id": req.note_id}

@app.post("/api/delete-note")
def delete_note(req: DeleteNoteReq):
    db = load_db()
    user = db["users"].get(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if "notes" in user and req.note_id in user["notes"]:
        del user["notes"][req.note_id]
        save_db(db)

    return {"status": "deleted"}

os.makedirs("static", exist_ok=True)
if os.path.exists("static") and not os.environ.get("VERCEL"):
    app.mount("/", StaticFiles(directory="static", html=True), name="static")