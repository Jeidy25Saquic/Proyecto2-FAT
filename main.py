

import os
import json
import random
from datetime import datetime, timezone
from typing import Optional, List, Dict

block_size = 20
fs_dir = "./fs"
blocks_dir = os.path.join(fs_dir, "blocks")
fat_file = os.path.join(fs_dir, "fat.json")
users_file = os.path.join(fs_dir, "users.json")

default_admin = {"username": "admin", "password": "1234"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def ensure_dirs():
    os.makedirs(blocks_dir, exist_ok=True)
    if not os.path.exists(fat_file):
        with open(fat_file, "w", encoding="utf-8") as f:
            json.dump({}, f, indent=2, ensure_ascii=False)
    if not os.path.exists(users_file):
        with open(users_file, "w", encoding="utf-8") as f:
            # guarda solo usuarios y contraseñas (proyecto académico)
            json.dump({default_admin["username"]: {"password": default_admin["password"]}}, f, indent=2, ensure_ascii=False)

def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(path: str, obj: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def create_blocks_from_content(content: str) -> List[str]:
    id= random.randint(100,10000)
    blocks = []
    i = 0
    while i < len(content):
        chunk = content[i:i + block_size]
        block_id = str(id)
        filename = f"{block_id}.json"
        path = os.path.join(blocks_dir, filename)
        block_obj = {"datos": chunk, "siguiente": None, "eof": False}
        with open(path, "w", encoding="utf-8") as bf:
            json.dump(block_obj, bf, indent=2, ensure_ascii=False)
        blocks.append(path)
        i += block_size
    # enlazar bloques
    for idx, p in enumerate(blocks):
        with open(p, "r+", encoding="utf-8") as bf:
            obj = json.load(bf)
            if idx < len(blocks) - 1:
                obj["siguiente"] = blocks[idx + 1]
                obj["eof"] = False
            else:
                obj["siguiente"] = None
                obj["eof"] = True
            bf.seek(0)
            json.dump(obj, bf, indent=2, ensure_ascii=False)
            bf.truncate()
    return blocks



class SistemaFAT:
    def __init__(self):
        ensure_dirs()
        self._fat = load_json(fat_file)
        self._users = load_json(users_file)


    def _save_fat(self):
        save_json(fat_file, self._fat)

    def _save_users(self):
        save_json(users_file, self._users)


    def validar_credenciales(self, username: str, password: str) -> bool:
        u = self._users.get(username)
        return bool(u and u.get("password") == password)

    def crear_usuario(self, username: str, password: str) -> dict:
        if username in self._users:
            raise ValueError("Usuario ya existe")
        self._users[username] = {"password": password}
        self._save_users()
        return {"username": username}


    def crear_archivo(self, name: str, content: str, actor: str) -> dict:
        if name in self._fat:
            raise ValueError("Archivo ya existe")
        blocks = create_blocks_from_content(content)
        start = blocks[0] if blocks else None
        entry = {
            "name": name,
            "data_start": start,
            "in_trash": False,
            "size_chars": len(content),
            "created_at": now_iso(),
            "modified_at": now_iso(),
            "deleted_at": None,
            "owner": actor,
            "permissions": {
                actor: {"read": True, "write": True}
            }
        }
        self._fat[name] = entry
        self._save_fat()
        return entry

    def listar_archivos(self) -> List[Dict]:
        result = []
        for name, e in self._fat.items():
            if not e.get("in_trash", False):
                result.append({
                    "name": name,
                    "size_chars": e.get("size_chars"),
                    "owner": e.get("owner"),
                    "modified_at": e.get("modified_at")
                })
        return result




if __name__ == "__main__":
    s = SistemaFAT()
    print("=== Simulador FAT (modo consola) ===")
    username = input("Usuario: ").strip()
    password = input("Password: ").strip()
    if not s.validar_credenciales(username, password):
        print("Credenciales inválidas. Saliendo.")

    print(f"Bienvenido {username}.")

    name = input("Nombre archivo: ").strip()
    content = input("Contenido (enter para finalizar):\n")
    entry = s.crear_archivo(name, content, username)
    print("Creado:", entry)

    for f in s.listar_archivos():
        print(f)

