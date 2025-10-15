
import os
import json
import random
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict

# configuracion incial
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

# Bloques
def create_blocks(content: str) -> List[str]:

    blocks = []
    i = 0
    while i < len(content):
        #id = random.randint(100, 10000)
        chunk = content[i:i + block_size]
        block_id = str(uuid.uuid4())
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

def read_blocks(start_path: Optional[str]) -> str:
    if not start_path:
        return ""
    parts = []
    p = start_path
    visited = set()
    while p:
        if p in visited:
            # loop de seguridad no deberia pasar
            break
        visited.add(p)
        if not os.path.exists(p):
            raise FileNotFoundError(f"Bloque faltante: {p}")
        with open(p, "r", encoding="utf-8") as bf:
            obj = json.load(bf)
        parts.append(obj.get("datos", ""))
        p = obj.get("siguiente")
    return "".join(parts)

def gather_block_chain(start_path: Optional[str]) -> List[str]:
    chain = []
    p = start_path
    visited = set()
    while p:
        if p in visited:
            break
        visited.add(p)
        if not os.path.exists(p):
            break
        chain.append(p)
        with open(p, "r", encoding="utf-8") as bf:
            obj = json.load(bf)
        p = obj.get("siguiente")
    return chain

def delete_block_files(paths: List[str]):
    for p in paths:
        try:
            if os.path.exists(p):
                os.remove(p)
        except Exception:
            pass


class SistemaFAT:
    def __init__(self):
        ensure_dirs()
        self._fat = load_json(fat_file)
        self._users = load_json(users_file)

    # persistencia
    def _save_fat(self):
        save_json(fat_file, self._fat)

    def _save_users(self):
        save_json(users_file, self._users)

    #usuarios
    def validar_credenciales(self, username: str, password: str) -> bool:
        u = self._users.get(username)
        return bool(u and u.get("password") == password)

    def crear_usuario(self, username: str, password: str) -> dict:
        if username in self._users:
            raise ValueError("Usuario ya existe")
        self._users[username] = {"password": password}
        self._save_users()
        return {"username": username}

    # ---------- operaciones de archivos ----------
    def crear_archivo(self, name: str, content: str, actor: str) -> dict:
        if name in self._fat:
            raise ValueError("Archivo ya existe")
        blocks = create_blocks(content)
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

    def listar_papelera(self) -> List[Dict]:
        result = []
        for name, e in self._fat.items():
            if e.get("in_trash", False):
                result.append({
                    "name": name,
                    "deleted_at": e.get("deleted_at"),
                    "owner": e.get("owner"),
                    "size_chars": e.get("size_chars")
                })
        return result

    def abrir_archivo(self, name: str, actor: str) -> Dict:
        e = self._fat.get(name)
        if not e:
            raise FileNotFoundError("Archivo no existe")
        if e.get("in_trash", False):
            raise ValueError("Archivo está en papelera")
        perms = e.get("permissions", {})
        user_perms = perms.get(actor, {"read": False, "write": False})
        if not user_perms.get("read", False):
            raise PermissionError("No tienes permiso de lectura")
        content = read_blocks(e.get("data_start"))
        metadata = {
            "name": e["name"],
            "owner": e["owner"],
            "size_chars": e["size_chars"],
            "created_at": e["created_at"],
            "modified_at": e["modified_at"]
        }
        return {"metadata": metadata, "content": content}

    def modificar_archivo(self, name: str, new_content: str, actor: str) -> Dict:
        e = self._fat.get(name)
        if not e:
            raise FileNotFoundError("Archivo no existe")
        if e.get("in_trash", False):
            raise ValueError("Archivo está en papelera")
        perms = e.get("permissions", {})
        user_perms = perms.get(actor, {"read": False, "write": False})
        if not user_perms.get("write", False):
            raise PermissionError("No tienes permiso de escritura")
        # guardar cadena vieja y crear nuevos bloques
        old_chain = gather_block_chain(e.get("data_start"))
        new_blocks = create_blocks(new_content)
        new_start = new_blocks[0] if new_blocks else None
        # actualizar entrada
        e["data_start"] = new_start
        e["size_chars"] = len(new_content)
        e["modified_at"] = now_iso()
        self._fat[name] = e
        self._save_fat()
        # eliminar físicamente bloques antiguos
        delete_block_files(old_chain)
        return e

    def eliminar_archivo(self, name: str, actor: str) -> Dict:
        e = self._fat.get(name)
        if not e:
            raise FileNotFoundError("Archivo no existe")
        if e.get("in_trash", False):
            raise ValueError("Archivo ya está en papelera")
        e["in_trash"] = True
        e["deleted_at"] = now_iso()
        self._fat[name] = e
        self._save_fat()
        return e

    def recuperar_archivo(self, name: str, actor: str) -> Dict:
        e = self._fat.get(name)
        if not e:
            raise FileNotFoundError("Archivo no existe")
        if not e.get("in_trash", False):
            raise ValueError("Archivo no está en papelera")
        e["in_trash"] = False
        e["deleted_at"] = None
        e["modified_at"] = now_iso()
        self._fat[name] = e
        self._save_fat()
        return e

    def actualizar_permisos(self, name: str, owner_actor: str, target_user: str,
                            read: Optional[bool] = None, write: Optional[bool] = None) -> Dict:
        e = self._fat.get(name)
        if not e:
            raise FileNotFoundError("Archivo no existe")
        if e.get("owner") != owner_actor:
            raise PermissionError("Solo el owner puede cambiar permisos")
        perms = e.get("permissions", {})
        t = perms.get(target_user, {"read": False, "write": False})
        if read is not None:
            t["read"] = bool(read)
        if write is not None:
            t["write"] = bool(write)
        perms[target_user] = t
        e["permissions"] = perms
        self._fat[name] = e
        # si usuario objetivo no existe en users, lo agrega
        if target_user not in self._users:
            self._users[target_user] = {"password": "1234"}
            self._save_users()
        self._save_fat()
        return perms

    def eliminar_permanente(self, name: str, actor: str) -> None:
        e = self._fat.get(name)
        if not e:
            raise FileNotFoundError("Archivo no existe")
        if e.get("owner") != actor:
            raise PermissionError("Solo el owner puede eliminar permanentemente")
        chain = gather_block_chain(e.get("data_start"))
        delete_block_files(chain)
        del self._fat[name]
        self._save_fat()


    def ver_fat_completa(self, actor: str) -> Dict:
        return self._fat.copy()

def menu_interactivo():
    s = SistemaFAT()
    print("=== Simulador FAT (modo consola) ===")
    username = input("Usuario: ").strip()
    password = input("Password: ").strip()
    if not s.validar_credenciales(username, password):
        print("Credenciales inválidas. Saliendo.")
        return
    print(f"Bienvenido {username}.")
    while True:
        print("\nOpciones:")
        print("1) Crear archivo")
        print("2) Listar archivos")
        print("3) Listar papelera")
        print("4) Abrir archivo")
        print("5) Modificar archivo")
        print("6) Eliminar (mover a papelera)")
        print("7) Recuperar archivo")
        print("8) Actualizar permisos (solo owner)")
        print("9) Eliminar permanentemente (solo owner)")
        print("10) Ver FAT completa (para evidencias)")
        print("0) Salir")
        opt = input(">> ").strip()
        try:
            if opt == "1":
                name = input("Nombre archivo: ").strip()
                content = input("Contenido (enter para finalizar):\n")
                entry = s.crear_archivo(name, content, username)
                print("Creado:", entry)
            elif opt == "2":
                for f in s.listar_archivos():
                    print(f)
            elif opt == "3":
                for f in s.listar_papelera():
                    print(f)
            elif opt == "4":
                name = input("Nombre archivo a abrir: ").strip()
                res = s.abrir_archivo(name, username)
                print("METADATA:", res["metadata"])
                print("CONTENIDO:\n", res["content"])
            elif opt == "5":
                name = input("Nombre archivo a modificar: ").strip()
                newc = input("Nuevo contenido:\n")
                res = s.modificar_archivo(name, newc, username)
                print("Archivo modificado:", res)
            elif opt == "6":
                name = input("Nombre archivo a eliminar: ").strip()
                res = s.eliminar_archivo(name, username)
                print("Movido a papelera:", res)
            elif opt == "7":
                name = input("Nombre archivo a recuperar: ").strip()
                res = s.recuperar_archivo(name, username)
                print("Recuperado:", res)
            elif opt == "8":
                name = input("Archivo: ").strip()
                target = input("Usuario objetivo: ").strip()
                r = input("Permiso lectura (y/n/skip): ").strip().lower()
                w = input("Permiso escritura (y/n/skip): ").strip().lower()
                r_val = None if r == "skip" else (r == "y")
                w_val = None if w == "skip" else (w == "y")
                perms = s.actualizar_permisos(name, username, target, read=r_val, write=w_val)
                print("Permisos actualizados:", perms)
            elif opt == "9":
                name = input("Archivo a eliminar permanentemente: ").strip()
                s.eliminar_permanente(name, username)
                print("Eliminado permanentemente.")
            elif opt == "10":
                fat = s.ver_fat_completa(username)
                print(json.dumps(fat, indent=2, ensure_ascii=False))
            elif opt == "0":
                break
            else:
                print("Opción inválida.")
        except Exception as ex:
            print("ERROR:", type(ex).__name__, str(ex))

if __name__ == "__main__":
    menu_interactivo()
