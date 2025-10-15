import sys
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton,
    QMessageBox, QStackedWidget, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QInputDialog, QListWidget, QDialog, QDialogButtonBox, QTextEdit, QFrame,
    QSizePolicy
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt

from main import SistemaFAT


C_BG = "#F8F8F8"
C_PANEL = "#E3F2FD"
C_ACCENT = "#2196F3"
C_TEXT = "#1A237E"
C_HOVER = "#1565C0"
C_SECOND = "#00BFA5"
C_MUTED = "#546E7A"
C_ALT1 = "#7C4DFF"
C_ALT2 = "#00E676"





class LoginPage(QWidget):
    def __init__(self, sistema: SistemaFAT, on_login_success, stacked: QStackedWidget):
        super().__init__()
        self.sistema = sistema
        self.on_login_success = on_login_success
        self.stacked = stacked
        self.init_ui()

    def init_ui(self):
        self.setStyleSheet("background-color: transparent;")  # Página transparente

        outer_layout = QVBoxLayout()
        outer_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Frame interno con fondo negro
        frame = QFrame()
        frame.setStyleSheet(f"background-color: {C_BG}; color: {C_TEXT}; border-radius: 12px;")
        frame_layout = QVBoxLayout();
        frame_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title = QLabel("Sistema FAT")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {C_ACCENT}; margin-bottom: 12px;")
        subtitle = QLabel("Inicia sesión o crea una cuenta nueva")
        subtitle.setStyleSheet("color: #CCCCCC;")

        self.user_in = QLineEdit();
        self.user_in.setPlaceholderText("Usuario")
        self.pwd_in = QLineEdit();
        self.pwd_in.setPlaceholderText("Contraseña")
        self.pwd_in.setEchoMode(QLineEdit.EchoMode.Password)
        for w in (self.user_in, self.pwd_in): w.setStyleSheet(self.input_style())

        btn_login = QPushButton("Iniciar sesión");
        btn_login.setStyleSheet(self.button_style(C_ACCENT));
        btn_login.clicked.connect(self.try_login)
        btn_reg = QPushButton("Crear nueva cuenta");
        btn_reg.setStyleSheet(self.button_style(C_SECOND));
        btn_reg.clicked.connect(lambda: self.stacked.setCurrentIndex(1))

        frame_layout.addWidget(title)
        frame_layout.addWidget(subtitle)
        frame_layout.addSpacing(6)
        frame_layout.addWidget(self.user_in)
        frame_layout.addWidget(self.pwd_in)
        frame_layout.addSpacing(10)
        frame_layout.addWidget(btn_login)
        frame_layout.addWidget(btn_reg)

        frame.setLayout(frame_layout)
        outer_layout.addWidget(frame)
        self.setLayout(outer_layout)

    def show_warning(self, title, message):
        dlg = QMessageBox(self)
        dlg.setWindowTitle(title)
        dlg.setText(message)
        dlg.setStyleSheet(f"""
            QMessageBox {{
                background-color: {C_BG};
                color: {C_TEXT};
            }}
            QPushButton {{
                background-color: {C_PANEL};
                color: {C_TEXT};
                padding: 6px 12px;
                border-radius: 6px;
            }}
            QPushButton:hover {{
                background-color: {C_HOVER};
            }}
        """)
        dlg.exec()

    def input_style(self):
        return f"""
            QLineEdit {{
                background-color: {C_PANEL};
                border: 1px solid {C_ALT1};
                border-radius: 8px;
                padding: 8px;
                color: {C_TEXT};
                min-width: 260px;
            }}
            QLineEdit:focus {{ border: 1px solid {C_HOVER}; }}
        """

    def button_style(self, color):
        return f"""
            QPushButton {{
                background-color: {color};
                color: #F8FDFF;
                font-weight: bold;
                border-radius: 8px;
                padding: 8px 12px;
                min-width: 200px;
            }}
            QPushButton:hover {{ background-color: {C_HOVER}; }}
        """

    def try_login(self):
        u = self.user_in.text().strip();
        p = self.pwd_in.text().strip()
        if not u or not p:
            QMessageBox.warning(self, "Error", "Ingresa usuario y contraseña")
            return
        if self.sistema.validar_credenciales(u, p):
            self.on_login_success(u)
        else:
            QMessageBox.warning(self, "Error", "Credenciales incorrectas")


class RegisterPage(QWidget):
    def __init__(self, sistema: SistemaFAT, stacked: QStackedWidget):
        super().__init__()
        self.sistema = sistema
        self.stacked = stacked
        self.init_ui()

    def init_ui(self):
        self.setStyleSheet(f"background-color: {C_BG}; color: {C_TEXT};")
        layout = QVBoxLayout();
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title = QLabel("Crear nuevo usuario");
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {C_ALT1}; margin-bottom: 12px;")

        self.user_in = QLineEdit();
        self.user_in.setPlaceholderText("Usuario nuevo")
        self.pwd_in = QLineEdit();
        self.pwd_in.setPlaceholderText("Contraseña");
        self.pwd_in.setEchoMode(QLineEdit.EchoMode.Password)
        for w in (self.user_in, self.pwd_in): w.setStyleSheet(self.input_style())

        btn_create = QPushButton("Crear cuenta");
        btn_create.setStyleSheet(self.button_style(C_ALT2));
        btn_create.clicked.connect(self.create_user)
        btn_back = QPushButton("Volver");
        btn_back.setStyleSheet(self.button_style(C_MUTED));
        btn_back.clicked.connect(lambda: self.stacked.setCurrentIndex(0))

        layout.addWidget(title);
        layout.addWidget(self.user_in);
        layout.addWidget(self.pwd_in)
        layout.addSpacing(8);
        layout.addWidget(btn_create);
        layout.addWidget(btn_back)
        self.setLayout(layout)

    def input_style(self):
        return f"""
            QLineEdit {{
                background-color: {C_PANEL};
                border: 1px solid {C_SECOND};
                border-radius: 8px;
                padding: 8px;
                color: {C_TEXT};
                min-width: 260px;
            }}
            QLineEdit:focus {{ border: 1px solid {C_HOVER}; }}
        """

    def button_style(self, color):
        return f"""
            QPushButton {{
                background-color: {color};
                color: #000;
                font-weight: bold;
                border-radius: 8px;
                padding: 8px 12px;
            }}
            QPushButton:hover {{ background-color: {C_HOVER}; }}
        """

    def create_user(self):
        u = self.user_in.text().strip();
        p = self.pwd_in.text().strip()
        if not u or not p:
            QMessageBox.warning(self, "Error", "Completa todos los campos")
            return
        try:
            self.sistema.crear_usuario(u, p)
            QMessageBox.information(self, "Éxito", f"Usuario '{u}' creado")
            self.stacked.setCurrentIndex(0)
        except Exception as ex:
            QMessageBox.warning(self, "Error", str(ex))


class SidebarButton(QPushButton):
    def __init__(self, text):
        super().__init__(text)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setFixedHeight(44)
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {C_TEXT};
                text-align: left;
                padding-left: 12px;
                border: none;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: {C_PANEL};
                border-radius: 6px;
            }}
        """)


class FilesPage(QWidget):
    def __init__(self, sistema: SistemaFAT, get_current_user):
        super().__init__()
        self.sistema = sistema
        self.get_current_user = get_current_user
        self.init_ui()

    def init_ui(self):
        self.setStyleSheet(f"background-color: {C_BG}; color: {C_TEXT};")
        layout = QVBoxLayout()
        header = QLabel("Administración de Archivos");
        header.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        header.setStyleSheet(f"color: {C_ALT1}; margin-bottom: 8px;")
        layout.addWidget(header)

        btns = QHBoxLayout()
        btn_create = QPushButton("Crear archivo");
        btn_create.setStyleSheet(self.btn_style(C_ACCENT));
        btn_create.clicked.connect(self.create_file)
        btn_refresh = QPushButton("Refrescar lista");
        btn_refresh.setStyleSheet(self.btn_style(C_SECOND));
        btn_refresh.clicked.connect(self.load_files)
        btn_open = QPushButton("Abrir");
        btn_open.setStyleSheet(self.btn_style(C_ALT2));
        btn_open.clicked.connect(self.open_selected)
        btn_modify = QPushButton("Modificar");
        btn_modify.setStyleSheet(self.btn_style("#FFD166"));
        btn_modify.clicked.connect(self.modify_selected)
        btn_delete = QPushButton("Eliminar (papelera)");
        btn_delete.setStyleSheet(self.btn_style(C_MUTED));
        btn_delete.clicked.connect(self.delete_selected)
        btn_trash = QPushButton("Listar papelera");
        btn_trash.setStyleSheet(self.btn_style("#888888"));
        btn_trash.clicked.connect(self.show_trash_dialog)


        btn_perms = QPushButton("Actualizar permisos");
        btn_perms.setStyleSheet(self.btn_style("#FFB4A2"));
        btn_perms.clicked.connect(self.update_permissions_dialog)
        btn_delete_perm = QPushButton("Eliminar permanentemente");
        btn_delete_perm.setStyleSheet(self.btn_style("#FF6B6B"));
        btn_delete_perm.clicked.connect(self.delete_permanent_selected)

        for b in (btn_create, btn_refresh, btn_open, btn_modify, btn_delete, btn_trash, btn_perms, btn_delete_perm):
            btns.addWidget(b)
        layout.addLayout(btns)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Nombre", "Tamaño (chars)", "Owner", "Modificado"])
        self.table.setStyleSheet(f"""
            QHeaderView::section {{ background-color: {C_PANEL}; color: {C_TEXT}; padding:4px; }}
            QTableWidget {{ background-color: #F8FDFF; color: {C_TEXT}; gridline-color: {C_MUTED}; }}
        """)
        layout.addWidget(self.table)
        self.setLayout(layout)
        self.load_files()

    def btn_style(self, color):
        return f"""
            QPushButton {{ background-color: {color}; color: #F8FDFF; border-radius: 6px; padding: 6px 8px; }}
            QPushButton:hover {{ background-color: {C_HOVER}; }}
        """

    def load_files(self):
        try:
            files = self.sistema.listar_archivos()
            self.table.setRowCount(0)
            for f in files:
                r = self.table.rowCount();
                self.table.insertRow(r)
                self.table.setItem(r, 0, QTableWidgetItem(f.get("name", "")))
                self.table.setItem(r, 1, QTableWidgetItem(str(f.get("size_chars", ""))))
                self.table.setItem(r, 2, QTableWidgetItem(f.get("owner", "")))
                self.table.setItem(r, 3, QTableWidgetItem(f.get("modified_at", "")))
        except Exception as ex:
            QMessageBox.warning(self, "Error", str(ex))

    def create_file(self):
        name, ok = QInputDialog.getText(self, "Nombre", "Nombre del archivo:")
        if not ok or not name.strip(): return
        content, ok2 = QInputDialog.getMultiLineText(self, "Contenido", "Contenido del archivo:")
        if not ok2: return
        actor = self.get_current_user()
        try:
            self.sistema.crear_archivo(name.strip(), content or "", actor)
            QMessageBox.information(self, "Éxito", f"Archivo '{name}' creado.")
            self.load_files()
        except Exception as ex:
            QMessageBox.warning(self, "Error", str(ex))

    def get_selected_name(self):
        cur = self.table.currentRow()
        if cur < 0: return None
        return self.table.item(cur, 0).text()

    def open_selected(self):
        name = self.get_selected_name()
        if not name:
            QMessageBox.warning(self, "Error", "Selecciona un archivo")
            return
        actor = self.get_current_user()
        try:
            res = self.sistema.abrir_archivo(name, actor)
            content = res.get("content", "")
            meta = res.get("metadata", {})
            dlg = QMessageBox(self)
            dlg.setWindowTitle(f"Archivo: {name}")
            dlg.setText(
                f"Owner: {meta.get('owner')}\nTamaño: {meta.get('size_chars')}\nModificado: {meta.get('modified_at')}\n\nContenido:\n{content}")
            dlg.exec()
        except Exception as ex:
            QMessageBox.warning(self, "Error", str(ex))

    def modify_selected(self):
        name = self.get_selected_name()
        if not name:
            QMessageBox.warning(self, "Error", "Selecciona un archivo")
            return
        actor = self.get_current_user()
        try:
            opened = self.sistema.abrir_archivo(name, actor)
            current = opened.get("content", "")
        except Exception as ex:
            QMessageBox.warning(self, "Error", f"No se puede abrir: {ex}")
            return
        newc, ok = QInputDialog.getMultiLineText(self, f"Modificar: {name}", "Nuevo contenido:", current)
        if not ok: return
        try:
            self.sistema.modificar_archivo(name, newc or "", actor)
            QMessageBox.information(self, "Éxito", "Archivo modificado")
            self.load_files()
        except Exception as ex:
            QMessageBox.warning(self, "Error", str(ex))

    def delete_selected(self):
        name = self.get_selected_name()
        if not name:
            QMessageBox.warning(self, "Error", "Selecciona un archivo")
            return
        actor = self.get_current_user()
        try:
            self.sistema.eliminar_archivo(name, actor)
            QMessageBox.information(self, "OK", f"'{name}' movido a papelera")
            self.load_files()
        except Exception as ex:
            QMessageBox.warning(self, "Error", str(ex))

    def show_trash_dialog(self):
        try:
            trash_list = self.sistema.listar_papelera()
        except Exception as ex:
            QMessageBox.warning(self, "Error", str(ex))
            return
        dlg = QDialog(self)
        dlg.setWindowTitle("Papelera - Recuperar archivos")
        dlg.setMinimumSize(500, 400)
        v = QVBoxLayout()
        listw = QListWidget()
        for e in trash_list:
            name = e.get("name");
            owner = e.get("owner");
            deleted = e.get("deleted_at");
            size = e.get("size_chars")
            listw.addItem(f"{name}  • owner: {owner}  • tam: {size}  • deleted: {deleted}")
        v.addWidget(listw)
        btns = QDialogButtonBox()
        btns.addButton("Recuperar seleccionado", QDialogButtonBox.ButtonRole.AcceptRole)
        btns.addButton("Cerrar", QDialogButtonBox.ButtonRole.RejectRole)
        btns.accepted.connect(lambda: self.recover_from_dialog(listw, dlg))
        btns.rejected.connect(dlg.reject)
        v.addWidget(btns)
        dlg.setLayout(v)
        dlg.exec()

    def recover_from_dialog(self, listw: QListWidget, dlg: QDialog):
        idx = listw.currentRow()
        if idx < 0:
            QMessageBox.warning(self, "Error", "Selecciona un archivo para recuperar")
            return
        item_text = listw.currentItem().text()
        name = item_text.split("  •")[0].strip()
        try:
            self.sistema.recuperar_archivo(name, self.get_current_user())
            QMessageBox.information(self, "Éxito", f"'{name}' recuperado")
            dlg.accept()
            self.load_files()
        except Exception as ex:
            QMessageBox.warning(self, "Error", str(ex))


    def update_permissions_dialog(self):
        name = self.get_selected_name()
        if not name:
            QMessageBox.warning(self, "Error", "Selecciona un archivo")
            return
        actor = self.get_current_user()


        if not self.sistema.es_administrador(actor):
            QMessageBox.warning(self, "Permiso denegado", "Solo el administrador puede actualizar permisos")
            return

        # pedir usuario objetivo
        target, ok = QInputDialog.getText(self, "Usuario objetivo", "Usuario al que asignar permisos:")
        if not ok or not target.strip():
            return
        target = target.strip()
        # preguntar lectura
        r = QMessageBox.question(self, "Permiso lectura", f"¿Dar permiso de lectura a '{target}'?",
                                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        read_val = (r == QMessageBox.StandardButton.Yes)
        # preguntar escritura
        w = QMessageBox.question(self, "Permiso escritura", f"¿Dar permiso de escritura a '{target}'?",
                                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        write_val = (w == QMessageBox.StandardButton.Yes)
        try:
            perms = self.sistema.actualizar_permisos(name, actor, target, read=read_val, write=write_val)
            QMessageBox.information(self, "Éxito", f"Permisos actualizados para '{target}': {perms.get(target)}")
        except Exception as ex:
            QMessageBox.warning(self, "Error", str(ex))

    def delete_permanent_selected(self):
        name = self.get_selected_name()
        if not name:
            QMessageBox.warning(self, "Error", "Selecciona un archivo")
            return

        actor = self.get_current_user()
        e = self.sistema._fat.get(name)  # Obtener los metadatos del archivo
        if not e:
            QMessageBox.warning(self, "Error", "Archivo no existe")
            return

        # administrador o propietario
        if not (self.sistema.es_administrador(actor) or e.get("owner") == actor):
            QMessageBox.warning(self, "Permiso denegado",
                                "Solo el administrador o el propietario puede eliminar permanentemente")
            return

        confirm = QMessageBox.question(
            self, "Confirmar",
            f"¿Eliminar permanentemente '{name}'? Esta acción no se puede deshacer.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        try:
            self.sistema.eliminar_permanente(name, actor)
            QMessageBox.information(self, "Eliminado", f"'{name}' eliminado permanentemente")
            self.load_files()
        except Exception as ex:
            QMessageBox.warning(self, "Error", str(ex))


class UsersPage(QWidget):
    def __init__(self, sistema: SistemaFAT, get_current_user):
        super().__init__()
        self.sistema = sistema
        self.get_current_user = get_current_user
        self.init_ui()

    def init_ui(self):
        self.setStyleSheet(f"background-color: {C_BG}; color: {C_TEXT};")
        layout = QVBoxLayout()
        header = QLabel("Gestión de Usuarios");
        header.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        header.setStyleSheet(f"color: {C_ALT1}; margin-bottom: 8px;")
        layout.addWidget(header)

        self.list_widget = QListWidget();
        self.list_widget.setStyleSheet(f"background-color: #F8F8F8; color: {C_TEXT};")
        layout.addWidget(self.list_widget)

        btn_create = QPushButton("Crear nuevo usuario");
        btn_create.setStyleSheet(f"background-color: {C_ACCENT}; color: #000; padding: 8px; border-radius: 6px;");
        btn_create.clicked.connect(self.create_user_dialog)
        btn_refresh = QPushButton("Refrescar lista");
        btn_refresh.setStyleSheet(f"background-color: {C_SECOND}; color: #000; padding: 8px; border-radius: 6px;");
        btn_refresh.clicked.connect(self.load_users)

        layout.addWidget(btn_create);
        layout.addWidget(btn_refresh)
        self.setLayout(layout)
        self.load_users()

    def load_users(self):
        try:
            self.list_widget.clear()
            users = getattr(self.sistema, "_users", {})
            for u, meta in users.items():
                self.list_widget.addItem(f"{u}  •  pwd: {meta.get('password', '(n/a)')}")
        except Exception as ex:
            QMessageBox.warning(self, "Error", str(ex))

    def create_user_dialog(self):
        u, ok = QInputDialog.getText(self, "Usuario", "Nombre del usuario:")
        if not ok or not u.strip(): return
        p, ok2 = QInputDialog.getText(self, "Contraseña", "Contraseña:")
        if not ok2: return
        try:
            self.sistema.crear_usuario(u.strip(), p)
            QMessageBox.information(self, "Éxito", f"Usuario '{u}' creado")
            self.load_users()
        except Exception as ex:
            QMessageBox.warning(self, "Error", str(ex))


class SystemPage(QWidget):
    def __init__(self, sistema: SistemaFAT, get_current_user):
        super().__init__()
        self.sistema = sistema
        self.get_current_user = get_current_user
        self.init_ui()

    def init_ui(self):
        self.setStyleSheet(f"background-color: {C_BG}; color: {C_TEXT};")
        layout = QVBoxLayout()
        header = QLabel("Sistema FAT - Inspección");
        header.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        header.setStyleSheet(f"color: {C_ALT1}; margin-bottom: 8px;")
        layout.addWidget(header)

        btn_view = QPushButton("Ver FAT completa (JSON)");
        btn_view.setStyleSheet(f"background-color: {C_SECOND}; color: #000000; padding:8px; border-radius:6px;");
        btn_view.clicked.connect(self.show_fat)
        layout.addWidget(btn_view)
        self.text = QTextEdit();
        self.text.setReadOnly(True);
        self.text.setStyleSheet(f"background-color: #F8F8F8; color: {C_MUTED};")
        layout.addWidget(self.text)
        self.setLayout(layout)

    def show_fat(self):
        try:
            # Solo admin puede ver la FAT completa
            actor = self.get_current_user()
            if not self.sistema.es_administrador(actor):
                QMessageBox.warning(self, "Permiso denegado", "Solo el administrador puede ver la FAT completa")
                return

            full = self.sistema.ver_fat_completa(actor)
            import json
            pretty = json.dumps(full, indent=2, ensure_ascii=False)
            self.text.setPlainText(pretty)
        except Exception as ex:
            QMessageBox.warning(self, "Error", str(ex))


class MainWindow(QWidget):
    def __init__(self, sistema: SistemaFAT, current_user: str, on_close_callback):
        super().__init__()
        self.sistema = sistema
        self.current_user = current_user
        self.on_close_callback = on_close_callback
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("FAT")
        self.setStyleSheet(f"background-color: {C_BG}; color: {C_TEXT};")
        self.resize(1000, 600)
        layout = QHBoxLayout()

        sidebar_widget = QFrame();
        sidebar_widget.setFixedWidth(200);
        sidebar_widget.setStyleSheet(f"background-color: {C_PANEL}; border-right: 1px solid {C_MUTED};")
        sb_inner = QVBoxLayout();
        sb_inner.setContentsMargins(8, 12, 8, 12)
        lbl = QLabel(f"Usuario: {self.current_user}");
        lbl.setStyleSheet(f"color: {C_TEXT}; font-weight:600; margin-bottom:8px;");
        lbl.setAlignment(Qt.AlignmentFlag.AlignLeft)

        # Mostrar rol del usuario
        role = "Administrador" if self.sistema.es_administrador(self.current_user) else "Usuario"
        role_label = QLabel(f"Rol: {role}");
        role_label.setStyleSheet(f"color: {C_ACCENT}; font-weight:500; margin-bottom:12px;")

        sb_inner.addWidget(lbl)
        sb_inner.addWidget(role_label)

        self.btn_arch = SidebarButton("Archivos");
        self.btn_users = SidebarButton("Usuarios");
        self.btn_sys = SidebarButton("Sistema FAT");
        self.btn_exit = SidebarButton("Salir")
        sb_inner.addWidget(self.btn_arch);
        sb_inner.addWidget(self.btn_users);
        sb_inner.addWidget(self.btn_sys);
        sb_inner.addStretch();
        sb_inner.addWidget(self.btn_exit)
        sidebar_widget.setLayout(sb_inner)

        self.stack = QStackedWidget()
        self.files_page = FilesPage(self.sistema, self.get_user);
        self.users_page = UsersPage(self.sistema, self.get_user);
        self.system_page = SystemPage(self.sistema, self.get_user)
        self.stack.addWidget(self.files_page);
        self.stack.addWidget(self.users_page);
        self.stack.addWidget(self.system_page)

        self.btn_arch.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        self.btn_users.clicked.connect(lambda: self.stack.setCurrentIndex(1))
        self.btn_sys.clicked.connect(lambda: self.stack.setCurrentIndex(2))
        # botón salir: cierra la ventana principal -> en closeEvent ejecutamos callback
        self.btn_exit.clicked.connect(self.close)

        layout.addWidget(sidebar_widget);
        layout.addWidget(self.stack)
        self.setLayout(layout)

    def get_user(self):
        return self.current_user

    def closeEvent(self, event):

        try:
            if callable(self.on_close_callback):
                self.on_close_callback()
        except Exception:
            pass
        event.accept()


# ------------------ App bootstrap ------------------

def main():
    app = QApplication(sys.argv)
    sistema = SistemaFAT()

    stacked = QStackedWidget()

    def on_login_success(username):
        # esconder el stacked (login) y abrir main window
        stacked.hide()
        mw = MainWindow(sistema, username, on_close_callback=lambda: stacked.show())
        mw.show()

    login_page = LoginPage(sistema, on_login_success, stacked)
    register_page = RegisterPage(sistema, stacked)
    stacked.addWidget(login_page);
    stacked.addWidget(register_page)
    stacked.setFixedSize(420, 360);
    stacked.setWindowTitle(" FAT - Acceso")
    stacked.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()