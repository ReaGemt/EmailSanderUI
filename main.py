import sys
import os
import smtplib
import configparser
import mimetypes
import logging
import pandas as pd
import re
from email.message import EmailMessage
from email.mime.application import MIMEApplication
from plyer import notification
from cryptography.fernet import Fernet

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QLineEdit, QTextEdit, QFileDialog, QListWidget, QTabWidget,
    QProgressBar, QMessageBox, QCheckBox, QMenu, QSystemTrayIcon, QComboBox
)
from PySide6.QtGui import QIcon, QAction
from PySide6.QtCore import QThread, Signal

# Импортируем темы оформления из отдельного модуля
from themes import THEMES, get_theme

# Настройка логирования в файл logs.txt
logging.basicConfig(filename="logs.txt", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")


#########################################
# Функция для отправки сообщения
#########################################
def send_email(smtp_server, smtp_port, username, password, msg, timeout=30):
    if smtp_port == 465:
        with smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=timeout) as server:
            server.set_debuglevel(1)
            server.login(username, password)
            server.send_message(msg)
    else:
        with smtplib.SMTP(smtp_server, smtp_port, timeout=timeout) as server:
            server.set_debuglevel(1)
            server.starttls()
            server.login(username, password)
            server.send_message(msg)


#########################################
# Фоновый поток для отправки писем
#########################################
class EmailSenderThread(QThread):
    progress = Signal(int)
    log = Signal(str)
    finished_signal = Signal()

    def __init__(self, smtp_server, smtp_port, smtp_user, smtp_password, emails,
                 subject, body, cc, bcc, attachments,
                 request_read_receipt, request_delivery_receipt):
        super().__init__()
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.emails = emails
        self.subject = subject
        self.body = body
        self.cc = cc
        self.bcc = bcc
        self.attachments = attachments
        self.request_read_receipt = request_read_receipt
        self.request_delivery_receipt = request_delivery_receipt
        self._is_running = True

    def run(self):
        total = len(self.emails)
        for i, recipient in enumerate(self.emails):
            if not self._is_running:
                self.log.emit("Отправка прервана пользователем.")
                break

            msg = EmailMessage()
            msg["From"] = self.smtp_user
            msg["To"] = recipient
            msg["Subject"] = self.subject
            if self.cc:
                msg["Cc"] = ", ".join(self.cc)
            if self.bcc:
                msg["Bcc"] = ", ".join(self.bcc)
            msg.set_content(self.body)
            if self.request_read_receipt:
                msg["Disposition-Notification-To"] = self.smtp_user
            if self.request_delivery_receipt:
                msg["Return-Receipt-To"] = self.smtp_user

            # Добавление вложений
            for filepath in self.attachments:
                try:
                    ctype, encoding = mimetypes.guess_type(filepath)
                    if ctype is None or encoding is not None:
                        ctype = "application/octet-stream"
                    maintype, subtype = ctype.split("/", 1)
                    with open(filepath, "rb") as f:
                        file_data = f.read()
                    attachment = MIMEApplication(file_data, _subtype=subtype)
                    attachment.add_header("Content-Disposition", "attachment",
                                          filename=os.path.basename(filepath))
                    msg.add_attachment(attachment.get_payload(decode=True),
                                       maintype=maintype, subtype=subtype,
                                       filename=os.path.basename(filepath))
                except Exception as e:
                    err_msg = f"Ошибка при добавлении вложения {filepath}: {e}"
                    self.log.emit(err_msg)
                    logging.error(err_msg)

            try:
                send_email(self.smtp_server, self.smtp_port, self.smtp_user,
                           self.smtp_password, msg, timeout=30)
                success_msg = f"✅ Отправлено на {recipient}"
                self.log.emit(success_msg)
                logging.info(success_msg)
            except Exception as e:
                error_msg = f"❌ Ошибка при отправке на {recipient}: {e}"
                self.log.emit(error_msg)
                logging.error(error_msg)

            progress_percent = int(((i + 1) / total) * 100)
            self.progress.emit(progress_percent)
            self.msleep(500)

        self.finished_signal.emit()

    def stop(self):
        self._is_running = False


#########################################
# Тестовый поток для отправки тестового письма
#########################################
class TestEmailThread(QThread):
    result = Signal(str)  # Передаёт "success" или текст ошибки

    def __init__(self, smtp_server, smtp_port, selected_account, smtp_pass):
        super().__init__()
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.selected_account = selected_account
        self.smtp_pass = smtp_pass

    def run(self):
        try:
            msg = EmailMessage()
            msg["From"] = self.selected_account
            msg["To"] = self.selected_account
            msg["Subject"] = "Тестовое письмо"
            msg.set_content("Это тестовое письмо для проверки настроек SMTP.")
            send_email(self.smtp_server, self.smtp_port, self.selected_account,
                       self.smtp_pass, msg, timeout=10)
            self.result.emit("success")
        except Exception as e:
            self.result.emit(str(e))


#########################################
# Основной класс GUI
#########################################
class EmailSenderGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Email Sender")
        self.setGeometry(100, 100, 800, 600)
        self.setWindowIcon(QIcon("icon.png"))  # Устанавливаем иконку главного окна
        self.config = configparser.ConfigParser()
        self.attachments = []  # Список путей вложений
        self.email_thread = None
        self.load_accounts()
        self.init_key()
        self.init_ui()
        self.create_tray_icon()
        self.apply_theme("Светлая")
        self.load_emails_persistent()

    def init_key(self):
        self.key_file = "secret.key"
        generate_new = False
        if not os.path.exists(self.key_file):
            generate_new = True
        else:
            try:
                with open(self.key_file, "rb") as f:
                    key = f.read().strip()
                if len(key) != 44:
                    generate_new = True
            except Exception:
                generate_new = True

        if generate_new:
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as f:
                f.write(key)
            # Устанавливаем атрибут "скрытый" для файла (только для Windows)
            if os.name == 'nt':
                os.system(f'attrib +h {self.key_file}')
        self.cipher_suite = Fernet(key)

    def encrypt_password(self, password):
        return self.cipher_suite.encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted_password):
        return self.cipher_suite.decrypt(encrypted_password.encode()).decode()

    def load_accounts(self):
        if not os.path.exists("config.ini"):
            self.config["ACCOUNTS"] = {}
            with open("config.ini", "w") as configfile:
                self.config.write(configfile)
        else:
            self.config.read("config.ini")

    def save_account(self):
        smtp_server = self.smtp_server_input.text()
        smtp_port = self.smtp_port_input.text()
        smtp_user = self.smtp_user_input.text()
        smtp_pass = self.smtp_pass_input.text()

        if not smtp_server or not smtp_port or not smtp_user or not smtp_pass:
            QMessageBox.warning(self, "Ошибка", "Заполните все поля!")
            return

        encrypted_pass = self.encrypt_password(smtp_pass)
        self.config["ACCOUNTS"][smtp_user] = f"{smtp_server},{smtp_port},{encrypted_pass}"
        with open("config.ini", "w") as configfile:
            self.config.write(configfile)
        QMessageBox.information(self, "Успех", "Учетная запись сохранена!")
        self.update_account_combo()

    def update_account_combo(self):
        self.account_combo.clear()
        if "ACCOUNTS" in self.config:
            accounts = list(self.config["ACCOUNTS"].keys())
            self.account_combo.addItems(accounts)
            # Если ровно одна учётная запись, загрузим поля автоматически
            if len(accounts) == 1:
                self.load_account_fields(accounts[0])

    def load_account_fields(self, account_name: str):
        print("DEBUG: load_account_fields called with:", account_name)
        if not account_name:
            return
        account_data = self.config["ACCOUNTS"].get(account_name)
        if not account_data:
            print("Данные учетной записи не найдены!")
            return
        try:
            smtp_server, smtp_port, encrypted_pass = account_data.split(',')
            smtp_pass = self.decrypt_password(encrypted_pass)
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось загрузить данные учетной записи: {e}")
            return

        self.smtp_server_input.setText(smtp_server)
        self.smtp_port_input.setText(smtp_port)
        self.smtp_user_input.setText(account_name)
        self.smtp_pass_input.setText(smtp_pass)
        print("Поля заполнены:", smtp_server, smtp_port, account_name, smtp_pass)

    def test_email(self):
        selected_account = self.account_combo.currentText()
        if not selected_account:
            QMessageBox.warning(self, "Ошибка", "Нет сохраненных учетных записей для теста!")
            return
        account_data = self.config["ACCOUNTS"].get(selected_account)
        if not account_data:
            QMessageBox.warning(self, "Ошибка", "Выбранная учетная запись не найдена!")
            return
        try:
            smtp_server, smtp_port, encrypted_pass = account_data.split(',')
            smtp_port = int(smtp_port)
            smtp_pass = self.decrypt_password(encrypted_pass)
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Ошибка при чтении учетной записи: {e}")
            return

        self.test_thread = TestEmailThread(smtp_server, smtp_port, selected_account, smtp_pass)
        self.test_thread.result.connect(self.handle_test_result)
        self.test_thread.start()

    def handle_test_result(self, result):
        if result == "success":
            QMessageBox.information(self, "Успех", "Тестовое письмо успешно отправлено!")
        else:
            QMessageBox.warning(self, "Ошибка", f"Ошибка при отправке тестового письма: {result}")

    def apply_theme(self, theme_name):
        style = get_theme(theme_name)
        self.setStyleSheet(style)

    def init_ui(self):
        layout = QVBoxLayout()
        self.tabs = QTabWidget()
        self.tabs.addTab(self.settings_tab(), "Настройки")
        self.tabs.addTab(self.email_list_tab(), "Email-адреса")
        self.tabs.addTab(self.email_content_tab(), "Письмо")
        self.tabs.addTab(self.send_tab(), "Отправка")
        layout.addWidget(self.tabs)
        self.setLayout(layout)

    def delete_account(self):
        selected_account = self.account_combo.currentText()
        if not selected_account:
            QMessageBox.warning(self, "Ошибка", "Нет выбранной учетной записи для удаления!")
            return
        confirm = QMessageBox.question(
            self,
            "Подтверждение",
            f"Вы действительно хотите удалить учетную запись {selected_account}?",
            QMessageBox.Yes | QMessageBox.No
        )
        if confirm == QMessageBox.Yes:
            if selected_account in self.config["ACCOUNTS"]:
                del self.config["ACCOUNTS"][selected_account]
                with open("config.ini", "w") as configfile:
                    self.config.write(configfile)
                QMessageBox.information(self, "Успех", "Учетная запись удалена!")
                self.update_account_combo()
                # Очищаем поля
                self.smtp_server_input.clear()
                self.smtp_port_input.clear()
                self.smtp_user_input.clear()
                self.smtp_pass_input.clear()

    def settings_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        # Поля для ввода настроек SMTP
        self.smtp_server_input = QLineEdit()
        self.smtp_server_input.setPlaceholderText("SMTP сервер")
        self.smtp_port_input = QLineEdit()
        self.smtp_port_input.setPlaceholderText("Порт")
        self.smtp_user_input = QLineEdit()
        self.smtp_user_input.setPlaceholderText("Логин (полный email)")
        self.smtp_pass_input = QLineEdit()
        self.smtp_pass_input.setPlaceholderText("Пароль")
        self.smtp_pass_input.setEchoMode(QLineEdit.Password)

        btn_save_account = QPushButton("Сохранить учетную запись")
        btn_save_account.clicked.connect(self.save_account)

        # Выпадающий список для сохранённых учетных записей
        self.account_combo = QComboBox()
        self.update_account_combo()
        self.account_combo.currentTextChanged.connect(self.load_account_fields)

        btn_test_email = QPushButton("Тестовое письмо")
        btn_test_email.clicked.connect(self.test_email)

        btn_delete_account = QPushButton("Удалить учетную запись")
        btn_delete_account.clicked.connect(self.delete_account)

        # Блок выбора темы оформления
        theme_layout = QHBoxLayout()
        theme_label = QLabel("Выберите тему:")
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(THEMES.keys())
        self.theme_combo.currentTextChanged.connect(self.apply_theme)
        theme_layout.addWidget(theme_label)
        theme_layout.addWidget(self.theme_combo)

        layout.addWidget(QLabel("SMTP сервер:"))
        layout.addWidget(self.smtp_server_input)
        layout.addWidget(QLabel("Порт:"))
        layout.addWidget(self.smtp_port_input)
        layout.addWidget(QLabel("Логин:"))
        layout.addWidget(self.smtp_user_input)
        layout.addWidget(QLabel("Пароль:"))
        layout.addWidget(self.smtp_pass_input)
        layout.addWidget(btn_save_account)
        layout.addWidget(QLabel("Сохраненные учетные записи:"))
        layout.addWidget(self.account_combo)
        layout.addWidget(btn_test_email)
        layout.addWidget(btn_delete_account)
        layout.addLayout(theme_layout)

        tab.setLayout(layout)
        return tab

    def delete_selected_email(self):
        selected_items = self.email_list.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "Информация", "Не выбраны email-адреса для удаления.")
            return
        confirm = QMessageBox.question(
            self,
            "Подтверждение",
            "Вы уверены, что хотите удалить выбранные email-адреса?",
            QMessageBox.Yes | QMessageBox.No
        )
        if confirm == QMessageBox.Yes:
            for item in selected_items:
                self.email_list.takeItem(self.email_list.row(item))
            self.save_emails_persistent()

    def email_list_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        self.email_list = QListWidget()

        btn_load_emails = QPushButton("Загрузить email-адреса")
        btn_load_emails.clicked.connect(self.load_email_list)
        btn_delete_email = QPushButton("Удалить выбранное")
        btn_delete_email.clicked.connect(self.delete_selected_email)

        manual_layout = QHBoxLayout()
        self.manual_email_input = QLineEdit()
        self.manual_email_input.setPlaceholderText("Введите email")
        btn_add_manual = QPushButton("Добавить email")
        btn_add_manual.clicked.connect(self.add_manual_email)
        manual_layout.addWidget(self.manual_email_input)
        manual_layout.addWidget(btn_add_manual)

        layout.addWidget(QLabel("Список Email-адресов:"))
        layout.addWidget(self.email_list)
        hlayout = QHBoxLayout()
        hlayout.addWidget(btn_load_emails)
        hlayout.addWidget(btn_delete_email)
        layout.addLayout(hlayout)
        layout.addLayout(manual_layout)
        tab.setLayout(layout)
        return tab

    def load_email_list(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Выбрать файл", "", "Файлы CSV/XLSX/TXT (*.csv *.xlsx *.txt)"
        )
        if file_path:
            try:
                if file_path.endswith(".csv"):
                    df = pd.read_csv(file_path)
                    emails = df.iloc[:, 0].dropna().astype(str).tolist()
                elif file_path.endswith(".xlsx"):
                    df = pd.read_excel(file_path)
                    emails = df.iloc[:, 0].dropna().astype(str).tolist()
                elif file_path.endswith(".txt"):
                    with open(file_path, "r", encoding="utf-8") as f:
                        emails = [line.strip() for line in f if line.strip()]
                else:
                    QMessageBox.warning(self, "Ошибка", "Неподдерживаемый формат файла!")
                    return
                for email in emails:
                    self.email_list.addItem(email)
            except Exception as e:
                QMessageBox.warning(self, "Ошибка", f"Не удалось загрузить email-адреса: {e}")

    def load_emails_persistent(self):
        if os.path.exists("emails.txt"):
            with open("emails.txt", "r", encoding="utf-8") as f:
                for line in f:
                    email = line.strip()
                    if email:
                        self.email_list.addItem(email)

    def save_emails_persistent(self):
        emails = [self.email_list.item(i).text() for i in range(self.email_list.count())]
        with open("emails.txt", "w", encoding="utf-8") as f:
            for email in emails:
                f.write(email + "\n")

    def delete_selected_email(self):
        for item in self.email_list.selectedItems():
            self.email_list.takeItem(self.email_list.row(item))
        self.save_emails_persistent()

    def add_manual_email(self):
        email = self.manual_email_input.text().strip()
        if email:
            if self.validate_email(email):
                self.email_list.addItem(email)
                self.manual_email_input.clear()
                self.save_emails_persistent()
            else:
                QMessageBox.warning(self, "Ошибка", "Неверный формат email.")

    def validate_email(self, email):
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern, email) is not None

    def email_content_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.subject_input = QLineEdit()
        self.subject_input.setPlaceholderText("Тема письма")
        self.body_input = QTextEdit()
        self.body_input.setPlaceholderText("Текст письма")

        self.cc_input = QLineEdit()
        self.cc_input.setPlaceholderText("CC (через запятую)")
        self.bcc_input = QLineEdit()
        self.bcc_input.setPlaceholderText("BCC (через запятую)")

        self.read_receipt_checkbox = QCheckBox("Запросить уведомление о прочтении")
        self.delivery_receipt_checkbox = QCheckBox("Запросить уведомление о доставке")

        attachment_layout = QHBoxLayout()
        self.attachment_list = QListWidget()
        btn_add_attachment = QPushButton("Добавить вложение")
        btn_add_attachment.clicked.connect(self.add_attachment)
        attachment_layout.addWidget(btn_add_attachment)
        attachment_layout.addWidget(self.attachment_list)

        layout.addWidget(QLabel("Тема письма:"))
        layout.addWidget(self.subject_input)
        layout.addWidget(QLabel("Текст письма:"))
        layout.addWidget(self.body_input)
        layout.addWidget(QLabel("CC:"))
        layout.addWidget(self.cc_input)
        layout.addWidget(QLabel("BCC:"))
        layout.addWidget(self.bcc_input)
        layout.addWidget(self.read_receipt_checkbox)
        layout.addWidget(self.delivery_receipt_checkbox)
        layout.addLayout(attachment_layout)
        tab.setLayout(layout)
        return tab

    def add_attachment(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Выбрать файл для вложения", "", "Все файлы (*)"
        )
        if file_path:
            self.attachments.append(file_path)
            self.attachment_list.addItem(file_path)

    def send_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        btn_send = QPushButton("Начать отправку")
        btn_send.clicked.connect(self.start_sending)
        btn_stop = QPushButton("Остановить отправку")
        btn_stop.clicked.connect(self.stop_sending)
        layout.addWidget(QLabel("Лог отправки:"))
        layout.addWidget(self.log_output)
        layout.addWidget(self.progress_bar)
        hlayout = QHBoxLayout()
        hlayout.addWidget(btn_send)
        hlayout.addWidget(btn_stop)
        layout.addLayout(hlayout)
        tab.setLayout(layout)
        return tab

    def start_sending(self):
        smtp_server = self.smtp_server_input.text()
        try:
            smtp_port = int(self.smtp_port_input.text())
        except ValueError:
            QMessageBox.warning(self, "Ошибка", "Порт должен быть числом!")
            return

        smtp_user = self.smtp_user_input.text()
        smtp_pass = self.smtp_pass_input.text()

        emails = [self.email_list.item(i).text() for i in range(self.email_list.count())]
        subject = self.subject_input.text()
        body = self.body_input.toPlainText()
        cc = [email.strip() for email in self.cc_input.text().split(",") if email.strip()]
        bcc = [email.strip() for email in self.bcc_input.text().split(",") if email.strip()]
        request_read_receipt = self.read_receipt_checkbox.isChecked()
        request_delivery_receipt = self.delivery_receipt_checkbox.isChecked()

        if not smtp_server or not smtp_port or not smtp_user or not smtp_pass:
            QMessageBox.warning(self, "Ошибка", "Заполните все SMTP-поля!")
            return
        if not emails:
            QMessageBox.warning(self, "Ошибка", "Список email-адресов пуст!")
            return

        self.log_output.append("Отправка началась...")
        self.progress_bar.setValue(0)

        self.email_thread = EmailSenderThread(
            smtp_server, smtp_port, smtp_user, smtp_pass, emails,
            subject, body, cc, bcc, self.attachments,
            request_read_receipt, request_delivery_receipt
        )
        self.email_thread.progress.connect(self.progress_bar.setValue)
        self.email_thread.log.connect(self.log_output.append)
        self.email_thread.finished_signal.connect(self.sending_finished)
        self.email_thread.start()

    def stop_sending(self):
        if self.email_thread:
            self.email_thread.stop()
            self.log_output.append("Отправка остановлена пользователем.")

    def sending_finished(self):
        self.log_output.append("Отправка завершена!")
        notification.notify(title="Email Sender", message="Отправка завершена!", timeout=5)

    def create_tray_icon(self):
        self.tray_icon = QSystemTrayIcon(QIcon("icon.png"), self)
        tray_menu = QMenu()
        restore_action = QAction("Восстановить", self)
        restore_action.triggered.connect(self.showNormal)
        exit_action = QAction("Выход", self)
        exit_action.triggered.connect(QApplication.instance().quit)
        tray_menu.addAction(restore_action)
        tray_menu.addAction(exit_action)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.icon_activated)
        self.tray_icon.show()

    def icon_activated(self, reason):
        if reason == QSystemTrayIcon.Trigger:
            self.showNormal()

    def closeEvent(self, event):
        event.ignore()
        self.hide()
        self.tray_icon.showMessage(
            "Email Sender",
            "Приложение свернуто в трей.",
            QSystemTrayIcon.Information,
            2000
        )


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = EmailSenderGUI()
    window.show()
    sys.exit(app.exec())
