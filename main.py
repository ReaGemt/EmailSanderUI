import sys
import smtplib
import json
import logging
import traceback
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QPushButton, QLabel, QLineEdit, QTextEdit,
                             QVBoxLayout, QHBoxLayout, QFileDialog, QListWidget, QMessageBox, QTabWidget,
                             QProgressBar, QCheckBox, QSpinBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.utils import formataddr

logging.basicConfig(filename="logs.txt", level=logging.INFO, encoding="utf-8",
                    format="%(asctime)s - %(levelname)s - %(message)s")

error_logger = logging.getLogger("errors")
error_handler = logging.FileHandler("errors.log", encoding="utf-8")
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
error_logger.addHandler(error_handler)

class EmailSenderThread(QThread):
    progress = pyqtSignal(int)
    log = pyqtSignal(str)

    def __init__(self, smtp_server, smtp_port, smtp_user, smtp_pass, emails,
                 subject, body, cc, bcc, attachments,
                 request_read_receipt, request_delivery_receipt,
                 delay_between_emails=2):
        super().__init__()
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_pass = smtp_pass
        self.emails = emails
        self.subject = subject
        self.body = body
        self.cc = cc
        self.bcc = bcc
        self.attachments = attachments
        self.request_read_receipt = request_read_receipt
        self.request_delivery_receipt = request_delivery_receipt
        self.delay_between_emails = delay_between_emails

    def run(self):
        total = len(self.emails)
        for i, recipient in enumerate(self.emails):
            try:
                msg = MIMEMultipart()
                msg['From'] = formataddr(("", self.smtp_user))
                msg['To'] = recipient
                msg['Subject'] = self.subject
                if self.cc:
                    msg['Cc'] = self.cc
                if self.bcc:
                    msg['Bcc'] = self.bcc
                if self.request_read_receipt:
                    msg.add_header('Disposition-Notification-To', self.smtp_user)
                if self.request_delivery_receipt:
                    msg.add_header('Return-Receipt-To', self.smtp_user)

                msg.attach(MIMEText(self.body, 'plain'))

                for path in self.attachments:
                    try:
                        with open(path, "rb") as f:
                            part = MIMEApplication(f.read(), Name=path.split("/")[-1])
                            part['Content-Disposition'] = f'attachment; filename="{path.split("/")[-1]}"'
                            msg.attach(part)
                    except Exception as e:
                        self.log.emit(f"❌ Ошибка с вложением {path}: {e}")

                with smtplib.SMTP(self.smtp_server, self.smtp_port) as smtp:
                    smtp.starttls()
                    smtp.login(self.smtp_user, self.smtp_pass)
                    try:
                        smtp.send_message(msg)
                        self.log.emit(f"✅ Отправлено на {recipient}")
                    except smtplib.SMTPResponseException as smtp_err:
                        if smtp_err.smtp_code == 450:
                            self.log.emit(f"⚠️ Ошибка 450. Пауза 60 сек... Повторная отправка на {recipient}")
                            self.sleep(60)
                            try:
                                smtp.send_message(msg)
                                self.log.emit(f"🔁 Повторно отправлено на {recipient}")
                            except Exception as retry_err:
                                self.log.emit(f"❌ Повторная ошибка при отправке на {recipient}: {retry_err}")
                                error_logger.error(f"Повторная ошибка: {recipient}", exc_info=True)
                        else:
                            raise
            except Exception as e:
                self.log.emit(f"❌ Ошибка при отправке на {recipient}: {e}")
                error_logger.error(f"Ошибка при отправке: {recipient}", exc_info=True)
            progress_percent = int(((i + 1) / total) * 100)
            self.progress.emit(progress_percent)
            self.sleep(self.delay_between_emails)

# Остальной код GUI и методов не показан для краткости
