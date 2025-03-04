# Email Sender

**Email Sender** – это графическое приложение на Python, позволяющее отправлять письма через SMTP с использованием удобного интерфейса, реализованного на PySide6. Приложение поддерживает:
- Отправку писем с вложениями
- Сохранение SMTP-учетных записей с шифрованием паролей (с использованием cryptography.fernet)
- Загрузку email-адресов из файлов форматов TXT, CSV и XLSX, а также их ручной ввод с валидацией
- Фоновую отправку писем в отдельном потоке (с использованием QThread)
- Логирование действий в файл logs.txt
- Пуш-уведомления о завершении отправки (через plyer)
- Минимизацию приложения в системный трей с контекстным меню
- Выбор тем оформления (несколько тем, реализованных через отдельный модуль themes.py)
- Отправку тестового письма для проверки настроек SMTP

## Функциональные возможности

- Графический интерфейс (GUI):
  - Главное окно с четырьмя вкладками: "Настройки", "Email-адреса", "Письмо", "Отправка"
  - Поддержка минимизации в системный трей с контекстным меню (Восстановить/Выход)
  - Push-уведомления о завершении отправки писем

- Работа с учетными записями SMTP:
  - Во вкладке "Настройки" можно вводить SMTP-сервер, порт, логин и пароль
  - Сохранение учетных записей в файле config.ini с шифрованием паролей
  - Выбор сохраненной учетной записи и автоматическая загрузка настроек
  - Отправка тестового письма для проверки настроек

- Работа с email-адресами:
  - Загрузка списка email из файлов (TXT, CSV, XLSX)
  - Ручной ввод email-адресов с проверкой формата
  - Удаление выбранных адресов
  - Сохранение списка email в файл (с возможностью шифрования – опционально)

- Работа с письмом:
  - Поля для ввода темы, текста письма, а также адресов для CC и BCC
  - Возможность запроса уведомлений о прочтении и доставке
  - Добавление вложений к письму

- Процесс отправки:
  - Отправка осуществляется в фоновом потоке (QThread) для поддержания отзывчивости интерфейса
  - Отображение прогресс-бара и логирование процесса отправки
  - Возможность остановки отправки писем

- Дополнительные функции:
  - Выбор тем оформления (светлая, тёмная, синяя, зелёная, классическая и др.)
  - Иконка приложения для главного окна и системного трея (иконка взята с [Klipartz](https://www.klipartz.com/))
  - Сохранение email-адресов с возможностью их шифрования

## Требования

- Python 3.6+
- PySide6 (https://pypi.org/project/PySide6/)
- cryptography (https://pypi.org/project/cryptography/)
- pandas (https://pandas.pydata.org/)
- plyer (https://pypi.org/project/plyer/)

## Установка

1. Клонируйте репозиторий:

   git clone https://github.com/yourusername/EmailSenderUI.git
   cd EmailSenderUI

2. Создайте виртуальное окружение и активируйте его:

   python -m venv .venv
   (на Windows: .venv\Scripts\activate; на Linux/Mac: source .venv/bin/activate)

3. Установите зависимости:

   pip install -r requirements.txt

   Если файла requirements.txt нет, установите вручную:
   
   pip install PySide6 cryptography pandas plyer

## Использование

1. Запустите приложение:

   python main.py

2. Настройки:
   - Во вкладке "Настройки" введите параметры SMTP-сервера, порт, логин и пароль.
   - Нажмите "Сохранить учетную запись" для сохранения настроек (пароль шифруется).
   - Выберите сохраненную учетную запись из выпадающего списка, чтобы автоматически подставились данные.
   - Проверьте настройки, отправив "Тестовое письмо".

3. Email-адреса:
   - Загрузите список email из файла или добавьте адреса вручную через поле "Введите email".
   - Удаляйте ненужные адреса по выбору.

4. Письмо:
   - Заполните поля "Тема письма" и "Текст письма".
   - При необходимости добавьте адреса для CC и BCC, запросите уведомления о прочтении/доставке.
   - Прикрепите вложения, если это нужно.

5. Отправка:
   - Перейдите во вкладку "Отправка", где отображается лог и прогресс отправки.
   - Нажмите "Начать отправку" для запуска процесса.
   - При необходимости остановите отправку, нажав "Остановить отправку".
   - После завершения отправки появится push-уведомление.

## SMTP Настройки для Яндекс 360

- SMTP_SSL (порт 465):
  - SMTP-сервер: smtp.yandex.ru
  - Порт: 465
  - Приложение использует SMTP_SSL для подключения (автоматически выбирается при указании порта 465).

- STARTTLS (порт 587):
  - SMTP-сервер: smtp.yandex.ru
  - Порт: 587
  - Приложение использует SMTP с вызовом starttls() для подключения.

_Если включена двухфакторная аутентификация, используйте пароль приложения._

## Иконка приложения

Иконка для главного окна и системного трея взята с [Klipartz](https://www.klipartz.com/). Файл icon.png должен находиться в рабочей директории.

## Безопасность

- Пароли SMTP-учетных записей шифруются с помощью библиотеки cryptography.fernet и сохраняются в файле config.ini.
- (Опционально) Список email-адресов можно шифровать для дополнительной защиты.

## Дополнительно

- Темы оформления реализованы в отдельном модуле themes.py.
- Логи отправки сохраняются в файл logs.txt.
- При закрытии приложение сворачивается в системный трей с push-уведомлениями о завершении отправки.

## Лицензия

Этот проект распространяется под лицензией [MIT License](LICENSE).

## Контакты

Если у вас возникли вопросы или предложения, пожалуйста, свяжитесь с [your.email@example.com](mailto:your.email@example.com).
