# themes.py

THEMES = {
    "Светлая": """
        QWidget { background-color: #ffffff; color: #000000; }
        QLineEdit, QTextEdit { background-color: #f0f0f0; }
        QPushButton { background-color: #e0e0e0; }
        QTabWidget::pane { border: 1px solid #cccccc; }
    """,
    "Тёмная": """
        QWidget { background-color: #2b2b2b; color: #ffffff; }
        QLineEdit, QTextEdit { background-color: #3c3f41; }
        QPushButton { background-color: #4a4a4a; }
        QTabWidget::pane { border: 1px solid #555555; }
    """,
    "Синяя": """
        QWidget { background-color: #E6F7FF; color: #003366; }
        QLineEdit, QTextEdit { background-color: #F0F8FF; }
        QPushButton { background-color: #B3E5FC; }
        QTabWidget::pane { border: 1px solid #90CAF9; }
    """,
    "Зелёная": """
        QWidget { background-color: #E8F5E9; color: #1B5E20; }
        QLineEdit, QTextEdit { background-color: #F1F8E9; }
        QPushButton { background-color: #A5D6A7; }
        QTabWidget::pane { border: 1px solid #66BB6A; }
    """,
    "Классическая": """
        QWidget { background-color: #F5F5F5; color: #212121; }
        QLineEdit, QTextEdit { background-color: #FFFFFF; }
        QPushButton { background-color: #E0E0E0; }
        QTabWidget::pane { border: 1px solid #BDBDBD; }
    """
}

def get_theme(theme_name):
    """Возвращает строку стилей для заданной темы."""
    return THEMES.get(theme_name, "")
