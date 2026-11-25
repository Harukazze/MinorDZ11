# DLP Веб-чат (прототип на FastAPI и RegEx)

Небольшой веб-чат с интерактивным DLP-фильтром на базе регулярных выражений и проверок контрольных сумм. Позволяет проверять текст на утечки (API-ключи, email, телефоны, номера карт, ИНН, запрещённые термины/проекты), подсвечивать совпадения, маскировать их перед отправкой и отправлять запрос в LLM API (или в локальный mock-режим).

## Структура проекта

```text
dlp_chat_server/
├── dlp_filter.py     # Логика RegEx-поиска, валидации и маскирования
├── main.py           # Сервер FastAPI и эндпоинты /api/dlp/check и /api/chat
├── index.html        # Простой веб-интерфейс с подсветкой и чатом
├── requirements.txt  # Зависимости Python
└── README.md
```

## Установка и запуск

1. Перейдите в папку проекта:
   ```bash
   cd dlp_chat_server
   ```

2. Создайте и активируйте виртуальное окружение:
   * **Windows (PowerShell):**
     ```powershell
     python -m venv .venv
     .\.venv\Scripts\Activate.ps1
     ```
   * **Linux / macOS / WSL:**
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

3. Установите зависимости:
   ```bash
   pip install -r requirements.txt
   ```

4. Запустите сервер:
   ```bash
   uvicorn main:app --reload --port 8000
   ```

Сервер будет доступен по адресу `http://localhost:8000`.

### Переменные окружения для реального LLM API (опционально)

По умолчанию, если переменные не заданы, `/api/chat` работает в режиме заглушки (`[MOCK LLM]`) и возвращает текст промпта после DLP-очистки. Чтобы подключить OpenAI-совместимый API, задайте переменные перед запуском:

* **Windows (PowerShell):**
  ```powershell
  $env:LLM_API_URL = "[https://api.openai.com/v1/chat/completions](https://api.openai.com/v1/chat/completions)"
  $env:LLM_API_KEY = "ваш_api_ключ"
  $env:LLM_MODEL = "gpt-4o-mini"
  uvicorn main:app --reload --port 8000
  ```
* **Linux / macOS / WSL:**
  ```bash
  export LLM_API_URL="[https://api.openai.com/v1/chat/completions](https://api.openai.com/v1/chat/completions)"
  export LLM_API_KEY="ваш_api_ключ"
  export LLM_MODEL="gpt-4o-mini"
  uvicorn main:app --reload --port 8000
  ```

## Как проверить работу

### 1. Через веб-интерфейс (проще всего)
1. Откройте в браузере `http://localhost:8000/`.
2. Введите тестовый текст, например:
   ```text
   Скинь отчёт по проекту Проект Аврора, почта test@example.com, ключ sk-1234567890abcdefghijklmnop
   ```
3. Нажмите **«Проверить текст»** — появятся подсветка совпадений, предпросмотр маскировки и список найденных правил с кнопкой **«Игнорировать»**.
4. Нажмите **«Подставить замаскированный текст»** или **«Отправить в чат»**, чтобы проверить отправку сообщения и ответ в окне истории.

### 2. Через Swagger UI
Откройте `http://localhost:8000/docs` и протестируйте `POST /api/dlp/check` и `POST /api/chat` прямо в браузере.

### 3. Через API-запросы

* **Linux / macOS / WSL (`curl`):**
  ```bash
  curl -X POST http://localhost:8000/api/dlp/check \
    -H "Content-Type: application/json" \
    -d '{"text": "Скинь отчёт по проекту Проект Аврора, почта test@example.com"}'
  ```

* **Windows (PowerShell):**
  ```powershell
  $body = @{ text = "Скинь отчёт по проекту Проект Аврора, почта test@example.com" } | ConvertTo-Json
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)$resp = Invoke-WebRequest -Uri "http://localhost:8000/api/dlp/check" `
    -Method Post `
    -ContentType "application/json; charset=utf-8" `
    -Body $bytes
  [System.Text.Encoding]::UTF8.GetString($resp.RawContentStream.ToArray()) | ConvertFrom-Json | ConvertTo-Json -Depth 5
  ```

### 4. Быстрый тест самого фильтра в консоли
```bash
python dlp_filter.py
```