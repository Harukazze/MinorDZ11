from __future__ import annotations

import os
from typing import Literal

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import httpx
from pydantic import BaseModel, Field

from dlp_filter import DlpMatch, RegexDlpFilter

from pathlib import Path
from fastapi.responses import FileResponse

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="Minimal DLP Chat API", version="0.1.0")

# Разрешаем локальный фронтенд (при необходимости сузьте allow_origins)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Инициализируем фильтр один раз при старте приложения
dlp_filter = RegexDlpFilter(
    forbidden_terms=["Проект Аврора", "ООО Ромашка", "Клиент-Х"]
)


class CheckRequest(BaseModel):
    text: str = Field(..., min_length=1)
    ignored_match_ids: list[str] = Field(default_factory=list)
    numbered_placeholders: bool = True


class DlpMatchOut(BaseModel):
    match_id: str
    rule_id: str
    label: str
    severity: Literal["low", "medium", "high"]
    start: int
    end: int
    value: str
    mask: str
    ignored: bool


class CheckResponse(BaseModel):
    matches: list[DlpMatchOut]
    redacted_text: str
    has_unhandled_high_risk: bool


class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant"]
    content: str


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1)
    history: list[ChatMessage] = Field(default_factory=list)
    ignored_match_ids: list[str] = Field(default_factory=list)
    allow_high_risk_override: bool = False


class ChatResponse(BaseModel):
    status: Literal["sent", "blocked"]
    reply: str | None = None
    sent_prompt: str | None = None
    matches: list[DlpMatchOut] = Field(default_factory=list)
    reason: str | None = None


def _serialize_matches(
        matches: list[DlpMatch], ignored_ids: set[str]
) -> list[DlpMatchOut]:
    return [
        DlpMatchOut(
            match_id=m.match_id,
            rule_id=m.rule_id,
            label=m.label,
            severity=m.severity,
            start=m.start,
            end=m.end,
            value=m.value,
            mask=m.mask,
            ignored=m.match_id in ignored_ids,
        )
        for m in matches
    ]


async def _call_llm(prompt: str, history: list[ChatMessage]) -> str:
    """
    Пример вызова OpenAI-совместимого HTTP API.
    Если LLM_API_URL / LLM_API_KEY не заданы, возвращает тестовый ответ,
    чтобы сервер можно было сразу проверить локально.
    """
    api_url = os.getenv("LLM_API_URL", "").strip()
    api_key = os.getenv("LLM_API_KEY", "").strip()
    model = os.getenv("LLM_MODEL", "gpt-4o-mini").strip()

    if not api_url or not api_key:
        return (
            "[MOCK LLM] Запрос принят после DLP-очистки. "
            f"Модель увидела текст: «{prompt}»"
        )

    messages = [{"role": m.role, "content": m.content} for m in history]
    messages.append({"role": "user", "content": prompt})

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": messages,
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(api_url, headers=headers, json=payload)
        resp.raise_for_status()
        data = resp.json()

    return data["choices"][0]["message"]["content"]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/dlp/check", response_model=CheckResponse)
def check_text(req: CheckRequest) -> CheckResponse:
    ignored_set = set(req.ignored_match_ids)
    redacted_text, matches = dlp_filter.redact(
        req.text,
        ignored_match_ids=ignored_set,
        numbered_placeholders=req.numbered_placeholders,
    )

    unhandled_high = any(
        m.severity == "high" and m.match_id not in ignored_set for m in matches
    )

    return CheckResponse(
        matches=_serialize_matches(matches, ignored_set),
        redacted_text=redacted_text,
        has_unhandled_high_risk=unhandled_high,
    )


@app.post("/api/chat", response_model=ChatResponse)
async def send_chat_message(req: ChatRequest) -> ChatResponse:
    ignored_set = set(req.ignored_match_ids)
    redacted_text, matches = dlp_filter.redact(
        req.message,
        ignored_match_ids=ignored_set,
        numbered_placeholders=True,
    )

    # Ищем high-совпадения, которые не были явно помечены как ignored
    unhandled_high = [
        m for m in matches if m.severity == "high" and m.match_id not in ignored_set
    ]

    # Если есть high-риски и нет явного разрешения на отправку после маскировки — блокируем
    if unhandled_high and not req.allow_high_risk_override:
        return ChatResponse(
            status="blocked",
            reason=(
                "Обнаружены данные высокого риска (high). "
                "Замаскируйте их, добавьте в ignored_match_ids или подтвердите отправку."
            ),
            matches=_serialize_matches(matches, ignored_set),
        )

    reply = await _call_llm(redacted_text, req.history)

    return ChatResponse(
        status="sent",
        reply=reply,
        sent_prompt=redacted_text,
        matches=_serialize_matches(matches, ignored_set),
    )

@app.get("/")
def index() -> FileResponse:
    return FileResponse(BASE_DIR / "index.html")
