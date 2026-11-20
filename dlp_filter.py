from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Iterable, Literal

Severity = Literal["low", "medium", "high"]


@dataclass(frozen=True)
class DlpRule:
    rule_id: str
    label: str
    pattern: str
    mask: str
    severity: Severity = "medium"
    flags: int = re.IGNORECASE
    validator: str | None = None  # например, "luhn" или "inn"


@dataclass
class DlpMatch:
    match_id: str
    rule_id: str
    label: str
    severity: Severity
    start: int
    end: int
    value: str
    mask: str


def _is_valid_luhn(number_str: str) -> bool:
    digits = [int(ch) for ch in number_str if ch.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _is_valid_inn(inn_str: str) -> bool:
    digits = [int(ch) for ch in inn_str if ch.isdigit()]
    if len(digits) == 10:
        weights = (2, 4, 10, 3, 5, 9, 4, 6, 8)
        ctrl = sum(w * d for w, d in zip(weights, digits[:9])) % 11 % 10
        return ctrl == digits[9]
    if len(digits) == 12:
        w11 = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
        w12 = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
        c11 = sum(w * d for w, d in zip(w11, digits[:10])) % 11 % 10
        c12 = sum(w * d for w, d in zip(w12, digits[:11])) % 11 % 10
        return c11 == digits[10] and c12 == digits[11]
    return False


def _passes_validator(validator_name: str | None, value: str) -> bool:
    if validator_name is None:
        return True
    if validator_name == "luhn":
        return _is_valid_luhn(value)
    if validator_name == "inn":
        return _is_valid_inn(value)
    return True


DEFAULT_RULES: list[DlpRule] = [
    DlpRule(
        rule_id="api_key",
        label="API-ключ / токен",
        severity="high",
        pattern=r"(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16})",
        mask="<API_KEY>",
        flags=0,
    ),
    DlpRule(
        rule_id="email",
        label="Email",
        severity="medium",
        pattern=r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        mask="<EMAIL>",
    ),
    DlpRule(
        rule_id="ru_phone",
        label="Телефон",
        severity="medium",
        pattern=r"(?:\+7|8)[\s\-\(]*\d{3}[\s\-\)]*\d{3}[\s\-\-]*\d{2}[\s\-\-]*\d{2}",
        mask="<PHONE>",
    ),
    DlpRule(
        rule_id="card_pan",
        label="Номер карты",
        severity="high",
        pattern=r"(?<!\d)(?:\d{4}[\s\-]?){3}\d{4}(?!\d)",
        mask="<CARD>",
        validator="luhn",
    ),
    DlpRule(
        rule_id="inn",
        label="ИНН",
        severity="high",
        pattern=r"(?<!\d)(?:\d{10}|\d{12})(?!\d)",
        mask="<INN>",
        validator="inn",
    ),
]


@dataclass
class RegexDlpFilter:
    rules: list[DlpRule] = field(default_factory=lambda: list(DEFAULT_RULES))
    forbidden_terms: list[str] = field(default_factory=list)

    def _build_all_rules(self) -> list[DlpRule]:
        all_rules = list(self.rules)
        cleaned_terms = sorted(
            {t.strip() for t in self.forbidden_terms if t and t.strip()},
            key=len,
            reverse=True,
        )
        if cleaned_terms:
            escaped = "|".join(re.escape(term) for term in cleaned_terms)
            # Границы для кириллицы и латиницы: не буква/цифра/подчёркивание вокруг термина
            term_pattern = (
                rf"(?<![А-Яа-яЁёA-Za-z0-9_])(?:{escaped})(?![А-Яа-яЁёA-Za-z0-9_])"
            )
            all_rules.append(
                DlpRule(
                    rule_id="forbidden_term",
                    label="Запрещённый термин / проект",
                    severity="high",
                    pattern=term_pattern,
                    mask="<SECRET_TERM>",
                    flags=re.IGNORECASE,
                )
            )
        return all_rules

    def scan(self, text: str) -> list[DlpMatch]:
        raw_matches: list[DlpMatch] = []

        for rule in self._build_all_rules():
            for m in re.finditer(rule.pattern, text, flags=rule.flags):
                val = m.group(0)
                if not _passes_validator(rule.validator, val):
                    continue
                raw_matches.append(
                    DlpMatch(
                        match_id="",
                        rule_id=rule.rule_id,
                        label=rule.label,
                        severity=rule.severity,
                        start=m.start(),
                        end=m.end(),
                        value=val,
                        mask=rule.mask,
                    )
                )

        # Сначала более ранние совпадения, при равном start — более длинные
        raw_matches.sort(key=lambda item: (item.start, -(item.end - item.start)))

        # Убираем перекрывающиеся совпадения, чтобы индексы не конфликтовали
        resolved: list[DlpMatch] = []
        last_end = -1
        for item in raw_matches:
            if item.start < last_end:
                continue
            resolved.append(item)
            last_end = item.end

        # Присваиваем стабильный ID на основе позиции и правила
        for idx, item in enumerate(resolved, start=1):
            item.match_id = f"{item.rule_id}:{item.start}:{item.end}#{idx}"

        return resolved

    def redact(
        self,
        text: str,
        ignored_match_ids: Iterable[str] = (),
        numbered_placeholders: bool = True,
    ) -> tuple[str, list[DlpMatch]]:
        ignored_set = set(ignored_match_ids)
        matches = self.scan(text)
        active_matches = [m for m in matches if m.match_id not in ignored_set]

        if not active_matches:
            return text, matches

        counters: dict[str, int] = {}
        parts: list[str] = []
        cursor = 0

        for m in active_matches:
            parts.append(text[cursor : m.start])
            if numbered_placeholders:
                counters[m.mask] = counters.get(m.mask, 0) + 1
                base = m.mask.rstrip(">")
                placeholder = f"{base}_{counters[m.mask]}>"
            else:
                placeholder = m.mask
            parts.append(placeholder)
            cursor = m.end

        parts.append(text[cursor:])
        return "".join(parts), matches


if __name__ == "__main__":
    dlp = RegexDlpFilter(
        forbidden_terms=["Проект Аврора", "ООО Ромашка", "Клиент-Х"]
    )

    sample_prompt = (
        "Привет! Помоги написать письмо для ООО Ромашка по теме Проект Аврора. "
        "Контакт: ivan.petrov@example.com, тел +7 (999) 123-45-67. "
        "Ключ теста: sk-1234567890abcdefghijklmnop. Обычное число 1234567890 не должно считаться ИНН."
    )

    matches = dlp.scan(sample_prompt)
    print("Найдено совпадений:", len(matches))
    for item in matches:
        print(
            f"  - [{item.severity.upper()}] {item.label}: '{item.value}' "
            f"({item.start}..{item.end}) -> {item.mask}"
        )

    clean_text, _ = dlp.redact(sample_prompt)
    print("\nОбезличенный промпт для LLM:\n", clean_text)

    # Пример игнорирования конкретного срабатывания (например, email оставляем)
    email_ids = [item.match_id for item in matches if item.rule_id == "email"]
    partially_clean, _ = dlp.redact(sample_prompt, ignored_match_ids=email_ids)
    print("\nС разрешённым email:\n", partially_clean)