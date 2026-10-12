"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re


_EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+(?![\w-])"
)
_LABELED_ACCOUNT_RE = re.compile(
    r"(?i)(?:\bSTK\b|số\s+tài\s+khoản)\s*[:#-]?\s*"
    r"(?P<number>\d{8,16})(?!\d)"
)
_CCCD_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
_PHONE_RE = re.compile(r"(?<!\d)0(?:[ .-]?\d){9,10}(?!\d)")
_ACCOUNT_RE = re.compile(r"(?<!\d)\d{8,16}(?!\d)")


def _entity(kind: str, start: int, end: int) -> dict:
    return {"type": kind, "start": start, "end": end}


def detect(text: str) -> list[dict]:
    # More specific signals win: a labeled account is an account even when
    # its length also matches CCCD/phone, while unlabeled numeric overlaps
    # prefer CCCD and then phone over a generic account number.
    candidates: list[dict] = []

    def add_matches(kind: str, pattern: re.Pattern, priority: int, group: str | None = None):
        for match in pattern.finditer(text):
            start, end = (match.span(group) if group else match.span())
            candidates.append({**_entity(kind, start, end), "_priority": priority})

    add_matches("EMAIL", _EMAIL_RE, 0)
    add_matches("VN_BANK_ACCOUNT", _LABELED_ACCOUNT_RE, 1, "number")
    add_matches("VN_CCCD", _CCCD_RE, 2)
    add_matches("VN_PHONE", _PHONE_RE, 3)
    add_matches("VN_BANK_ACCOUNT", _ACCOUNT_RE, 4)

    selected: list[dict] = []
    for candidate in sorted(
        candidates,
        key=lambda item: (
            item["_priority"],
            item["start"],
            -(item["end"] - item["start"]),
        ),
    ):
        if any(
            candidate["start"] < existing["end"]
            and existing["start"] < candidate["end"]
            for existing in selected
        ):
            continue
        candidate.pop("_priority")
        selected.append(candidate)

    return sorted(selected, key=lambda item: (item["start"], item["end"]))


def redact(text: str) -> str:
    result = text
    for entity in sorted(detect(text), key=lambda item: item["start"], reverse=True):
        replacement = f"[REDACTED_{entity['type']}]"
        result = result[: entity["start"]] + replacement + result[entity["end"] :]
    return result
