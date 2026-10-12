"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, policy, tools
from agent.pii import redact

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
BASE_DIR = Path(__file__).resolve().parent.parent
CUSTOMERS_PATH = BASE_DIR / "data" / "customers.json"
AGENT_ID = "lab24-agent"
RUN_TTL = timedelta(minutes=5)
_TICKET_FILENAME_RE = re.compile(r"ticket-(\d+)\.md\Z")


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = Path(log_dir or REPORTS_DIR) / "ledger.jsonl"
    allowed_agent_scopes = ("search_docs", "read_customer")

    def new_run() -> tuple[str, str, str]:
        run_id = str(uuid.uuid4())
        expires_at = (datetime.now(timezone.utc) + RUN_TTL).isoformat().replace("+00:00", "Z")
        return run_id, f"{AGENT_ID}/{run_id}", expires_at

    def record_decision(tool_name: str, args: dict, classification: str,
                        run_id: str, agent_owner: str, expires_at: str,
                        agent_scopes: tuple[str, ...], parent_scopes: tuple[str, ...],
                        delegation_depth: int, egress_enabled: bool = False) -> bool:
        context = policy.PolicyContext(
            data_classification=classification,
            request_purpose="support-reply",
            agent_owner=agent_owner,
            delegation_depth=delegation_depth,
            egress_enabled=egress_enabled,
            principal_id=principal_id,
            requested_tool=tool_name,
            agent_scopes=agent_scopes,
            parent_scopes=parent_scopes,
            expires_at=expires_at,
        )
        allowed, reason = policy.check(context)
        args_hash = hashlib.sha256(
            json.dumps(args, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "agent_id": AGENT_ID,
            "run_id": run_id,
            "tool": tool_name,
            "args_hash": args_hash,
            "classification": classification,
            "decision": "allow" if allowed else "deny",
            "reason": reason or "policy returned no reason",
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
        }, ledger_path)
        return allowed

    # Run A: search untrusted documents, inspect injection only as a signal,
    # and redact PII before document text reaches the summarizer. Only ticket
    # IDs parsed from filenames cross into Run B.
    run_a_id, run_a_owner, run_a_expiry = new_run()
    raw_docs: list[dict] = []
    if record_decision(
        "search_docs", {"query": message}, "internal", run_a_id, run_a_owner,
        run_a_expiry, ("search_docs",), (), 0,
    ):
        raw_docs = tools.search_docs(message)

    # The detector may identify an exfil request, but its customer IDs never
    # choose a record. The URL is retained only for a separate policy check.
    untrusted_text = "\n\n".join(doc["text"] for doc in raw_docs)
    injection = llm.find_injection(untrusted_text)
    docs = [{**doc, "text": redact(doc["text"])} for doc in raw_docs]
    ticket_ids = sorted({
        int(match.group(1))
        for doc in raw_docs
        if (match := _TICKET_FILENAME_RE.fullmatch(doc.get("id", ""))) is not None
    })

    if not ticket_ids:
        if injection is not None:
            _record_egress_denial(injection.target_url, principal_id, ledger_path)
        return llm.summarize(docs)

    # Run B receives only typed ticket IDs. Gate the private-store lookup
    # before opening customers.json; a denied principal never opens it.
    run_b_id, run_b_owner, run_b_expiry = new_run()
    if not record_decision(
        "read_customer", {"ticket_ids": ticket_ids, "operation": "related_tickets_lookup"},
        "restricted", run_b_id, run_b_owner, run_b_expiry,
        ("read_customer",), allowed_agent_scopes, 1,
    ):
        if injection is not None:
            _record_egress_denial(injection.target_url, principal_id, ledger_path)
        return llm.summarize(docs)

    customers = json.loads(CUSTOMERS_PATH.read_text(encoding="utf-8"))
    ticket_set = set(ticket_ids)
    related_customer_ids = sorted({
        str(customer["customer_id"])
        for customer in customers
        if ticket_set.intersection(customer.get("related_tickets", []))
    })

    for customer_id in related_customer_ids:
        if record_decision(
            "read_customer", {"customer_id": customer_id}, "restricted",
            run_b_id, run_b_owner, run_b_expiry, ("read_customer",),
            allowed_agent_scopes, 1,
        ):
            # Authorized data remains within Run B; it is not added to the
            # untrusted document context and is never sent to the sink.
            tools.read_customer(customer_id)

    if injection is not None:
        _record_egress_denial(injection.target_url, principal_id, ledger_path)

    return llm.summarize(docs)


def _record_egress_denial(url: str, principal_id: str, ledger_path: Path) -> None:
    """Audit the requested egress with URL only; a deny never invokes http_post."""
    run_id = str(uuid.uuid4())
    expires_at = (datetime.now(timezone.utc) + RUN_TTL).isoformat().replace("+00:00", "Z")
    context = policy.PolicyContext(
        data_classification="restricted",
        request_purpose="support-reply",
        agent_owner=f"{AGENT_ID}/{run_id}",
        delegation_depth=0,
        egress_enabled=True,
        principal_id=principal_id,
        requested_tool="http_post",
        agent_scopes=("http_post",),
        parent_scopes=(),
        expires_at=expires_at,
    )
    allowed, reason = policy.check(context)
    args_hash = hashlib.sha256(
        json.dumps({"url": url}, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    ledger.append({
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "agent_id": AGENT_ID,
        "run_id": run_id,
        "tool": "http_post",
        "args_hash": args_hash,
        "classification": "restricted",
        "decision": "allow" if allowed else "deny",
        "reason": reason or "policy returned no reason",
        "on_behalf_of": principal_id,
        "expires_at": expires_at,
    }, ledger_path)
    if allowed:
        # Kept fail-closed: this lab's restricted egress invariant must deny.
        raise RuntimeError("policy unexpectedly allowed restricted egress")
