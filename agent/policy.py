"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


_VALID_CLASSIFICATIONS = {"public", "internal", "restricted"}
_PRINCIPALS_PATH = Path(__file__).resolve().parent.parent / "data" / "principals.json"


def check(context: PolicyContext) -> tuple[bool, str]:
    classification = context.data_classification
    if classification not in _VALID_CLASSIFICATIONS:
        return False, f"unknown data classification: {classification!r}"

    # This invariant applies to every principal, including DPO.
    if classification == "restricted" and context.egress_enabled is True:
        return False, "restricted data cannot be used while egress is enabled"

    if not isinstance(context.egress_enabled, bool):
        return False, "egress_enabled must be a boolean"
    if not context.agent_owner.strip():
        return False, "agent owner is required"
    if not isinstance(context.delegation_depth, int) or context.delegation_depth < 0:
        return False, "delegation depth must be a non-negative integer"
    if not context.request_purpose.strip():
        return False, "request purpose is required"
    if not context.requested_tool.strip():
        return False, "requested tool is required"

    try:
        raw_principals = json.loads(_PRINCIPALS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, f"principal registry unavailable: {type(exc).__name__}"

    principal = raw_principals.get(context.principal_id)
    if not isinstance(principal, dict):
        return False, f"unknown principal: {context.principal_id!r}"
    if context.request_purpose not in principal.get("purposes", []):
        return False, f"principal {context.principal_id!r} is not authorized for purpose {context.request_purpose!r}"

    allowed_tools = principal.get("allowed_tools", [])
    if context.requested_tool not in allowed_tools:
        return False, f"principal {context.principal_id!r} is not authorized for tool {context.requested_tool!r}"
    if context.requested_tool not in context.agent_scopes:
        return False, f"agent scope does not include tool {context.requested_tool!r}"
    if context.delegation_depth > 0 and context.requested_tool not in context.parent_scopes:
        return False, f"parent scope does not include delegated tool {context.requested_tool!r}"

    if context.requested_tool == "http_post" and not context.egress_enabled:
        return False, "egress is disabled for http_post"

    try:
        expires_at = datetime.fromisoformat(context.expires_at.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        return False, "expires_at must be a valid UTC ISO-8601 timestamp"
    if expires_at.tzinfo is None or expires_at.utcoffset() != timezone.utc.utcoffset(expires_at):
        return False, "expires_at must include a UTC timezone"
    if expires_at <= datetime.now(timezone.utc):
        return False, "delegation has expired"

    return True, (
        f"allowed: principal {context.principal_id!r} may call "
        f"{context.requested_tool!r} for {context.request_purpose!r}"
    )
