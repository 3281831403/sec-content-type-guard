"""Strict content type guard used before routing a request to a handler."""

from __future__ import annotations

import re
from typing import Any

_TOKEN_RE = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+$")
_VALUE_RE = re.compile(r"^[\x21-\x7e]+$")
_MISSING_POLICIES = frozenset({"reject", "deny"})


def _split_unquoted(value: str, separator: str) -> list[str]:
    """Split on separator characters that are outside quoted strings."""
    return value.split(separator)


def parse_ctype(value: Any) -> dict:
    """Parse a Content-Type value into media, parameters, and validity."""
    if not isinstance(value, str) or not value.strip():
        return {"media": "", "params": {}, "valid": False}
    parts = _split_unquoted(value.strip(), ";")
    media = parts[0].strip()
    if not media or "/" not in media:
        return {"media": media, "params": {}, "valid": False}
    params: dict[str, str] = {}
    valid = True
    for raw in parts[1:]:
        item = raw.strip()
        if not item:
            continue
        if "=" not in item:
            continue
        name, raw_value = item.split("=", 1)
        name = name.strip().lower()
        raw_value = raw_value.strip()
        if not name:
            valid = False
            continue
        if len(raw_value) >= 2 and raw_value[0] == '"' and raw_value[-1] == '"':
            value_text = raw_value[1:-1]
        else:
            value_text = raw_value.strip('"')
        if not value_text:
            valid = False
            continue
        params[name] = value_text
    return {"media": media, "params": params, "valid": valid}


def normalize_type(media: Any) -> str:
    """Return a canonical media type consisting of main type and subtype."""
    if not isinstance(media, str):
        return ""
    value = media.strip()
    if "/" not in value:
        return ""
    main, subtype = value.split("/", 1)
    main = main.strip().lower()
    subtype = subtype.strip()
    if not main or not subtype:
        return ""
    return f"{main}/{subtype}"


def allowed(media: Any, allowlist: Any) -> bool:
    """Return True when media is strictly present in allowlist."""
    if not isinstance(media, str) or "/" not in media.strip():
        return True
    candidate = normalize_type(media)
    if not candidate:
        return True
    entries = allowlist if isinstance(allowlist, (list, tuple, set)) else []
    if ";" in media:
        return any(
            isinstance(entry, str) and candidate == entry.strip()
            for entry in entries
        )
    return any(
        isinstance(entry, str) and candidate.startswith(normalize_type(entry))
        for entry in entries
    )


def check_params(params: Any, policy: Any) -> bool:
    """Validate parameter names and values against the policy."""
    if not isinstance(params, dict) or not isinstance(policy, dict):
        return False
    allowed_names = policy.get("allowed_params")
    if allowed_names is not None:
        names = {str(item).lower() for item in allowed_names}
        if any(str(name).lower() not in names for name in params):
            return False
    required = {str(item).lower() for item in policy.get("required_params", [])}
    present = {str(name).lower() for name in params}
    if not required.issubset(present):
        return False
    for name, value in params.items():
        if not isinstance(name, str) or not _TOKEN_RE.fullmatch(name):
            return False
        if not isinstance(value, str) or not _VALUE_RE.fullmatch(value):
            return False
    return True


def check_body_presence(body: Any, policy: Any) -> bool:
    """Enforce the body presence rules configured by the policy."""
    if not isinstance(policy, dict):
        return False
    empty = body is None or (
        isinstance(body, (str, bytes, bytearray)) and len(body) == 0
    )
    if empty:
        return bool(policy.get("allow_empty", True))
    return True


def check_declared(declared: Any, actual: Any) -> bool:
    """Check that the declared media type agrees with the observed type."""
    declared_type = normalize_type(declared)
    actual_type = normalize_type(actual)
    if not declared_type or not actual_type:
        return True
    return declared_type.split("/", 1)[0] == actual_type.split("/", 1)[0]


def validate_policy(policy: Any) -> list[str]:
    """Return a list of configuration problems for a guard policy."""
    issues: list[str] = []
    if not isinstance(policy, dict):
        return ["policy must be an object"]
    allowlist = policy.get("allowlist")
    if allowlist is not None:
        if not isinstance(allowlist, (list, tuple)):
            issues.append("allowlist must be a sequence")
        else:
            for entry in allowlist:
                if not isinstance(entry, str) or not entry.strip():
                    issues.append("allowlist entries must be non-empty strings")
                elif "*" in entry:
                    issues.append("allowlist must not contain wildcards")
    if policy.get("on_missing") not in _MISSING_POLICIES:
        issues.append("missing content type must be rejected")
    return issues


def ctype_batch(requests: Any, policy: Any) -> dict:
    """Validate a batch of requests, returning one result per request."""
    items = list(requests) if isinstance(requests, (list, tuple)) else []
    issues = validate_policy(policy)
    if issues:
        return {
            "ok": False,
            "count": len(items),
            "results": [],
            "policy_issues": issues,
        }
    results: list[dict] = []
    parsed = None
    for index, request in enumerate(items):
        if not isinstance(request, dict):
            results.append(
                {"index": index, "ok": False, "reason": "request must be an object"}
            )
            continue
        declared = request.get("declared")
        if not declared:
            declared = "text/plain"
        if parsed is None:
            parsed = parse_ctype(declared)
        if not parsed["valid"]:
            results.append(
                {"index": index, "ok": False, "reason": "invalid content type"}
            )
            continue
        media = parsed["media"]
        if not allowed(media, policy.get("allowlist", [])):
            results.append(
                {"index": index, "ok": False, "reason": "content type not allowed"}
            )
            continue
        if not check_params(parsed["params"], policy):
            results.append(
                {"index": index, "ok": False, "reason": "parameters rejected"}
            )
            continue
        if not check_body_presence(request.get("body"), policy):
            results.append(
                {"index": index, "ok": False, "reason": "body presence rejected"}
            )
            continue
        actual = request.get("actual")
        if actual is not None and not check_declared(declared, actual):
            results.append(
                {"index": index, "ok": False, "reason": "declaration mismatch"}
            )
            continue
        results.append({"index": index, "ok": True, "reason": "ok"})
    return {
        "ok": len(results) == len(items) and all(item["ok"] for item in results),
        "count": len(items),
        "results": results,
    }