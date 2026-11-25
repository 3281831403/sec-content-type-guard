"""Strict content type guard used before routing a request to a handler."""

from __future__ import annotations

import re
from typing import Any

_TOKEN_RE = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+$")
_VALUE_RE = re.compile(r"^[\x21-\x7e]+$")
_MISSING_POLICIES = frozenset({"reject", "deny"})
_SEQUENCE_TYPES = (list, tuple, set, frozenset)


def _split_unquoted(value: str, separator: str) -> list[str]:
    """Split on separator characters that are outside quoted strings.

    Backslash escapes inside quoted strings are preserved (not interpreted) so
    the caller can unquote each value once.  An unterminated quoted string is a
    hard error: the value cannot be split reliably any more.
    """
    parts: list[str] = []
    buffer: list[str] = []
    in_quotes = False
    escaped = False
    for char in value:
        if escaped:
            buffer.append(char)
            escaped = False
            continue
        if in_quotes and char == "\\":
            buffer.append(char)
            escaped = True
            continue
        if char == '"':
            in_quotes = not in_quotes
            buffer.append(char)
            continue
        if char == separator and not in_quotes:
            parts.append("".join(buffer))
            buffer = []
            continue
        buffer.append(char)
    if in_quotes or escaped:
        raise ValueError("unterminated quoted parameter")
    parts.append("".join(buffer))
    return parts


def _unquote(raw: str) -> str | None:
    """Return the parameter value, stripping one layer of quotes.

    ``None`` means the value is malformed (dangling quote or escape).
    """
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        inner = raw[1:-1]
        result: list[str] = []
        escaped = False
        for char in inner:
            if escaped:
                result.append(char)
                escaped = False
            elif char == "\\":
                escaped = True
            else:
                result.append(char)
        if escaped:
            return None
        return "".join(result)
    if '"' in raw:
        return None
    return raw


def parse_ctype(value: Any) -> dict:
    """Parse a Content-Type value into media, parameters, and validity."""
    if not isinstance(value, str) or not value.strip():
        return {"media": "", "params": {}, "valid": False}
    try:
        parts = _split_unquoted(value.strip(), ";")
    except ValueError:
        return {"media": "", "params": {}, "valid": False}
    media = parts[0].strip()
    if not media or media.count("/") != 1:
        return {"media": media, "params": {}, "valid": False}
    main, subtype = media.split("/", 1)
    main = main.strip()
    subtype = subtype.strip()
    if not _TOKEN_RE.fullmatch(main) or not _TOKEN_RE.fullmatch(subtype):
        return {"media": media, "params": {}, "valid": False}
    params: dict[str, str] = {}
    for raw in parts[1:]:
        item = raw.strip()
        if not item:
            continue
        if "=" not in item:
            return {"media": media, "params": params, "valid": False}
        name, raw_value = item.split("=", 1)
        name = name.strip()
        raw_value = raw_value.strip()
        if not name or not _TOKEN_RE.fullmatch(name):
            return {"media": media, "params": params, "valid": False}
        key = name.lower()
        if key in params:
            return {"media": media, "params": params, "valid": False}
        value_text = _unquote(raw_value)
        if value_text is None or not value_text:
            return {"media": media, "params": params, "valid": False}
        params[key] = value_text
    return {"media": media, "params": params, "valid": True}


def normalize_type(media: Any) -> str:
    """Return a canonical ``main/subtype`` pair, discarding parameters.

    Returns the empty string for anything that is not a concrete media type
    (missing, malformed, wildcarded, or with invalid token characters).
    """
    if not isinstance(media, str):
        return ""
    value = media.strip()
    if not value:
        return ""
    try:
        parts = _split_unquoted(value, ";")
    except ValueError:
        return ""
    media_part = parts[0].strip()
    if media_part.count("/") != 1:
        return ""
    main, subtype = media_part.split("/", 1)
    main = main.strip().lower()
    subtype = subtype.strip().lower()
    if not _TOKEN_RE.fullmatch(main) or not _TOKEN_RE.fullmatch(subtype):
        return ""
    return f"{main}/{subtype}"


def allowed(media: Any, allowlist: Any) -> bool:
    """Return True only when media exactly matches an allowlist entry.

    Parameters never participate in the comparison: ``text/plain; charset=x``
    matches the ``text/plain`` entry.  Everything unknown, malformed, missing,
    or merely sharing a prefix is rejected.
    """
    candidate = normalize_type(media)
    if not candidate:
        return False
    if not isinstance(allowlist, _SEQUENCE_TYPES):
        return False
    for entry in allowlist:
        if isinstance(entry, str) and normalize_type(entry) == candidate:
            return True
    return False


def check_params(params: Any, policy: Any) -> bool:
    """Validate parameter names and values against the policy."""
    if not isinstance(params, dict) or not isinstance(policy, dict):
        return False
    allowed_names = policy.get("allowed_params")
    if allowed_names is not None:
        if not isinstance(allowed_names, _SEQUENCE_TYPES):
            return False
        names = {str(item).lower() for item in allowed_names}
        if any(str(name).lower() not in names for name in params):
            return False
    required_raw = policy.get("required_params", ())
    if required_raw is None:
        required_raw = ()
    if not isinstance(required_raw, _SEQUENCE_TYPES):
        return False
    required = {str(item).lower() for item in required_raw}
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
        isinstance(body, (str, bytes, bytearray, memoryview)) and len(body) == 0
    )
    if not empty:
        return True
    flag = policy.get("allow_empty_body", policy.get("allow_empty", True))
    return bool(flag)


def check_declared(declared: Any, actual: Any) -> bool:
    """Check that the declared media type agrees with the observed type.

    The full main type and subtype must agree; parameters are ignored.  When no
    observed type is available there is nothing to contradict, but any observed
    type that cannot be parsed is treated as a mismatch.
    """
    if actual is None:
        return True
    if declared is None:
        return False
    declared_type = normalize_type(declared)
    actual_type = normalize_type(actual)
    if not declared_type or not actual_type:
        return False
    return declared_type == actual_type


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
                elif not normalize_type(entry):
                    issues.append("allowlist entries must be concrete media types")
    for key in ("allowed_params", "required_params"):
        value = policy.get(key)
        if value is not None:
            if not isinstance(value, _SEQUENCE_TYPES):
                issues.append(f"{key} must be a sequence")
            else:
                for item in value:
                    if not isinstance(item, str) or not item.strip():
                        issues.append(f"{key} entries must be non-empty strings")
    allow_empty = policy.get("allow_empty_body", policy.get("allow_empty"))
    if allow_empty is not None and not isinstance(allow_empty, bool):
        issues.append("allow_empty_body must be a boolean")
    if policy.get("on_missing") not in _MISSING_POLICIES:
        issues.append("missing content type must be rejected")
    return issues


def ctype_batch(requests: Any, policy: Any) -> dict:
    """Validate a batch of requests, returning one result per request.

    Every request is evaluated independently: parsing state is never reused
    between entries, and transport details such as chunked encoding do not
    influence the outcome.
    """
    items = list(requests) if isinstance(requests, (list, tuple)) else None
    issues = validate_policy(policy)
    if issues:
        return {
            "ok": False,
            "count": len(items) if items is not None else 0,
            "results": [],
            "policy_issues": issues,
        }
    if items is None:
        return {
            "ok": False,
            "count": 0,
            "results": [],
            "policy_issues": ["requests must be a sequence"],
        }
    results: list[dict] = []
    for index, request in enumerate(items):
        if not isinstance(request, dict):
            results.append(
                {"index": index, "ok": False, "reason": "request must be an object"}
            )
            continue
        declared = request.get("declared")
        if declared is None or (isinstance(declared, str) and not declared.strip()):
            results.append(
                {"index": index, "ok": False, "reason": "missing content type"}
            )
            continue
        parsed = parse_ctype(declared)
        if not parsed["valid"]:
            results.append(
                {"index": index, "ok": False, "reason": "invalid content type"}
            )
            continue
        if not allowed(parsed["media"], policy.get("allowlist", [])):
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
        if not check_declared(declared, request.get("actual")):
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
