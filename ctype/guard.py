"""Strict content type guard used before routing a request to a handler."""

from __future__ import annotations

import re
from typing import Any

# RFC 7230 token characters.
_TOKEN_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+-.^_`|~]+$")
_VALUE_RE = re.compile(r"^[\x21-\x7e]+$")
_MISSING_POLICIES = frozenset({"reject", "deny"})
_SEQUENCES = (list, tuple, set, frozenset)


def _split_unquoted(value: str, separator: str) -> list[str]:
    """Split on separator characters that are outside quoted strings.

    Quoted strings (RFC 7230 quoted-string) are kept intact, including
    separator characters embedded in them. Backslash escapes are honored.
    """
    parts: list[str] = []
    current: list[str] = []
    in_quotes = False
    escaped = False
    for ch in value:
        if escaped:
            current.append(ch)
            escaped = False
            continue
        if ch == "\\":
            current.append(ch)
            escaped = True
            continue
        if ch == '"':
            in_quotes = not in_quotes
            current.append(ch)
            continue
        if ch == separator and not in_quotes:
            parts.append("".join(current))
            current = []
            continue
        current.append(ch)
    parts.append("".join(current))
    return parts


def _unquote(raw_value: str) -> tuple[str, bool]:
    """Remove quotes from a parameter value and unescape quoted pairs.

    Returns ``(text, ok)``; ``ok`` is False when the quoting is malformed.
    """
    if raw_value.startswith('"'):
        if len(raw_value) < 2 or not raw_value.endswith('"'):
            return "", False
        result: list[str] = []
        escaped = False
        for ch in raw_value[1:-1]:
            if escaped:
                result.append(ch)
                escaped = False
            elif ch == "\\":
                escaped = True
            else:
                result.append(ch)
        if escaped:
            return "", False
        return "".join(result), True
    if '"' in raw_value:
        return "", False
    return raw_value, True


def parse_ctype(value: Any) -> dict:
    """Parse a Content-Type value into media, parameters, and validity."""
    if not isinstance(value, str) or not value.strip():
        return {"media": "", "params": {}, "valid": False}
    parts = _split_unquoted(value.strip(), ";")
    media = parts[0].strip()
    if not media or media.count("/") != 1:
        return {"media": media, "params": {}, "valid": False}
    main, subtype = (part.strip() for part in media.split("/", 1))
    if not _TOKEN_RE.fullmatch(main) or not _TOKEN_RE.fullmatch(subtype):
        return {"media": media, "params": {}, "valid": False}
    params: dict[str, str] = {}
    valid = True
    for raw in parts[1:]:
        item = raw.strip()
        if not item or "=" not in item:
            # Malformed parameter segment (empty segment or missing "=").
            valid = False
            continue
        name, raw_value = item.split("=", 1)
        name = name.strip().lower()
        raw_value = raw_value.strip()
        if not name or not _TOKEN_RE.fullmatch(name):
            valid = False
            continue
        value_text, ok = _unquote(raw_value)
        if not ok or not value_text:
            valid = False
            continue
        params[name] = value_text
    return {"media": media, "params": params, "valid": valid}


def normalize_type(media: Any) -> str:
    """Return a canonical media type consisting of main type and subtype.

    Parameters are stripped; comparison only ever uses main type/subtype.
    Returns an empty string for anything that is not a well-formed media type.
    """
    if not isinstance(media, str):
        return ""
    value = media.split(";", 1)[0].strip()
    if value.count("/") != 1:
        return ""
    main, subtype = (part.strip().lower() for part in value.split("/", 1))
    if not _TOKEN_RE.fullmatch(main) or not _TOKEN_RE.fullmatch(subtype):
        return ""
    return f"{main}/{subtype}"


def allowed(media: Any, allowlist: Any) -> bool:
    """Return True when media strictly matches an allowlist entry.

    Only the main type and subtype are compared; parameters on either side
    are ignored. Unknown or malformed types are always rejected.
    """
    candidate = normalize_type(media)
    if not candidate:
        return False
    entries = allowlist if isinstance(allowlist, _SEQUENCES) else []
    for entry in entries:
        if not isinstance(entry, str):
            continue
        allowed_media = normalize_type(entry)
        if allowed_media and candidate == allowed_media:
            return True
    return False


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
    """Enforce the body presence rules configured by the policy.

    Empty bodies (including an empty chunk list from chunked transfer) are
    accepted only when the policy explicitly allows them. A chunked body
    with chunks is a present body; transfer encoding never changes the
    content-type decision itself.
    """
    if not isinstance(policy, dict):
        return False
    empty = body is None or (
        isinstance(body, (str, bytes, bytearray, list, tuple, dict)) and len(body) == 0
    )
    if empty:
        return bool(policy.get("allow_empty", True))
    return True


def check_declared(declared: Any, actual: Any) -> bool:
    """Check that the declared media type agrees with the observed type.

    Compares the full main type and subtype (parameters ignored). Any
    malformed side is treated as a mismatch and rejected.
    """
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
    if policy.get("on_missing") not in _MISSING_POLICIES:
        issues.append("missing content type must be rejected")
    return issues


def ctype_batch(requests: Any, policy: Any) -> dict:
    """Validate a batch of requests, returning one result per request.

    Each request is parsed and judged independently with no shared state,
    so the same request always yields the same decision, regardless of
    position or neighboring requests.
    """
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
    for index, request in enumerate(items):
        if not isinstance(request, dict):
            results.append(
                {"index": index, "ok": False, "reason": "request must be an object"}
            )
            continue
        declared = request.get("declared")
        if not isinstance(declared, str) or not declared.strip():
            # Missing content type: reject instead of guessing one.
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
