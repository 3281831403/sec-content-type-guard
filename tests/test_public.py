from ctype.guard import allowed, ctype_batch, parse_ctype


def test_parse_quoted_parameter_semicolon():
    parsed = parse_ctype('text/plain; charset="utf-8"; note="a;b"')
    assert parsed["media"] == "text/plain"
    assert parsed["params"] == {"charset": "utf-8", "note": "a;b"}


def test_exact_type_match_not_prefix():
    assert allowed("text/plain-lookalike", ["text/plain"]) is False


def test_parameterized_type_matches_main_type():
    assert allowed("text/plain; charset=utf-8", ["text/plain"]) is True


def test_unknown_type_is_rejected():
    assert allowed("bogus", ["text/plain"]) is False


def test_batch_requests_are_independent():
    policy = {
        "allowlist": ["text/plain"],
        "allowed_params": ["charset", "boundary"],
        "required_params": [],
        "allow_empty_body": True,
        "on_missing": "reject",
    }
    batch = ctype_batch(
        [
            {"declared": "text/plain", "body": "first"},
            {"declared": "application/json", "body": "second"},
        ],
        policy,
    )
    assert [item["ok"] for item in batch["results"]] == [True, False]