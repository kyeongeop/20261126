from app.main import build_redactor
from app.redaction import ContextException, Redactor, RegexRule


def test_regex_rule_redacts_hostname(redactor):
    result = redactor.redact({"msg": "alert on web-01.prod.internal"})
    assert "web-01.prod.internal" not in result.data["msg"]
    assert result.counts["internal-hostname"] == 1


def test_match_exception_keeps_public_status_host(redactor):
    result = redactor.redact({"msg": "see status.prod.internal for updates"})
    assert result.data["msg"] == "see status.prod.internal for updates"
    assert result.total == 0


def test_context_exception_keeps_documented_token(redactor):
    text = "See documentation: sample token tok_0000example00001 is redacted in docs"
    result = redactor.redact({"msg": text})
    assert result.data["msg"] == text
    assert result.counts["api-token"] == 0


def test_real_token_is_redacted(redactor):
    result = redactor.redact({"msg": "deploy key tok_a1b2c3d4e5f6g7h8 used"})
    assert "tok_a1b2c3d4e5f6g7h8" not in result.data["msg"]
    assert result.counts["api-token"] == 1


def test_field_rule_redacts_nested_email(redactor):
    data = {"payload": {"reporter": {"email": "alice.chen@corp.example.net"}}}
    result = redactor.redact(data)
    email = result.data["payload"]["reporter"]["email"]
    assert email.startswith("<email:")
    assert "alice.chen" not in email
    assert result.counts["reporter-email-field"] == 1


def test_email_match_exception(redactor):
    result = redactor.redact({"msg": "contact team@example.com"})
    assert result.data["msg"] == "contact team@example.com"


def test_deterministic_replacements(redactor):
    data = {"msg": "host web-01.prod.internal down, web-01.prod.internal flaky"}
    first = redactor.redact(data)
    second = redactor.redact(data)
    assert first.data == second.data
    assert first.data["msg"].count("<host:") == 2
    parts = first.data["msg"].split()
    assert parts[1].rstrip(",") == parts[3]


def test_determinism_with_fresh_redactor(store):
    data = {"msg": "ping bob.li@corp.example.net"}
    first = build_redactor(store).redact(data).data
    second = build_redactor(store).redact(data).data
    assert first == second


def test_counts_reported_per_rule(redactor):
    data = {
        "msg": "web-01.prod.internal mailed alice.chen@corp.example.net"
        " with tok_a1b2c3d4e5f6g7h8"
    }
    result = redactor.redact(data)
    assert result.counts == {
        "internal-hostname": 1,
        "email-address": 1,
        "api-token": 1,
    }
    assert result.total == 3


def test_context_exception_on_match_vs_context():
    rule = RegexRule(
        name="t",
        label="token",
        pattern=r"tok_\w+",
        exceptions=(ContextException(pattern="public", on="context"),),
    )
    redactor = Redactor(secret=b"s", regex_rules=[rule])
    kept = redactor.redact("public example tok_abc1234567890abcdef here")
    assert "tok_abc1234567890abcdef" in kept.data
    hidden = redactor.redact("secret tok_abc1234567890abcdef here")
    assert "tok_abc1234567890abcdef" not in hidden.data
