"""Unit tests for the rule expression language."""

import pytest

from rtdb_rules.expr import RulesError, evaluate, parse, strict_equal, tokenize
from rtdb_rules.snapshot import Snapshot

TREE = {"devices": {"hive-1": {"owners": {"u1": True}, "status": {"temp": 26.9, "door": "shut"}}}}


def ev(src: str, **env):
    base = {
        "auth": None,
        "now": 1_700_000_000_000,
        "root": Snapshot(TREE),
        "data": Snapshot(TREE, ["devices", "hive-1"]),
    }
    base.update(env)
    return evaluate(parse(src), base)


def test_tokenizer_handles_strings_regex_and_numbers():
    kinds = [t.kind for t in tokenize("'a\\'b' + \"c\" === 1.5 && x.matches(/^a\\/b$/i)")]
    assert kinds == [
        "str",
        "op",
        "str",
        "op",
        "num",
        "op",
        "ident",
        "op",
        "ident",
        "op",
        "regex",
        "op",
        "eof",
    ]
    regex = [t for t in tokenize("s.matches(/^[0-9]{10}$/)") if t.kind == "regex"][0]
    assert regex.value == ("^[0-9]{10}$", "")


def test_division_is_not_mistaken_for_regex():
    assert ev("now / 1000 + 300") == 1_700_000_300


@pytest.mark.parametrize("src", ["a == b", "a != b", "'open", "1 +", "foo(", "a.b.c(/x)"])
def test_bad_syntax_raises(src):
    with pytest.raises(RulesError):
        parse(src)


def test_precedence_and_ternary():
    assert ev("1 + 2 * 3 === 7")
    assert ev("!(1 < 2) || 2 > 1")
    assert ev("true ? 'a' : 'b'") == "a"
    assert ev("false && 1 < 'x'") is False  # short circuit: no type error on the right


def test_strict_equality_does_not_coerce():
    assert strict_equal(1, 1.0)
    assert not strict_equal(1, True)
    assert not strict_equal("1", 1)
    assert strict_equal(None, None)
    assert not ev("data.val() === true")  # an object is never === a literal


def test_type_errors_are_rules_errors():
    for src in ["1 + 'a'", "'a' < 1", "-'a'", "!1", "1 / 0", "unknown === 1", "auth.uid === 'x'"]:
        with pytest.raises(RulesError):
            ev(src)


def test_auth_object_and_missing_claims():
    auth = {"uid": "u1", "provider": "custom", "token": {"sub": "u1", "device": True}}
    assert ev("auth !== null && auth.uid === 'u1'", auth=auth)
    assert ev("auth.token.device === true", auth=auth)
    assert ev("auth.token.deviceId === null", auth=auth)  # absent claim reads as null


def test_snapshot_methods():
    assert ev("data.child('status/temp').val()") == 26.9
    assert ev("data.child('status').child('temp').isNumber()")
    assert ev("data.child('status/door').isString()")
    assert ev("data.hasChildren(['owners', 'status'])")
    assert not ev("data.hasChildren(['owners', 'missing'])")
    assert ev("data.hasChildren()")
    assert not ev("data.child('status/temp').hasChildren()")
    assert ev("data.child('nothing').exists()") is False
    assert ev("data.child('status').parent().child('owners/u1').val() === true")
    assert ev("root.child('devices').child('hive-1').child('owners').child('u1').val() === true")
    assert ev("data.getPriority() === null")


def test_string_methods():
    assert ev("'hive-1'.length === 6")
    assert ev("'hive-1'.beginsWith('hive') && 'hive-1'.endsWith('-1') && 'hive-1'.contains('ve')")
    assert ev("'Hive'.toLowerCase() === 'hive' && 'hive'.toUpperCase() === 'HIVE'")
    assert ev("'a-b-c'.replace('-', '_') === 'a_b_c'")
    assert ev("'1791021711'.matches(/^[0-9]{10}$/)")
    assert not ev("'-NxQ7abc'.matches(/^[0-9]{10}$/)")
    assert ev("'ABC'.matches(/abc/i)")
    with pytest.raises(RulesError):
        ev("'x'.matches('x')")  # matches needs a regex literal
