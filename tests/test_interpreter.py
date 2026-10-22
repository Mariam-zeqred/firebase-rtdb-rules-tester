"""Cascade semantics of the interpreter on small hand-written rule trees."""

import pytest

from rtdb_rules.interpreter import Rules, RulesError

USER = {"uid": "u1", "provider": "custom", "token": {"sub": "u1"}}


def rules(tree):
    return Rules({"rules": tree})


def test_read_granted_at_ancestor_cascades_down():
    r = rules({"a": {".read": True, "b": {".read": False}}})
    assert r.can_read("/a/b/c", None, {})
    assert not r.can_read("/x", None, {})
    assert r.can_read("/a/b/c", None, {}).trace == ["/a .read: true"]


def test_write_cannot_be_granted_by_a_child_rule():
    r = rules({"a": {"b": {".write": True}}})
    assert r.can_write("/a/b", {"x": 1}, None, {})
    d = r.can_write("/a", {"b": {"x": 1}}, None, {})
    assert not d and d.reason == "no .write rule granted access"


def test_variable_binding_and_literal_precedence():
    r = rules({"users": {"admin": {".read": False}, "$uid": {".read": "auth.uid === $uid"}}})
    assert r.can_read("/users/u1", USER, {})
    assert not r.can_read("/users/u2", USER, {})
    assert not r.can_read("/users/admin", {**USER, "uid": "admin"}, {})  # literal key wins


def test_two_wildcards_at_one_level_rejected():
    with pytest.raises(RulesError):
        rules({"$a": {}, "$b": {}})
    with pytest.raises(RulesError):
        rules({".read": "auth.uid ==== 1"})


def test_validate_on_ancestor_sees_merged_data():
    r = rules(
        {
            "s": {
                ".write": True,
                ".validate": "newData.hasChildren(['a', 'b'])",
                "a": {".validate": "newData.isNumber()"},
                "b": {".validate": "newData.isNumber()"},
            }
        }
    )
    assert not r.can_write("/s", {"a": 1}, None, {})
    assert r.can_write("/s", {"a": 1, "b": 2}, None, {})
    assert r.can_write("/s/a", 5, None, {"s": {"a": 1, "b": 2}})  # single-field update, merged
    assert not r.can_write("/s/a", 5, None, {})  # fresh node, 'b' missing
    assert not r.can_write("/s/a", "x", None, {"s": {"a": 1, "b": 2}})


def test_validate_checks_written_subtree_and_skips_null():
    r = rules(
        {
            "s": {
                ".write": True,
                ".validate": "newData.hasChildren()",
                "a": {".validate": "newData.isNumber()"},
                "$other": {".validate": False},
            }
        }
    )
    assert r.can_write("/s", {"a": 1}, None, {})
    assert not r.can_write("/s", {"a": 1, "zzz": 1}, None, {})
    assert not r.can_write("/s", {"a": "no"}, None, {})
    d = r.can_write("/s", None, None, {"s": {"a": 1}})  # delete passes: validate skipped
    assert d and any("skipped" in line for line in d.trace)
    assert r.can_write("/s", {"a": 1, "zzz": None}, None, {})  # null child is not a write


def test_data_and_newdata_refer_to_the_rule_node():
    r = rules({"h": {"$k": {".write": "!data.exists() && newData.exists()"}}})
    assert r.can_write("/h/1", {"v": 1}, None, {})
    assert not r.can_write("/h/1", {"v": 2}, None, {"h": {"1": {"v": 1}}})
    assert not r.can_write("/h/1", None, None, {"h": {"1": {"v": 1}}})


def test_root_is_pre_write_data():
    r = rules({"x": {".write": True, ".validate": "root.child('x').val() === null"}})
    assert r.can_write("/x", 1, None, {})  # root still has no x during the write


def test_expression_error_is_false_with_trace():
    r = rules({"p": {".read": "auth.uid === 'u1'"}})
    d = r.can_read("/p", None, {})
    assert not d
    assert "error → false" in d.trace[0] and "null" in d.trace[0]


def test_non_boolean_rule_result_is_false():
    r = rules({"p": {".read": "'yes'"}})
    assert not r.can_read("/p", None, {})


def test_update_is_one_write_per_child_path():
    r = rules({"d": {"c": {".write": True}, "s": {".write": False}}})
    assert r.can_update("/d", {"c/x": 1, "c/y": 2}, None, {})
    d = r.can_update("/d", {"c/x": 1, "s/x": 2}, None, {})
    assert not d and d.reason.startswith("/d/s/x")


def test_now_is_available_and_pinnable():
    r = rules({"t": {".write": "newData.val() < now / 1000 + 300"}})
    assert r.can_write("/t", 1000, None, {}, now=1_000_000)
    assert not r.can_write("/t", 2000, None, {}, now=1_000_000)


def test_empty_objects_normalise_to_null():
    r = rules({"$k": {".write": "!data.exists()"}})
    assert r.can_write("/a", 1, None, {"a": {"b": None}})
