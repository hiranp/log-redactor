import pytest
import 

def test_redactorAPI_with_ignore():
    line = "API key=12345"
    secretArray = []
    ignoreArray = ["12345"]
    redacted_line, secretArray, ignoreArray = redactorAPI(
        line, secretArray, ignoreArray, "api", False
    )
    assert redacted_line == "API key=12345"
    assert secretArray == []
    assert ignoreArray == ["12345"]


def test_redactorAPI_with_secret():
    line = "API key=12345"
    secretArray = ["12345"]
    ignoreArray = []
    redacted_line, secretArray, ignoreArray = redactorAPI(
        line, secretArray, ignoreArray, "api", False
    )
    assert redacted_line == "API key=API_REDACTED"
    assert secretArray == ["12345"]
    assert ignoreArray == []


def test_redactorAPI_interactive_yes(monkeypatch):
    line = "API key=12345"
    secretArray = []
    ignoreArray = []
    monkeypatch.setattr("builtins.input", lambda: "yes")
    redacted_line, secretArray, ignoreArray = redactorAPI(
        line, secretArray, ignoreArray, "api", True
    )
    assert redacted_line == "API key=API_REDACTED"
    assert secretArray == ["12345"]
    assert ignoreArray == []


def test_redactorAPI_interactive_no(monkeypatch):
    line = "API key=12345"
    secretArray = []
    ignoreArray = []
    monkeypatch.setattr("builtins.input", lambda: "no")
    redacted_line, secretArray, ignoreArray = redactorAPI(
        line, secretArray, ignoreArray, "api", True
    )
    assert redacted_line == "API key=12345"
    assert secretArray == []
    assert ignoreArray == ["12345"]


def test_redactorAPI_interactive_always(monkeypatch):
    line = "API key=12345"
    secretArray = []
    ignoreArray = []
    monkeypatch.setattr("builtins.input", lambda: "always")
    redacted_line, secretArray, ignoreArray = redactorAPI(
        line, secretArray, ignoreArray, "api", True
    )
    assert redacted_line == "API key=API_REDACTED"
    assert secretArray == ["12345"]
    assert ignoreArray == []


def test_redactorAPI_interactive_never(monkeypatch):
    line = "API key=12345"
    secretArray = []
    ignoreArray = []
    monkeypatch.setattr("builtins.input", lambda: "never")
    redacted_line, secretArray, ignoreArray = redactorAPI(
        line, secretArray, ignoreArray, "api", True
    )
    assert redacted_line == "API key=12345"
    assert secretArray == []
    assert ignoreArray == ["12345"]
