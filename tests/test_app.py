import types

import pytest


def test_validate_url_valid(app_module):
    assert app_module.validate_url('/changelog') == '/changelog'


def test_validate_url_invalid(app_module):
    # invalid because of query string
    assert app_module.validate_url('/changelog?bad=1') == '/'


def test_validate_url_fragment(app_module):
    assert app_module.validate_url('/changelog#frag') == '/'


def test_validate_url_unknown_path(app_module):
    assert app_module.validate_url('/evil') == '/'


def test_is_safe_url(app_module, monkeypatch):
    app_module.request = types.SimpleNamespace(host_url='http://localhost:5000/')
    assert app_module.is_safe_url('http://localhost:5000/changelog') is True
    assert app_module.is_safe_url('https://evil.com/') is False


def test_get_locale(app_module):
    app_module.session['lang'] = 'de'
    assert app_module.get_locale() == 'de'
    app_module.session.clear()
    assert app_module.get_locale() == 'en'


def test_find_cdb_executable(app_module, monkeypatch):
    called = []

    def fake_exists(path):
        called.append(path)
        expected = r'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe'
        return path == expected

    monkeypatch.setattr(app_module.os.path, 'exists', fake_exists)
    result = app_module.find_cdb_executable()
    assert result in called


def test_find_cdb_executable_none(app_module, monkeypatch):
    monkeypatch.setattr(app_module.os.path, 'exists', lambda p: False)
    assert app_module.find_cdb_executable() is None


def test_analyze_dump_no_debugger(app_module, monkeypatch):
    monkeypatch.setattr(app_module, 'find_cdb_executable', lambda: None)
    result = app_module.analyze_dump('dummy', 1)
    assert result == 'Debugger not found'


def test_analyze_dump_success(app_module, monkeypatch, tmp_path):
    # fake debugger path
    monkeypatch.setattr(app_module, 'find_cdb_executable', lambda: '/path/cdb.exe')

    class DummyProcess:
        def communicate(self, timeout=None):
            out = 'PROCESS_NAME: myapp.exe\nExceptionCode: 0xC0000005\n'
            return out.encode(), b''

    monkeypatch.setattr(app_module.subprocess, 'Popen', lambda *a, **k: DummyProcess())

    app_module.app.config['ANALYSIS_FOLDER'] = str(tmp_path)
    exe, reason = app_module.analyze_dump('dump.dmp', 42)
    assert exe == 'myapp.exe'
    assert reason == '0xC0000005 - Access Violation'
    analysis_file = tmp_path / 'analysis_42.txt'
    assert analysis_file.exists()
    assert 'PROCESS_NAME: myapp.exe' in analysis_file.read_text()
