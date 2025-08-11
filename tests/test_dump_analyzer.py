import builtins
import sys
import types

import pytest


def test_analyze_dump_fallback_minidump(analyzer_module, monkeypatch, tmp_path):
    monkeypatch.setattr(analyzer_module, 'find_cdb_executable', lambda: None)

    class FakeExceptionRecord:
        exception_code = 0xDEADBEEF

    class FakeException:
        exception_record = FakeExceptionRecord()

    class FakeDump:
        exception = FakeException()
        modules = types.SimpleNamespace(modules=[types.SimpleNamespace(name='foo.exe')])

        def __str__(self):
            return 'fake dump'

    minidump_stub = types.ModuleType('minidump')
    minidump_stub.MinidumpFile = types.SimpleNamespace(parse=lambda path: FakeDump())
    monkeypatch.setitem(sys.modules, 'minidump', minidump_stub)

    exe_name, crash_reason = analyzer_module.analyze_dump('dummy', 1, str(tmp_path))
    assert exe_name == 'foo.exe'
    assert crash_reason.startswith('0xDEADBEEF')


def test_analyze_dump_no_debugger(analyzer_module, monkeypatch, tmp_path):
    monkeypatch.setattr(analyzer_module, 'find_cdb_executable', lambda: None)

    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == 'minidump':
            raise ImportError
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, '__import__', fake_import)

    exe_name, crash_reason = analyzer_module.analyze_dump('dummy', 1, str(tmp_path))
    assert exe_name == 'Unknown application'
    assert crash_reason == 'Debugger not found'
