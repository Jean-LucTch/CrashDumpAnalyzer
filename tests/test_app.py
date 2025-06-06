
import importlib
import sys
import types

import pytest



@pytest.fixture
def app_module(monkeypatch):
    """Import `app` with minimal stubs so tests run without Flask."""

    flask_stub = types.ModuleType("flask")

    class Flask:
        def __init__(self, name):
            self.jinja_env = types.SimpleNamespace(add_extension=lambda ext: None)
            self.config = {}

        def route(self, *args, **kwargs):
            def decorator(func):
                return func
            return decorator

        def context_processor(self, func):
            return func

    flask_stub.Flask = Flask
    flask_stub.request = None
    flask_stub.redirect = lambda *a, **k: None
    flask_stub.url_for = lambda *a, **k: ""
    flask_stub.render_template = lambda *a, **k: ""
    flask_stub.flash = lambda *a, **k: None
    flask_stub.send_from_directory = lambda *a, **k: None
    flask_stub.session = {}
    monkeypatch.setitem(sys.modules, "flask", flask_stub)

    babel_stub = types.ModuleType("flask_babel")

    class Babel:
        def __init__(self, app, locale_selector=None):
            self.app = app
            self.locale_selector = locale_selector

    babel_stub.Babel = Babel
    babel_stub.gettext = lambda s, *a, **k: s
    monkeypatch.setitem(sys.modules, "flask_babel", babel_stub)

    monkeypatch.setitem(sys.modules, "markdown", types.ModuleType("markdown"))

    module = importlib.import_module("app")
    try:
        yield module
    finally:
        importlib.reload(module)



def test_analyze_dump_no_debugger(app_module, monkeypatch):
    monkeypatch.setattr(app_module, 'find_cdb_executable', lambda: None)
    result = app_module.analyze_dump('dummy', 1)
    assert result == 'Debugger not found'
