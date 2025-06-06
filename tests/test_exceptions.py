import importlib
import sys
import types


def load_app():
    if 'app' in sys.modules:
        return importlib.reload(sys.modules['app'])

    # Create minimal flask stub
    flask_stub = types.ModuleType('flask')

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
    flask_stub.url_for = lambda *a, **k: ''
    flask_stub.render_template = lambda *a, **k: ''
    flask_stub.flash = lambda *a, **k: None
    flask_stub.send_from_directory = lambda *a, **k: None
    flask_stub.session = {}
    sys.modules['flask'] = flask_stub

    # flask_babel stub
    babel_stub = types.ModuleType('flask_babel')

    class Babel:
        def __init__(self, app, locale_selector=None):
            self.app = app
            self.locale_selector = locale_selector

    babel_stub.Babel = Babel
    babel_stub.gettext = lambda s, *a, **k: s
    sys.modules['flask_babel'] = babel_stub

    # markdown stub
    sys.modules['markdown'] = types.ModuleType('markdown')

    return importlib.import_module('app')


def test_known_exception_code():
    app = load_app()
    assert app.get_exception_description('0xC0000005') == 'Access Violation'


def test_unknown_exception_code():
    app = load_app()
    assert app.get_exception_description('0xDEADBEEF') == 'Unknown error'

