import os
import re
from importlib.util import spec_from_file_location, module_from_spec
from pathlib import Path

import pytest


def load_real_app(tmp_path, monkeypatch):
    """Load a clean instance of the real Flask app module.

    This bypasses the stub-based fixture by importing app.py under a
    unique module name and setting isolated env/config for tests.
    """
    # Ensure development mode so the hardcoded credentials are active
    monkeypatch.setenv("APP_ENV", "development")
    # Use a temp DB so tests don't touch the real DB
    monkeypatch.setenv("TICKET_DB_PATH", str(tmp_path / "tickets.db"))

    repo_root = Path(__file__).resolve().parents[1]
    app_py = str(repo_root / "app.py")
    spec = spec_from_file_location("real_app_module", app_py)
    if spec is None:
        raise ImportError(f"Could not load spec for {app_py}")
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]

    # Isolate file system state
    uploads = tmp_path / "uploads"
    analyses = tmp_path / "analyses"
    uploads.mkdir(exist_ok=True)
    analyses.mkdir(exist_ok=True)

    mod.app.config.update(
        TESTING=True,
        SECRET_KEY="test-secret",
        UPLOAD_FOLDER=str(uploads),
        ANALYSIS_FOLDER=str(analyses),
    )
    return mod


@pytest.fixture()
def real_app(tmp_path, monkeypatch):
    return load_real_app(tmp_path, monkeypatch)


@pytest.fixture()
def client(real_app):
    return real_app.app.test_client()


def extract_csrf(html: str) -> str:
    m = re.search(r'name="csrf_token"\s+value=\"([^"]+)\"', html)
    assert m, "CSRF token not found in HTML"
    return m.group(1)


def test_root_redirects_to_login_when_unauthenticated(client):
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert "/login" in resp.headers.get("Location", "")


def test_login_get_serves_form_with_csrf(client):
    resp = client.get("/login")
    assert resp.status_code == 200
    assert b"name=\"csrf_token\"" in resp.data


def test_login_rejects_invalid_csrf(client):
    # No prior GET: missing or wrong token
    resp = client.post(
        "/login",
        data={"email": "admin", "password": "password", "csrf_token": "bad"},
        follow_redirects=False,
    )
    # Renders login again with generic error
    assert resp.status_code == 200
    assert b"Invalid email or password" in resp.data


def test_login_rejects_bad_credentials(client):
    # Fetch correct CSRF first
    get_resp = client.get("/login")
    token = extract_csrf(get_resp.data.decode("utf-8", errors="ignore"))

    resp = client.post(
        "/login",
        data={"email": "admin", "password": "wrong", "csrf_token": token},
    )
    assert resp.status_code == 200
    assert b"Invalid email or password" in resp.data


def test_login_success_sets_session_and_redirects(client):
    # Fetch CSRF
    get_resp = client.get("/login")
    token = extract_csrf(get_resp.data.decode("utf-8", errors="ignore"))

    resp = client.post(
        "/login",
        data={"email": "admin", "password": "password", "csrf_token": token},
        follow_redirects=False,
    )
    # Redirect to the protected index
    assert resp.status_code in (301, 302)
    assert "/" == resp.headers.get("Location", "/")

    # Session cookie security flags
    set_cookie = "; ".join(resp.headers.getlist("Set-Cookie"))
    assert "HttpOnly" in set_cookie
    assert "SameSite=Strict" in set_cookie
    # In development we don't expect Secure flag
    assert "Secure" not in set_cookie

    # After login, the main page should be accessible and non-cacheable
    home = client.get("/")
    assert home.status_code == 200
    assert home.headers.get("Cache-Control") == "no-store"
    assert home.headers.get("Pragma") == "no-cache"
    assert home.headers.get("Expires") == "0"


def test_logout_requires_csrf_and_clears_session(client):
    # Log in first
    token = extract_csrf(client.get("/login").data.decode("utf-8", errors="ignore"))
    client.post("/login", data={"email": "admin", "password": "password", "csrf_token": token})

    # Missing token -> 400
    resp_bad = client.post("/logout")
    assert resp_bad.status_code == 400

    # Valid token -> redirect to login and session cleared
    with client.session_transaction() as sess:
        valid_token = sess.get("csrf_token")
        assert valid_token
    resp_ok = client.post("/logout", data={"csrf_token": valid_token}, follow_redirects=False)
    assert resp_ok.status_code in (301, 302)
    assert "/login" in resp_ok.headers.get("Location", "")

    # Accessing home should now redirect to login
    after = client.get("/", follow_redirects=False)
    assert after.status_code in (301, 302)
    assert "/login" in after.headers.get("Location", "")


def test_admin_actions_require_csrf_and_delete_only_dumps(real_app, client, tmp_path):
    # Login
    token = extract_csrf(client.get("/login").data.decode("utf-8", errors="ignore"))
    client.post("/login", data={"email": "admin", "password": "password", "csrf_token": token})

    # Prepare files
    uploads = Path(real_app.app.config["UPLOAD_FOLDER"])  # type: ignore[index]
    (uploads / "keep.txt").write_text("ok", encoding="utf-8")
    (uploads / "one.dmp").write_text("dummy", encoding="utf-8")
    (uploads / "two.DMP").write_text("dummy", encoding="utf-8")

    # Missing token -> 302 back to /
    bad = client.post("/clear_dumps", follow_redirects=False)
    assert bad.status_code in (301, 302)

    # Valid token -> deletes only .dmp files
    with client.session_transaction() as sess:
        csrf = sess["csrf_token"]
    ok = client.post("/clear_dumps", data={"csrf_token": csrf}, follow_redirects=False)
    assert ok.status_code in (301, 302)

    remaining = {p.name for p in uploads.iterdir()}
    assert "keep.txt" in remaining
    assert not any(name.lower().endswith(".dmp") for name in remaining)


def test_set_language_redirect_is_safe(client):
    # Unsafe referrer should fall back to internal page
    resp = client.get("/set_language/de", headers={"Referer": "http://evil.example/"}, follow_redirects=False)
    assert resp.status_code in (301, 302)
    # Should redirect internally (upload page)
    assert resp.headers.get("Location", "").startswith("/")

