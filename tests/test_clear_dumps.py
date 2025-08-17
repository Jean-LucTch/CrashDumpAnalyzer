import os
import types


def test_clear_dumps(app_module, tmp_path):
    # prepare upload folder with dump and other files
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    # create dump files and a text file
    (upload_dir / "a.dmp").write_text("dummy")
    (upload_dir / "b.DMP").write_text("dummy")
    (upload_dir / "keep.txt").write_text("text")

    app_module.app.config['UPLOAD_FOLDER'] = str(upload_dir)

    # set CSRF tokens for stubbed request and session
    token = 'testtoken'
    app_module.session['csrf_token'] = token
    app_module.request = types.SimpleNamespace(form={'csrf_token': token})

    # call the function
    app_module.clear_dumps()

    remaining = list(p.name for p in upload_dir.iterdir())
    assert "keep.txt" in remaining
    assert not any(name.lower().endswith('.dmp') for name in remaining)
