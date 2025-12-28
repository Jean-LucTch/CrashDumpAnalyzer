import os
import secrets
from flask import Flask, request, redirect, url_for, render_template, flash, send_from_directory, session, abort
from markupsafe import Markup
from werkzeug.exceptions import RequestEntityTooLarge
import markdown
from datetime import datetime
from flask_babel import Babel, gettext as _
from config import VERSION
import sys
from urllib.parse import urlparse
import sqlite3
from dump_analyzer import analyze_dump


try:
    # Waitress is used for the production server when bundled
    from waitress import serve
except ImportError:  # pragma: no cover - Waitress not needed in tests
    serve = None

app = Flask(__name__)
app.secret_key = '578493092754320oio6547a32653402tzu174321045d414d5g4d5g314d5644315¨ü6448¨$34ö14$üöäiä643*914*64*op416*43146*443*i1*643i*16*443*146*4431*464*31464i4315p453145oi6443165464531'
app.jinja_env.add_extension('jinja2.ext.i18n')
# Prefer SECRET_KEY from environment when provided
app.secret_key = os.environ.get('SECRET_KEY', app.secret_key)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ANALYSIS_FOLDER'] = 'analyses'
app.config['BABEL_DEFAULT_LOCALE'] = 'en'
app.config['BABEL_SUPPORTED_LOCALES'] = ['en', 'de', 'nl', 'fr']
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200 MB upload limit
DB_PATH = os.environ.get('TICKET_DB_PATH', 'tickets.db')

# Session & cookie security (server-side configuration)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
# In production, require HTTPS for session cookies
_env_mode = os.getenv('APP_ENV', os.getenv('FLASK_ENV', os.getenv('ENV', os.getenv('PYTHON_ENV', 'development'))))
if str(_env_mode).lower() == 'production':
    app.config['SESSION_COOKIE_SECURE'] = True


VALID_REDIRECTS = [
    '/', 
    '/changelog', 
    '/analysis'
]

def validate_url(url):
    parsed_url = urlparse(url.replace('\\', ''))
    if parsed_url.path in VALID_REDIRECTS and not parsed_url.query and not parsed_url.fragment:
        return parsed_url.path
    return '/'

def is_safe_url(target):
    """
    Validate that the target URL is safe to redirect to.

    A URL is considered safe if it:
    - Uses http/https when a scheme is present, and
    - Has no netloc (relative URL) or the same netloc as the current request.
    Backslashes are stripped to avoid browser-specific interpretations.
    """
    if not target:
        return False
    # Normalize backslashes to avoid bypasses like "https:\\evil.com"
    target = target.replace('\\', '')
    ref_url = urlparse(request.host_url)
    test_url = urlparse(target)

    # If a scheme is present, it must be http or https
    if test_url.scheme and test_url.scheme not in ('http', 'https'):
        return False

    # If netloc is present, it must match the current host
    if test_url.netloc and test_url.netloc != ref_url.netloc:
        return False

    # Relative URLs (no scheme, no netloc) are allowed
    return True

def get_csrf_token():
    token = session.get('csrf_token')
    if not token:
        token = secrets.token_hex(16)
        session['csrf_token'] = token
    return token

# Minimal helper to provide a Jinja-friendly "form" with csrf_token
# without bringing in Flask-WTF for this example. If Flask-WTF is
# present, you can replace this with the real form.
class _Field:
    def __init__(self, errors=None, data=None):
        self.errors = errors or []
        self.data = data

class _SimpleForm:
    def __init__(self, csrf_token_html, email_errors=None, password_errors=None, email_data=None):
        self.csrf_token = Markup(csrf_token_html)
        self.email = _Field(email_errors, email_data)
        self.password = _Field(password_errors)

def _build_simple_form(email_errors=None, password_errors=None, email_data=None):
    token = get_csrf_token()
    csrf_html = f'<input type="hidden" name="csrf_token" value="{token}">'
    return _SimpleForm(csrf_html, email_errors, password_errors, email_data)

def get_locale():
    # Check if a language is stored in the session
    lang = session.get('lang', 'en')
    #print(f"Current language: {lang}")
    return lang

babel = Babel(app, locale_selector=get_locale)


@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(error):
    flash(_('File is too large. Maximum size is 900 MB.'))
    return redirect(url_for('upload_file')), 413

@app.route('/set_language/<language>')
def set_language(language):
    session['lang'] = language
    referrer = request.referrer
    if not referrer or not is_safe_url(referrer):
        referrer = url_for('upload_file')
    return redirect(referrer)

# Create directories if they do not exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['ANALYSIS_FOLDER'], exist_ok=True)

# Database functions for ticket persistence
from contextlib import contextmanager

@contextmanager
def get_db_connection():
    """Context manager for database connections to ensure proper cleanup"""
    conn = sqlite3.connect(DB_PATH)
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS tickets (
                        ticket_number INTEGER PRIMARY KEY,
                        exe_name TEXT,
                        crash_reason TEXT,
                        analysis_file TEXT,
                        timestamp TEXT
                    )''')
        conn.commit()


def load_tickets_from_db():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT ticket_number, exe_name, crash_reason, analysis_file, timestamp FROM tickets')
        rows = c.fetchall()
    return {row[0]: {
        'exe_name': row[1],
        'crash_reason': row[2],
        'analysis_file': row[3],
        'timestamp': row[4]
    } for row in rows}


def get_next_ticket_number():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('SELECT IFNULL(MAX(ticket_number), 0) + 1 FROM tickets')
        return c.fetchone()[0]


def save_ticket_to_db(ticket_number, ticket):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute('INSERT INTO tickets (ticket_number, exe_name, crash_reason, analysis_file, timestamp) VALUES (?, ?, ?, ?, ?)',
                  (ticket_number, ticket['exe_name'], ticket['crash_reason'], ticket['analysis_file'], ticket['timestamp']))
        conn.commit()


init_db()
tickets = load_tickets_from_db()



@app.context_processor
def inject_get_locale():
    return dict(get_locale=get_locale, csrf_token=get_csrf_token())

# Prevent caching on authenticated responses
@app.after_request
def apply_no_store(resp):
    try:
        if session.get('user') and not request.path.startswith('/static/'):
            resp.headers['Cache-Control'] = 'no-store'
            resp.headers['Pragma'] = 'no-cache'
            resp.headers['Expires'] = '0'
    except Exception:
        pass
    return resp

# -------------------------
# Authentication endpoints
# -------------------------

def _in_production():
    return str(_env_mode).lower() == 'production'


def _get_configured_credentials():
    """Return the configured admin credentials if provided."""
    username = app.config.get('ADMIN_USER') or os.environ.get('APP_ADMIN_USER')
    password = app.config.get('ADMIN_PASSWORD') or os.environ.get('APP_ADMIN_PASSWORD')
    if username is not None:
        username = str(username)
    if password is not None:
        password = str(password)
    return username, password


def _validate_credentials(email, password):
    if _in_production():
        expected_user, expected_password = _get_configured_credentials()
        if not expected_user or not expected_password:
            return False
        return (
            secrets.compare_digest(email, expected_user)
            and secrets.compare_digest(password, expected_password)
        )
    return email == 'admin' and password == 'password'


@app.route('/login', methods=['GET', 'POST'])
def login():
    # If already authenticated, go to the protected index
    if session.get('user'):
        return redirect(url_for('upload_file'))

    error_message = None

    if request.method == 'POST':
        # CSRF check using the same token the template includes
        form_token = request.form.get('csrf_token')
        if not form_token or not secrets.compare_digest(session.get('csrf_token', ''), form_token):
            error_message = _('Invalid email or password') if '_' in globals() else 'Invalid email or password'
            form = _build_simple_form(email_errors=[error_message],
                                      password_errors=[error_message],
                                      email_data=request.form.get('email', ''))
            return render_template('login.html', form=form, error_message=error_message)

        email = (request.form.get('email') or '').strip()
        password = request.form.get('password') or ''
        remember = request.form.get('remember') is not None

        valid = _validate_credentials(email, password)

        if valid:
            session.clear()
            session['user'] = email
            session['sid'] = secrets.token_urlsafe(16)
            session['csrf_token'] = secrets.token_urlsafe(32)
            session.permanent = bool(remember)
            return redirect(url_for('upload_file'))
        else:
            # Generic message to avoid user enumeration
            error_message = _('Invalid email or password') if '_' in globals() else 'Invalid email or password'
            form = _build_simple_form(email_errors=[error_message],
                                      password_errors=[error_message],
                                      email_data=email)
            return render_template('login.html', form=form, error_message=error_message)

    # GET
    form = _build_simple_form()
    return render_template('login.html', form=form, error_message=None)


@app.route('/forgot-password')
def forgot_password():
    page_title = _('Forgot password') if '_' in globals() else 'Forgot password'
    return render_template('coming_soon.html', page_title=page_title)


@app.route('/register')
def register():
    page_title = _('Create account') if '_' in globals() else 'Create account'
    return render_template('coming_soon.html', page_title=page_title)


@app.route('/logout', methods=['POST'])
def logout():
    # POST-only logout with CSRF verification
    form_token = request.form.get('csrf_token', '')
    sess_token = session.get('csrf_token')
    if not sess_token or not form_token or not secrets.compare_digest(sess_token, form_token):
        abort(400)

    session.clear()
    resp = redirect(url_for('login'))
    try:
        cookie_name = app.config.get('SESSION_COOKIE_NAME', 'session')
        resp.delete_cookie(cookie_name)
    except Exception:
        pass
    return resp


@app.route('/index', methods=['GET', 'POST'])
def protected_index():
    # Keep /index as an alias entry point after login
    if not session.get('user'):
        return redirect(url_for('login'))
    return redirect(url_for('upload_file'))

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    # Require authentication for the main application
    if not session.get('user'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        if 'file' not in request.files:
            flash (_('No file selected')) 
            return redirect(validate_url(request.url))
        file = request.files['file']
        if file.filename == '':
            flash (_('No file selected'))
            return redirect(validate_url(request.url))
        if file and file.filename.lower().endswith('.dmp'):
            ticket_number = get_next_ticket_number()

            # Save the file
            dump_filename = f"dump_{ticket_number}.dmp"
            dump_path = os.path.join(app.config['UPLOAD_FOLDER'], dump_filename)
            file.save(dump_path)

            # Analyze the dump file (ticket number is passed)
            exe_name, crash_reason = analyze_dump(dump_path, ticket_number, app.config['ANALYSIS_FOLDER'])

            # Save the ticket
            ticket_info = {
            'exe_name': exe_name,
            'crash_reason': crash_reason,
            'analysis_file': f"analysis_{ticket_number}.txt",
            'timestamp': datetime.now().strftime('%d.%m.%Y %H:%M:%S')
            }
            tickets[ticket_number] = ticket_info
            save_ticket_to_db(ticket_number, ticket_info)

            flash (_('File uploaded and analyzed. Ticket number:') + f' {ticket_number}')

            return redirect(url_for('upload_file'))

        else:
            flash (_('Please upload a valid .dmp file'))
            return redirect(validate_url(request.url))
    #print(f"Current language in the view: {get_locale()}") 
    return render_template('index.html', tickets=tickets, version=VERSION, get_locale=get_locale)

@app.route('/changelog')
def changelog():
    # Determine the base directory
    if getattr(sys, 'frozen', False):
        # Application is bundled as an executable
        application_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    else:
        # Application is running normally
        application_path = os.path.dirname(os.path.abspath(__file__))

    changelog_path = os.path.join(application_path, 'changelog.md')

    if not os.path.exists(changelog_path):
        return _("Changelog file not found."), 404

    with open(changelog_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Convert Markdown to HTML
    changelog_html = markdown.markdown(content)
    return render_template('changelog.html', changelog=changelog_html, version=VERSION)

@app.route('/analysis/<int:ticket_number>')
def view_analysis(ticket_number):
    analysis_filename = f"analysis_{ticket_number}.txt"
    base_path = app.config['ANALYSIS_FOLDER']
    analysis_path = os.path.normpath(os.path.join(base_path, analysis_filename))

    if not analysis_path.startswith(base_path):
        flash(_('Invalid file path.'))
        return redirect(url_for('upload_file'))

    if os.path.exists(analysis_path):
        with open(analysis_path, 'r', encoding='utf-8') as f:
            analysis_content = f.read()
        ticket_info = tickets.get(ticket_number)
        ticket_timestamp = ticket_info.get('timestamp') if ticket_info else ''
        return render_template('analysis.html', 
                               ticket_number=ticket_number, 
                               analysis_content=analysis_content,
                               ticket_timestamp=ticket_timestamp,
                               version=VERSION)
    else:
        flash (_('Analysis report not found.'))
        return redirect(url_for('upload_file'))


@app.route('/clear_dumps', methods=['POST'])
def clear_dumps():
    """Delete all uploaded .dmp files but keep analyses and tickets."""
    if not session.get('user'):
        flash(_('You must be signed in to perform this action.'))
        return redirect(url_for('login'))
    form_token = request.form.get('csrf_token')
    session_token = session.get('csrf_token')
    if form_token is None or session_token is None:
        flash(_('Invalid CSRF token.'))
    if not form_token or not session_token or not secrets.compare_digest(session_token, form_token):
        flash(_('Invalid CSRF token.'))
        return redirect(url_for('upload_file'))
    upload_folder = app.config['UPLOAD_FOLDER']
    for name in os.listdir(upload_folder):
        if name.lower().endswith('.dmp'):
            file_path = os.path.join(upload_folder, name)
            try:
                os.remove(file_path)
            except OSError:
                # Ignore errors so that remaining files can still be deleted
                pass
    flash(_('Dump files cleared.'))
    return redirect(url_for('upload_file'))


@app.route('/clear_tickets', methods=['POST'])
def clear_tickets():
    """Delete all tickets: dump files, analysis files, and DB entries."""
    if not session.get('user'):
        flash(_('You must be signed in to perform this action.'))
        return redirect(url_for('login'))
    form_token = request.form.get('csrf_token')
    session_token = session.get('csrf_token')
    if form_token is None or session_token is None:
        flash(_('Invalid CSRF token.'))
    if not form_token or not session_token or not secrets.compare_digest(session_token, form_token):
        flash(_('Invalid CSRF token.'))
        return redirect(url_for('upload_file'))

    # Delete all dump files
    upload_folder = app.config['UPLOAD_FOLDER']
    try:
        for name in os.listdir(upload_folder):
            if name.lower().endswith('.dmp'):
                file_path = os.path.join(upload_folder, name)
                try:
                    os.remove(file_path)
                except OSError:
                    pass
    except FileNotFoundError:
        pass

    # Delete all analysis files
    analysis_folder = app.config['ANALYSIS_FOLDER']
    try:
        for name in os.listdir(analysis_folder):
            # Be conservative: only remove files that match our analysis naming pattern
            if name.lower().startswith('analysis_') and name.lower().endswith('.txt'):
                file_path = os.path.join(analysis_folder, name)
                try:
                    os.remove(file_path)
                except OSError:
                    pass
    except FileNotFoundError:
        pass

    # Clear DB entries
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute('DELETE FROM tickets')
            conn.commit()
    except sqlite3.Error:
        # If DB operation fails, still proceed with what we could delete
        pass

    # Reset in-memory tickets
    try:
        tickets.clear()
    except Exception:
        pass

    flash(_('All tickets and related files have been deleted.'))
    return redirect(url_for('upload_file'))

    
if __name__ == '__main__':
    if getattr(sys, 'frozen', False):
        if serve is None:
            raise RuntimeError("Waitress is required in frozen mode but is not available.")
        # Running as bundled executable: use production server
        serve(app, host='0.0.0.0', port=5000, max_request_body_size=app.config['MAX_CONTENT_LENGTH'])
    else:
        # Development mode
        app.run(host='0.0.0.0', port=5000)
