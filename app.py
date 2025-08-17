import os
import secrets
from flask import Flask, request, redirect, url_for, render_template, flash, send_from_directory, session
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
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ANALYSIS_FOLDER'] = 'analyses'
app.config['BABEL_DEFAULT_LOCALE'] = 'en'
app.config['BABEL_SUPPORTED_LOCALES'] = ['en', 'de', 'nl', 'fr']
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200 MB upload limit
DB_PATH = os.environ.get('TICKET_DB_PATH', 'tickets.db')

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
    ref_url = urlparse(request.host_url)
    test_url = urlparse(target)
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

def get_csrf_token():
    token = session.get('csrf_token')
    if not token:
        token = secrets.token_hex(16)
        session['csrf_token'] = token
    return token

def get_locale():
    # Check if a language is stored in the session
    lang = session.get('lang', 'en')
    #print(f"Current language: {lang}")
    return lang

babel = Babel(app, locale_selector=get_locale)


@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(error):
    flash(_('File is too large. Maximum size is 200 MB.'))
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
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS tickets (
                    ticket_number INTEGER PRIMARY KEY,
                    exe_name TEXT,
                    crash_reason TEXT,
                    analysis_file TEXT,
                    timestamp TEXT
                )''')
    conn.commit()
    conn.close()


def load_tickets_from_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT ticket_number, exe_name, crash_reason, analysis_file, timestamp FROM tickets')
    rows = c.fetchall()
    conn.close()
    loaded = {row[0]: {
        'exe_name': row[1],
        'crash_reason': row[2],
        'analysis_file': row[3],
        'timestamp': row[4]
    } for row in rows}
    return loaded


def get_next_ticket_number():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT IFNULL(MAX(ticket_number), 0) + 1 FROM tickets')
    next_ticket = c.fetchone()[0]
    conn.close()
    return next_ticket


def save_ticket_to_db(ticket_number, ticket):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO tickets (ticket_number, exe_name, crash_reason, analysis_file, timestamp) VALUES (?, ?, ?, ?, ?)',
              (ticket_number, ticket['exe_name'], ticket['crash_reason'], ticket['analysis_file'], ticket['timestamp']))
    conn.commit()
    conn.close()


init_db()
tickets = load_tickets_from_db()



@app.context_processor
def inject_get_locale():
    return dict(get_locale=get_locale, csrf_token=get_csrf_token())

@app.route('/', methods=['GET', 'POST'])
def upload_file():
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
        application_path = sys._MEIPASS
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
                               ticket_timestamp=ticket_timestamp)
    else:
        flash (_('Analysis report not found.'))
        return redirect(url_for('upload_file'))


@app.route('/clear_dumps', methods=['POST'])
def clear_dumps():
    """Delete all uploaded .dmp files but keep analyses and tickets."""
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

    
if __name__ == '__main__':
    if getattr(sys, 'frozen', False):
        if serve is None:
            raise RuntimeError("Waitress is required in frozen mode but is not available.")
        # Running as bundled executable: use production server
        serve(app, host='0.0.0.0', port=5000, max_request_body_size=app.config['MAX_CONTENT_LENGTH'])
    else:
        # Development mode
        app.run(host='0.0.0.0', port=5000)
