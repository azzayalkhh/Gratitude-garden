from flask import Flask, request, jsonify, render_template, session
import sqlite3
from datetime import date
import os
import hashlib
import secrets
import logging
from functools import wraps

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

app = Flask(__name__, template_folder='gratitude_templates')

_BASE = os.path.dirname(os.path.abspath(__file__))
_KEY_FILE = os.path.join(_BASE, '.gratitude_secret')
if os.path.exists(_KEY_FILE):
    with open(_KEY_FILE) as _f:
        app.secret_key = _f.read().strip()
else:
    app.secret_key = secrets.token_hex(32)
    with open(_KEY_FILE, 'w') as _f:
        _f.write(app.secret_key)

DB_PATH = os.path.join(_BASE, 'gratitude.db')
log.info("DB path: %s", DB_PATH)

VALID_PLANT_TYPES = {'flower', 'fruit', 'tree', 'vegetable'}


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{h}"


def verify_password(stored: str, provided: str) -> bool:
    salt, h = stored.split(':', 1)
    return hashlib.sha256((salt + provided).encode()).hexdigest() == h


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            garden_name TEXT NOT NULL DEFAULT 'Миний Цэцэрлэг',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            entry_date TEXT NOT NULL,
            content TEXT NOT NULL,
            plant_type TEXT NOT NULL DEFAULT 'flower',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE (user_id, entry_date)
        )
    ''')

    # Robust migration: inspect existing columns before altering
    entry_cols = {r[1] for r in conn.execute('PRAGMA table_info(entries)').fetchall()}
    log.info("entries columns: %s", entry_cols)

    if 'user_id' not in entry_cols:
        # Very old schema (no auth) — drop and recreate; old entries are unrecoverable anyway
        log.warning("Old entries schema detected (no user_id) — recreating table")
        conn.execute('DROP TABLE entries')
        conn.execute('''
            CREATE TABLE entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                entry_date TEXT NOT NULL,
                content TEXT NOT NULL,
                plant_type TEXT NOT NULL DEFAULT 'flower',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                UNIQUE (user_id, entry_date)
            )
        ''')
    elif 'plant_type' not in entry_cols:
        log.info("Adding plant_type column to entries")
        conn.execute("ALTER TABLE entries ADD COLUMN plant_type TEXT NOT NULL DEFAULT 'flower'")

    conn.commit()
    conn.close()
    log.info("DB initialised")


def get_plant_stage(days_ago: int) -> int:
    """Stage index 0–4. Full growth in 7 days."""
    if days_ago == 0: return 0
    if days_ago == 1: return 1
    if days_ago <= 3: return 2
    if days_ago <= 5: return 3
    return 4


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Нэвтрэх шаардлагатай'}), 401
        return f(*args, **kwargs)
    return decorated


@app.route('/')
def index():
    return render_template('gratitude.html')


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    password = data.get('password', '').strip()
    garden_name = data.get('garden_name', '').strip() or 'Миний Цэцэрлэг'

    if not name or not password:
        return jsonify({'error': 'Нэр болон нууц үг шаардлагатай'}), 400
    if len(name) < 2:
        return jsonify({'error': 'Нэр хамгийн багадаа 2 тэмдэгт байх ёстой'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Нууц үг хамгийн багадаа 6 тэмдэгт байх ёстой'}), 400

    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO users (name, password_hash, garden_name) VALUES (?, ?, ?)',
            (name, hash_password(password), garden_name)
        )
        conn.commit()
        user = conn.execute('SELECT * FROM users WHERE name = ?', (name,)).fetchone()
        session.permanent = True
        session['user_id'] = user['id']
        session['user_name'] = name
        return jsonify({'success': True, 'name': name, 'garden_name': garden_name})
    except Exception as e:
        if 'UNIQUE' in str(e):
            return jsonify({'error': 'Энэ нэр аль хэдийн бүртгэлтэй байна'}), 409
        return jsonify({'error': 'Алдаа гарлаа. Дахин оролдоно уу.'}), 500
    finally:
        conn.close()


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    password = data.get('password', '').strip()

    if not name or not password:
        return jsonify({'error': 'Нэр болон нууц үг шаардлагатай'}), 400

    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE name = ?', (name,)).fetchone()
    conn.close()

    if not user or not verify_password(user['password_hash'], password):
        return jsonify({'error': 'Нэр эсвэл нууц үг буруу байна'}), 401

    session.permanent = True
    session['user_id'] = user['id']
    session['user_name'] = user['name']
    return jsonify({'success': True, 'name': user['name'], 'garden_name': user['garden_name']})


@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})


@app.route('/api/me', methods=['GET'])
def me():
    if 'user_id' not in session:
        return jsonify({'logged_in': False})
    conn = get_db()
    user = conn.execute(
        'SELECT name, garden_name FROM users WHERE id = ?', (session['user_id'],)
    ).fetchone()
    conn.close()
    if not user:
        session.clear()
        return jsonify({'logged_in': False})
    return jsonify({'logged_in': True, 'name': user['name'], 'garden_name': user['garden_name']})


@app.route('/api/entry', methods=['POST'])
@login_required
def add_entry():
    data = request.get_json() or {}
    content = data.get('content', '').strip()
    plant_type = data.get('plant_type', 'flower')
    today = date.today().isoformat()

    if not content:
        return jsonify({'error': 'Талархлаа бичнэ үү'}), 400
    if len(content) > 1000:
        return jsonify({'error': 'Бичлэг хэт урт байна (1000 тэмдэгт хүртэл)'}), 400
    if plant_type not in VALID_PLANT_TYPES:
        plant_type = 'flower'

    conn = get_db()
    try:
        existing = conn.execute(
            'SELECT id FROM entries WHERE user_id = ? AND entry_date = ?',
            (session['user_id'], today)
        ).fetchone()
        if existing:
            return jsonify({'error': 'Өнөөдрийн бичлэг аль хэдийн байна. Маргааш дахин ирээрэй! 🌱'}), 409

        conn.execute(
            'INSERT INTO entries (user_id, entry_date, content, plant_type) VALUES (?, ?, ?, ?)',
            (session['user_id'], today, content, plant_type)
        )
        conn.commit()
        return jsonify({'success': True, 'message': 'Таны талархал цэцэрлэгт тарьж ургалаа! 🌱', 'plant_type': plant_type})
    except Exception as e:
        log.exception("add_entry failed:")
        msg = str(e) if app.debug else 'Алдаа гарлаа. Дахин оролдоно уу.'
        return jsonify({'error': msg}), 500
    finally:
        conn.close()


@app.route('/api/entries', methods=['GET'])
@login_required
def get_entries():
    conn = get_db()
    rows = conn.execute(
        'SELECT * FROM entries WHERE user_id = ? ORDER BY entry_date ASC',
        (session['user_id'],)
    ).fetchall()
    conn.close()

    today = date.today()
    result = []
    for row in rows:
        entry = dict(row)
        days_ago = (today - date.fromisoformat(row['entry_date'])).days
        entry['days_ago'] = days_ago
        entry['stage'] = get_plant_stage(days_ago)
        result.append(entry)
    return jsonify(result)


@app.route('/api/today', methods=['GET'])
@login_required
def check_today():
    today = date.today().isoformat()
    conn = get_db()
    row = conn.execute(
        'SELECT id, plant_type FROM entries WHERE user_id = ? AND entry_date = ?',
        (session['user_id'], today)
    ).fetchone()
    conn.close()
    if row:
        return jsonify({'has_entry': True, 'plant_type': row['plant_type']})
    return jsonify({'has_entry': False})


if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=True)
