from flask import Flask, request, session, render_template, redirect, url_for, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import psycopg2
from psycopg2.extras import RealDictCursor
import os
import sqlite3
from os import path
import re

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'секретно-секретный секрет')
app.config['DB_TYPE'] = os.getenv('DB_TYPE', 'postgres')

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'avatars')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def db_connect():
    if current_app.config['DB_TYPE'] == 'postgres':
        conn = psycopg2.connect(
            host='127.0.0.1',
            database='sveta_rgz',
            user='sveta_rgz',
            password='12345'
        )
        cur = conn.cursor(cursor_factory=RealDictCursor)
    else:
        dir_path = path.dirname(path.realpath(__file__))
        db_path = path.join(dir_path, "database.db")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
    return conn, cur

def db_close(conn, cur):
    conn.commit()
    cur.close()
    conn.close()

# Функция для валидации логина
def validate_login(login):
    if not login:
        return False
    return re.match(r'^[A-Za-z0-9_.-]+$', login) is not None

# Функция для валидации пароля
def validate_password(password):
    if not password:
        return False
    return re.match(r'^[A-Za-z0-9_.-]+$', password) is not None


@app.route('/')
def main():
    conn, cur = db_connect()

    if 'user_id' in session:
        cur.execute("""
            SELECT ads.id, ads.title, ads.content, users.name AS author, users.email
            FROM ads
            JOIN users ON ads.user_id = users.id;
        """)
    else:
        cur.execute("""
            SELECT ads.id, ads.title, ads.content, users.name AS author
            FROM ads
            JOIN users ON ads.user_id = users.id;
        """)
    ads = cur.fetchall()

    db_close(conn, cur)

    return render_template('main.html', ads=ads)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    login = request.form.get('login')
    password = request.form.get('password')
    name = request.form.get('name')
    email = request.form.get('email')
    about = request.form.get('about', '')
    avatar = request.files.get('avatar')

    if not login or not password or not name or not email:
        return render_template('register.html', error='Заполните все обязательные поля')
    
    if not validate_login(login):
        return render_template('register.html', error='Логин должен состоять из латинских букв, цифр и знаков препинания')
    
    if not validate_password(password):
        return render_template('register.html', error='Пароль должен состоять из латинских букв, цифр и знаков препинания')

    conn, cur = db_connect()
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT id FROM users WHERE login=%s;", (login,))
    else:
        cur.execute("SELECT id FROM users WHERE login=?;", (login,))
    
    if cur.fetchone():
        db_close(conn, cur)
        return render_template('register.html', error='Пользователь с таким логином уже существует')

    password_hash = generate_password_hash(password)

    filename = None
    if avatar:
        filename = secure_filename(avatar.filename)
        avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        avatar.save(avatar_path)

    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("""
            INSERT INTO users (login, password, name, email, about, avatar, is_admin)
            VALUES (%s, %s, %s, %s, %s, %s, %s);
        """, (login, password_hash, name, email, about, filename, False))
    else:
        cur.execute("""
            INSERT INTO users (login, password, name, email, about, avatar, is_admin)
            VALUES (?, ?, ?, ?, ?, ?, ?);
        """, (login, password_hash, name, email, about, filename, False))

    db_close(conn, cur)

    return redirect(url_for('main'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')

        conn, cur = db_connect()

        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("SELECT * FROM users WHERE login=%s;", (login,))
        else:
            cur.execute("SELECT * FROM users WHERE login=?;", (login,))
        user = cur.fetchone()

        if user and check_password_hash(user['password'], password):
            user = dict(user)
            session['user_id'] = user['id']
            session['is_admin'] = user.get('is_admin', False)
            db_close(conn, cur)
            return redirect(url_for('main'))
        else:
            db_close(conn, cur)
            return render_template('login.html', error='Неверный логин или пароль')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main'))

@app.route('/ads')
def ads():

    conn, cur = db_connect()

    cur.execute("""
        SELECT ads.id, ads.title, ads.content, users.name AS author, users.email
        FROM ads
        JOIN users ON ads.user_id = users.id;
    """)
    ads = cur.fetchall()

    db_close(conn, cur)

    return render_template('ads.html', ads=ads)

@app.route('/create_add', methods=['GET', 'POST'])
def create_add():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        user_id = session['user_id']

        conn, cur = db_connect()
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("INSERT INTO ads (title, content, user_id) VALUES (%s, %s, %s);", (title, content, user_id))
        else:
            cur.execute("INSERT INTO ads (title, content, user_id) VALUES (?, ?, ?);", (title, content, user_id))
        db_close(conn, cur)

        return redirect(url_for('profile'))

    return render_template('create_add.html')

@app.route('/edit_add/<int:ad_id>', methods=['GET', 'POST'])
def edit_add(ad_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn, cur = db_connect()
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT * FROM ads WHERE id=%s;", (ad_id,))
    else:
        cur.execute("SELECT * FROM ads WHERE id=?;", (ad_id,))
    ad = dict(cur.fetchone())

    if ad is None or ad['user_id'] != session['user_id']:
        return redirect(url_for('main'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("UPDATE ads SET title=%s, content=%s WHERE id=%s;", (title, content, ad_id))
        else:
            cur.execute("UPDATE ads SET title=?, content=? WHERE id=?;", (title, content, ad_id))
        db_close(conn, cur)
        return redirect(url_for('profile'))

    db_close(conn, cur)
    return render_template('edit_add.html', ad=ad)

@app.route('/delete_ad/<int:ad_id>', methods=['POST'])
def delete_ad(ad_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn, cur = db_connect()
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT * FROM ads WHERE id=%s;", (ad_id,))
    else:
        cur.execute("SELECT * FROM ads WHERE id=?;", (ad_id,))
    ad = dict(cur.fetchone())

    if ad is None or ad['user_id'] != session['user_id']:
        return redirect(url_for('main'))

    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("DELETE FROM ads WHERE id=%s;", (ad_id,))
    else:
        cur.execute("DELETE FROM ads WHERE id=?;", (ad_id,))
    db_close(conn, cur)
    return redirect(url_for('profile'))

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn, cur = db_connect()
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT * FROM users WHERE id=%s;", (session['user_id'],))
    else:
        cur.execute("SELECT * FROM users WHERE id=?;", (session['user_id'],))
    user = dict(cur.fetchone())

    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT * FROM ads WHERE user_id=%s;", (session['user_id'],))
    else:
        cur.execute("SELECT * FROM ads WHERE user_id=?;", (session['user_id'],))
    ads = [dict(ad) for ad in cur.fetchall()]

    db_close(conn, cur)
    return render_template('profile.html', user=user, ads=ads)

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn, cur = db_connect()
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT * FROM users WHERE id=%s;", (session['user_id'],))
    else:
        cur.execute("SELECT * FROM users WHERE id=?;", (session['user_id'],))
    user = cur.fetchone()

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        about = request.form.get('about', '')
        avatar = request.files.get('avatar')

        if avatar:
            filename = secure_filename(avatar.filename)
            avatar.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            if current_app.config['DB_TYPE'] == 'postgres':
                cur.execute("UPDATE users SET name=%s, email=%s, about=%s, avatar=%s WHERE id=%s;",
                            (name, email, about, filename, session['user_id']))
            else:
                cur.execute("UPDATE users SET name=?, email=?, about=?, avatar=? WHERE id=?;",
                            (name, email, about, filename, session['user_id']))
        else:
            if current_app.config['DB_TYPE'] == 'postgres':
                cur.execute("UPDATE users SET name=%s, email=%s, about=%s WHERE id=%s;",
                            (name, email, about, session['user_id']))
            else:
                cur.execute("UPDATE users SET name=?, email=?, about=? WHERE id=?;",
                            (name, email, about, session['user_id']))

        db_close(conn, cur)
        return redirect(url_for('profile'))

    db_close(conn, cur)
    return render_template('edit_profile.html', user=user)

@app.route('/users')
def users():

    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('main'))

    conn, cur = db_connect()

    cur.execute("SELECT * FROM users;")
    users = cur.fetchall()

    db_close(conn, cur)

    return render_template('users.html', users=users)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):

    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('main'))

    conn, cur = db_connect()

    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("DELETE FROM users WHERE id=%s;", (user_id,))
    else:
        cur.execute("DELETE FROM users WHERE id=?;", (user_id,))

    db_close(conn, cur)

    return redirect(url_for('users'))

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('main'))

    conn, cur = db_connect()
    if current_app.config['DB_TYPE'] == 'postgres':
        cur.execute("SELECT * FROM users WHERE id=%s;", (user_id,))
    else:
        cur.execute("SELECT * FROM users WHERE id=?;", (user_id,))
    user = dict(cur.fetchone())

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        about = request.form.get('about', '')
        avatar = request.files.get('avatar')

        if avatar:
            filename = secure_filename(avatar.filename)
            avatar.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            if current_app.config['DB_TYPE'] == 'postgres':
                cur.execute("UPDATE users SET name=%s, email=%s, about=%s, avatar=%s WHERE id=%s;",
                            (name, email, about, filename, user_id))
            else:
                cur.execute("UPDATE users SET name=?, email=?, about=?, avatar=? WHERE id=?;",
                            (name, email, about, filename, user_id))
        else:
            if current_app.config['DB_TYPE'] == 'postgres':
                cur.execute("UPDATE users SET name=%s, email=%s, about=%s WHERE id=%s;",
                            (name, email, about, user_id))
            else:
                cur.execute("UPDATE users SET name=?, email=?, about=? WHERE id=?;",
                            (name, email, about, user_id))

        db_close(conn, cur)
        return redirect(url_for('users'))

    db_close(conn, cur)
    return render_template('edit_user.html', user=user)

@app.route('/delete_ad_admin/<int:ad_id>', methods=['POST'])
def delete_ad_admin(ad_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn, cur = db_connect()

    is_admin = session.get('is_admin', False)

    if is_admin:

        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("DELETE FROM ads WHERE id=%s;", (ad_id,))
        else:
            cur.execute("DELETE FROM ads WHERE id=?;", (ad_id,))
    else:

        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("SELECT * FROM ads WHERE id=%s;", (ad_id,))
        else:
            cur.execute("SELECT * FROM ads WHERE id=?;", (ad_id,))
        ad = cur.fetchone()

        if ad and ad['user_id'] == session['user_id']:

            if current_app.config['DB_TYPE'] == 'postgres':
                cur.execute("DELETE FROM ads WHERE id=%s;", (ad_id,))
            else:
                cur.execute("DELETE FROM ads WHERE id=?;", (ad_id,))
        else:

            db_close(conn, cur)
            return redirect(url_for('main'))

    db_close(conn, cur)
    return redirect(url_for('main'))