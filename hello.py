from flask import Flask, render_template, request, redirect, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import markdown
from collections import deque, Counter
from passlib.hash import sha256_crypt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sqlite3
from flask_simplemde import SimpleMDE
import time
import math
from datetime import datetime
import bleach

app = Flask(__name__)
app.config['SIMPLEMDE_JS_IIFE'] = True
app.config['SIMPLEMDE_USE_CDN'] = True
SimpleMDE(app)

login_manager = LoginManager()
login_manager.init_app(app)
users = [[''], [{'count': 0, 'time': datetime.now()}]]

key = get_random_bytes(16)
iv = get_random_bytes(16)
app.secret_key = "206363ef77d567cc511df5098695d2b85058952afd5e2b1eecd5aed981805e60"

bleach.sanitizer.ALLOWED_TAGS.extend(['h1', 'p', 'a', 'img'])
attrs = allowed_attrs = {'a': ['href', 'rel'], 'img': ['src', 'alt']}

DATABASE = "./sqlite3.db"

class User(UserMixin):
    pass

@login_manager.user_loader
def user_loader(username):
    if username is None:
        return None

    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute(f"SELECT username, password FROM user WHERE username = ?", [username])
    row = sql.fetchone()
    try:
        username, password = row
    except:
        return None

    user = User()
    user.id = username
    user.password = password
    return user


@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    user = user_loader(username)
    return user


recent_users = deque(maxlen=3)

@app.route("/", methods=["GET","POST"])
def login():

    if request.method == "GET":
        return render_template("index.html")
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username in users[0]:
            index = users[0].index(username)
            if((datetime.now() - users[1][index]['time']).total_seconds()) > 60:
                users[1][index] = {'count': 1, 'time': datetime.now()}
            else:
                users[1][index] = {'count': users[1][index]['count'] + 1, 'time': datetime.now()}
        if username not in users[0]:
            users[0].append(username)
            users[1].append({'count': 1, 'time': datetime.now()})

        user = user_loader(username)
        if user is None:
            return "Nieprawidłowy login lub hasło", 401
        if users[1][users[0].index(username)]['count'] > 3:
            abort(403, 'Za dużo błędnych prób. Wait a minute')
        if sha256_crypt.verify(password, user.password):
            login_user(user)
            time.sleep(1)
            return redirect('/hello')
        else:
            return "Nieprawidłowy login lub hasło", 401

@app.route("/logout")
def logout():
    logout_user()
    return redirect("/")

@app.route("/hello", methods=['GET'])
@login_required
def hello():
    if request.method == 'GET':
        print(current_user.id)
        username = current_user.id

        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql.execute(f"SELECT id FROM notes WHERE share == 1 OR username == ?", [username])
        notes = sql.fetchall()

        return render_template("hello.html", username=bleach.clean(username), notes=notes)

@app.route("/render", methods=['POST'])
@login_required
def render():
    md = request.form.get("markdown","")
    rendered = markdown.markdown(md)
    username = current_user.id

    aes = AES.new(key, AES.MODE_CFB, iv)
    daes = AES.new(key, AES.MODE_CFB, iv)
    encd = aes.encrypt(rendered.encode())


    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute(f"INSERT INTO notes (username, note) VALUES (?, ?)", [username, encd])
    db.commit()
    return render_template("markdown.html", rendered=bleach.clean(daes.decrypt(encd).decode(), tags=bleach.sanitizer.ALLOWED_TAGS, attributes=attrs))

@app.route("/render/<rendered_id>")
@login_required
def render_old(rendered_id):
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute(f"SELECT username, note, share FROM notes WHERE id == ?", [rendered_id])

    try:
        username, rendered, share = sql.fetchone()
        aes = AES.new(key, AES.MODE_CFB, iv)
        decd = aes.decrypt(rendered)
        if username != current_user.id and share == 0:
            return "Access to note forbidden", 403
        return render_template("markdown.html", rendered_id=bleach.clean(rendered_id), rendered=bleach.clean(decd.decode(), tags=bleach.sanitizer.ALLOWED_TAGS, attributes=attrs))
    except:
        return "Note not found", 404

@app.route("/share/<rendered_id>")
@login_required
def share(rendered_id):
    username = current_user.id
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute(f"UPDATE notes SET share = 1 WHERE id == ? AND username == ?", [rendered_id, username])
    db.commit()

    return render_template("share.html")

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template("register.html")
    if request.method == 'POST':
        db = sqlite3.connect(DATABASE)
        sql = db.cursor()

        username = request.form.get('username')
        password = request.form.get('password')

        sql.execute(f"SELECT * FROM user WHERE username == ?", [username])
        user = sql.fetchone()

        if user:
            print(user)
            return render_template("register.html", message="Użytkownik już zarejestrowany. Nie możesz dokonać ponownej rejestracji.")
        if len(username) < 3:
            return render_template("register.html", message="Nazwa użytkownika jest za krótka.")
        if len(username) > 20:
            return render_template("register.html", message="Nazwa użytkownika jest za długa.")
        if len(password) < 8:
            return render_template("register.html", message="Hasło jest za krótkie.")
        if len(password) > 20:
            return render_template("register.html", message="Hasło jest za długie.")
        if entropy(password) < 2.5:
            return render_template("register.html", message="Hasło jest zbyt proste.")

        sql.execute(f"INSERT INTO user (username, password) VALUES (?, ?)", [username, sha256_crypt.hash(password)])

        db.commit()

        return redirect('/')

def entropy(s):
    p, lns = Counter(s), float(len(s))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

if __name__ == "__main__":
    print("[*] Init database!")
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute("DROP TABLE IF EXISTS user;")
    sql.execute("CREATE TABLE user (username VARCHAR(32), password VARCHAR(128));")
    sql.execute("DELETE FROM user;")
    sql.execute("INSERT INTO user (username, password) VALUES ('bach', '$5$rounds=535000$TSnXpxntSBo5ztYy$ob7pFU9AxXet43zTPNRBbiNM5QAPvhByaKmoRHFSSs/');")
    sql.execute("INSERT INTO user (username, password) VALUES ('john', '$5$rounds=535000$L/giQTew/Q1Ye7zr$TtLnqIfgyWsycw740twdskcCzoUEkK0V20xGIT0SiIC');")
    sql.execute("INSERT INTO user (username, password) VALUES ('bob', '$5$rounds=535000$svyYGZviIcZmOfmx$GhWZmNlI6bRnJErF9kyyJudRa3l1d.ohbYGNeKwW6Z6');")

    aes_1 = AES.new(key, AES.MODE_CFB, iv)
    aes_2 = AES.new(key, AES.MODE_CFB, iv)
    note_1 = aes_1.encrypt('To nie jest sekret!'.encode())
    note_2 = aes_2.encrypt('To jest sekret!'.encode())

    sql.execute("DROP TABLE IF EXISTS notes;")
    sql.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, username VARCHAR(32), share INTEGER DEFAULT 0, note VARCHAR(256));")
    sql.execute("DELETE FROM notes;")
    sql.execute(f"INSERT INTO notes (username, note, share, id) VALUES ('bob', ? , 1, 1);", [note_1])
    sql.execute(f"INSERT INTO notes (username, note, id) VALUES ('bob', ?, 2);", [note_2])
    db.commit()

    app.run("0.0.0.0", 5000)
