from flask import Flask, redirect, url_for, render_template, request, session, flash, jsonify
from datetime import timedelta, datetime
from flask_sqlalchemy import SQLAlchemy
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///default.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.permanent_session_lifetime = timedelta(minutes=5)

db = SQLAlchemy(app)


class users(db.Model):
    ''' Таблица пользователей '''
    _id = db.Column("id", db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    password = db.Column(db.String(200))  # Храним пароли в открытом виде
    role = db.Column(db.String(15), default="user")

    def __init__(self, name, email, password, role):
        self.name = name
        self.email = email
        self.password = password
        self.role = role


class Post(db.Model):
    ''' Таблица для хранения записей пользователей '''
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('users', backref=db.backref('posts', lazy=True))

    def __init__(self, content, user_id):
        self.content = content
        self.user_id = user_id


with app.app_context():
    db.create_all()

    admin_name = os.getenv("ADMIN")
    admin_email = os.getenv("ADMIN_EMAIL")
    admin_password = os.getenv("ADMIN_PASSWORD")

    admin_user = users.query.filter_by(name=admin_name).first()
    if not admin_user:
        admin_user = users(name=admin_name, email=admin_email, password=admin_password, role="admin")
        db.session.add(admin_user)
        db.session.commit()

        flag_post = Post(content="practice{this_is_the_flag}", user_id=admin_user._id)
        db.session.add(flag_post)
        db.session.commit()



@app.route("/")
def home():
    """Домашняя страница"""
    posts = Post.query.order_by(Post.timestamp.desc()).all()

    for post in posts:
        admin_user = users.query.filter_by(role="admin").first()
        if admin_user and post.user_id == admin_user._id:
            if 'role' not in session or session.get('role') != 'admin':
                post.content = "************"  # Скрываем флаг для всех, кроме админа

    return render_template("index.html", posts=posts)



@app.route("/register", methods=["POST", "GET"])
def register():
    ''' Эндпоинт для регистрации пользователя '''
    if request.method == "POST":
        username = request.form["nm"]
        email = request.form["email"]
        password = request.form["password"]
        found_user = users.query.filter_by(name=username).first()

        if found_user:
            flash("User already exists!")
            return redirect(url_for("register"))

        new_user = users(name=username, email=email, password=password, role="user")
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful!")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/check_password", methods=["GET", "POST"])
def check_password():
    """Эндпоинт для Blind SQL Injection"""
    if request.method == "GET":
        return render_template("check_password.html")

    elif request.method == "POST":
        user = request.form.get("user")
        condition = request.form.get("condition")  # Например, "LENGTH(password) = 12"

        # Уязвимый SQL-запрос (Blind SQL Injection)
        query = f"SELECT * FROM users WHERE name = '{user}' AND {condition}"

        # Открываем "сырой" коннект к БД
        conn = db.engine.raw_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(query)
            result = cursor.fetchone()
        except Exception as e:
            # Логируем ошибку, но не возвращаем её пользователю
            print(f"SQL Error: {e}")
            result = None
        finally:
            cursor.close()
            conn.close()

        # Возвращаем бинарный ответ (True/False)
        return jsonify({"success": bool(result)})


@app.route("/login", methods=["GET", "POST"])
def login():
    """Эндпоинт для авторизации"""
    if request.method == "POST":
        user = request.form["nm"]
        password = request.form["password"]

        # Поиск пользователя в базе данных
        found_user = users.query.filter_by(name=user, password=password).first()

        if found_user:
            session.permanent = True
            session['user'] = found_user.name
            session['role'] = found_user.role
            flash("Login successful!")
            return redirect(url_for("home"))
        else:
            flash("Invalid username or password")
            return redirect(url_for("login"))

    return render_template("login.html")



@app.route("/text", methods=["POST", "GET"])
def text():
    """Эндпоинт для добавления записи на страницу"""
    if 'user' not in session:
        flash("You need to login first!")
        return redirect(url_for("login"))

    if request.method == "POST":
        content = request.form["content"]
        user = users.query.filter_by(name=session['user']).first()

        if user:
            new_post = Post(content=content, user_id=user._id)
            db.session.add(new_post)
            db.session.commit()
            flash("Post added successfully!")
            return redirect(url_for("home"))

    return render_template("text.html")


@app.route("/logout")
def logout():
    """Эндпоинт для выхода из системы"""
    session.pop('user', None)
    session.pop('role', None)
    flash("You have been logged out!")

    response = redirect(url_for("home"))
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response



if __name__ == "__main__":
    app.run(debug=False)
