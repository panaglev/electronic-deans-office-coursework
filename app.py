from flask import Flask, render_template, request, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import dsa


app = Flask(__name__)
app.secret_key = 'noonewil2#WC3leverEQ@*uknowwQ@&Y$fhatisthe@*uen[390ripsecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String, nullable=False)
    last_name = db.Column(db.String, nullable=False)
    username = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)
    department = db.Column(db.String, nullable=False)
    public_key = db.Column(db.String, unique=True, nullable=False)
    private_key = db.Column(db.String, nullable=False)
    status = db.Column(db.String, nullable=False)

@app.route('/')
def main():
    return 'Welcome to the main page!'

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Получение данных с форм
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        username = request.form['username']
        password = request.form['password']
        department = request.form['department']
        status = request.form['status']

        # Генерация ключей с помощью нашего класса
        public_key, private_key = dsa.generate_keys()

        # Проверка зарегистрирован ли уже пользователь
        user = User.query.filter_by(username=username).first()
        if user:
            return render_template('register.html', error='This username already registered')

        # Создание нового пользователя и добавление его в базу данных
        new_user = User(first_name=first_name,
                        last_name=last_name,
                        username=username,
                        password=generate_password_hash(password),
                        department=department,
                        public_key=public_key,
                        private_key=private_key,
                        status=status)
        db.session.add(new_user)
        db.session.commit()

        # Сохранение имени пользователя в сессии
        session['user'] = username

        # Костыль, может можно было сделать лучше, но я не гений, не я гений, но не в этом
        user = User.query.filter_by(username=username).first()

        # Перенаправление пользователя на его домашнюю страницу
        return redirect(url_for('profile', user_id = user.id,
                                first_name=new_user.first_name,
                                last_name=new_user.last_name,
                                department=new_user.department,
                                public_key=new_user.public_key,
                                status=new_user.status))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Получение данных с форм
        username = request.form['username']
        password = request.form['password']

        # Получение пользователя из базы данных с помощью username
        user = User.query.filter_by(username=username).first()

        # Проверка пароля(совпадают ли хэши)
        if not user or not check_password_hash(user.password, password):
            return render_template('login.html', error='Invalid username or password')

        # Сохранение имени пользователя в сессии
        session['user'] = username

        # Костыль, может можно было сделать лучше, но я не гений, не я гений, но не в этом
        user = User.query.filter_by(username=username).first()

        # Перенаправление пользователя на домашнюю страницу
        return redirect(url_for('profile', user_id=user.id,
                                first_name=user.first_name,
                                last_name=user.last_name,
                                department=user.department,
                                public_key=user.public_key,
                                status=user.status))

    return render_template('login.html')

@app.route('/profile/<user_id>')
def profile(user_id):
    # Получение пользователя по его айди
    user = User.query.filter_by(id=user_id).first()

    # Рендер шаблона и передача в него информации 
    return render_template('profile.html',
                           first_name=user.first_name,
                           last_name=user.last_name,
                           department=user.department,
                           public_key=user.public_key,
                           status=user.status)


@app.route('/works', methods=['GET', 'POST'])
def works():
    if request.method == 'GET':
        return 'Here are the works'
    elif request.method == 'POST':
        work_name = request.form['work_name']
        return f'Added work: {work_name}'

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000)