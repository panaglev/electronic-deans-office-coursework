import os
import dsa
import jwt
import hashlib
import datetime
import subprocess
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, session, url_for, abort, make_response, send_file


send_nudes = send_file
app = Flask(__name__)
app.secret_key = 'noonewil2#WC3leverEQ@*uknowwQ@&Y$fhatisthe@*uen[390ripsecretkey'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'downloads')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String, nullable=False)
    last_name = db.Column(db.String, nullable=False)
    username = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)
    department = db.Column(db.String, nullable=False)
    public_key = db.Column(db.String, unique=True, nullable=False)
    private_key = db.Column(db.String, nullable=False)
    role = db.Column(db.String, nullable=False)

class Work(db.Model):
    __tablename__ = 'works'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    work_name = db.Column(db.String, nullable=False)
    approved = db.Column(db.String, nullable=False)
    base_hash = db.Column(db.String, nullable=False)
    approved_hash = db.Column(db.String, nullable=True)

def jwt_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("token")
        if not token:
            abort(401, description='Missing token')
        try:
            data = jwt.decode(token, 'SECRET', algorithms=['HS256'])
        except jwt.InvalidTokenError:
            abort(401, description='Invalid token')
        return func(*args, **kwargs)
    return wrapper

def calculate_pdf_hash(file_path):
    with open(file_path, 'rb') as file:
        content = file.read()
        hash_object = hashlib.sha256(content)
        return hash_object.hexdigest()

@app.route('/')
def main():
    return 'Welcome to the main page!'

#@app.route('/approve/<public_key>/<work_name>', methods=['GET'])
#def approve_work(public_key, work_name):
@app.route('/approve/<username>/<work_name>', methods=['GET'])
def approve_work(username, work_name):
    # 1. Взять из бд пользователей приватный ключ подписывающего
    #user = User.query.filter_by(public_key=public_key).first()
    user = User.query.filter_by(username=username).first()
    # 2. Взять из бд работ хэш работы по ее названию и айди пользователя
    work = Work.query.filter_by(work_name=work_name).first()
    # 3. Подписанную строчку положить в таблицу работ и изменить статус на подписано 
    signature = dsa.sign_message((work.base_hash).encode(), user.private_key)
    work.approved_hash = signature
    work.approved = "Yes"
    db.session.commit()
    #print(dsa.verify_signature((work.base_hash).encode(), signature, user.public_key))
    return 'Signed!'

@app.route('/download/<username>/<path:filename>', methods=['GET'])
def download_file(username, filename):
    return send_nudes("downloads/"+username+"/"+filename, as_attachment=True)

@app.route('/register', methods=['GET', 'POST'])
def register():
    # При переходе на страницу регистрации надо посмотреть по какому методу 
    # Был произведен заход на страницу
    # Если GET, то проверяем авторизован ли пользователь
    # Если да, то посылаем его куда подальше, но в нашем случае на его личную страницу
    # Если нет, то ничего не делаем, просто показываем страницу с регой
    if request.method == 'GET':
        # Получение токена из куки
        token = request.cookies.get("token")

        # Вылавливаем момент с активной сессией
        if token != None:
            data = jwt.decode(token, 'SECRET', "HS256")
            user = User.query.filter_by(username=data['username']).first()
            return make_response(redirect(url_for('profile', user_id=user.id,
                                    first_name=user.first_name,
                                    last_name=user.last_name,
                                    department=user.department,
                                    public_key=user.public_key,
                                    role=user.role)))
    # Если запрос пост, то регистрируем пользователя 
    if request.method == 'POST':
        # Получение данных с форм
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        username = request.form['username']
        password = request.form['password']
        department = request.form['department']

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
                        role="Student")
        db.session.add(new_user)
        db.session.commit()

        # Костыль, может можно было сделать лучше, но я не гений, не я гений, но не в этом
        user = User.query.filter_by(username=username).first()

        # Создание нагрузки которая войдет в жэвэтэ токен 
        payload = {
            'username': user.username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
            }
        secret_key = 'SECRET' # os.environ.get('SECRET')

        # Создание токена
        token = jwt.encode(payload, secret_key, algorithm='HS256')

        # Создание ответа с перенаправлением на страницу пользователя и установкой токена в куку
        response = make_response(redirect(url_for('profile', user_id=user.id,
                                first_name=user.first_name,
                                last_name=user.last_name,
                                department=user.department,
                                public_key=user.public_key,
                                role=user.role)))
        response.set_cookie('token', f'{token}')
        return response

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Если запрос GET, то надо узнать, авторизирован ли пользователь или нет
    # Если авторизирован, то кинуть на домашнюю страницу
    # В противном случае показать страницу авторизации 
    if request.method == "GET":
        # Получение токена из куки
        token = request.cookies.get("token")

        # Вылавливаем момент с активной сессией
        if token != None:
            data = jwt.decode(token, 'SECRET', "HS256")
            user = User.query.filter_by(username=data['username']).first()
            if user.role == "Dickunat":
                works = Work.query.filter_by(approved="No").all()
                return make_response(redirect(url_for('profile', user_id=user.id,
                                    first_name=user.first_name,
                                    last_name=user.last_name,
                                    department=user.department,
                                    public_key=user.public_key,
                                    role=user.role,
                                    works=works)))
            else:
                return make_response(redirect(url_for('profile', user_id=user.id,
                                    first_name=user.first_name,
                                    last_name=user.last_name,
                                    department=user.department,
                                    public_key=user.public_key,
                                    role=user.role)))

    # Если запрос POST, то собираем все данные из форм, проверяем пользователя и создаем ему токен в куке(если все успешно)
    if request.method == 'POST':
        # Получение данных с форм
        username = request.form['username']
        password = request.form['password']

        # Получение пользователя из базы данных с помощью username
        user = User.query.filter_by(username=username).first()

        # Проверка пароля(совпадают ли хэши)
        if not user or not check_password_hash(user.password, password):
            return render_template('login.html', error='Invalid username or password')

        # Костыль, может можно было сделать лучше, но я не гений, не, я гений, но не в этом
        user = User.query.filter_by(username=username).first()

        # Создание нагрузки которая войдет в жэвэтэ токен 
        payload = {
            'username': user.username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
            }
        secret_key = 'SECRET' # os.environ.get('SECRET')
        
        # Создание токена
        token = jwt.encode(payload, secret_key, algorithm='HS256')

        if user.role == "Dickunat":
            works = Work.query.filter_by(approved="No").all()
            response = make_response(redirect(url_for('profile', user_id=user.id,
                                first_name=user.first_name,
                                last_name=user.last_name,
                                department=user.department,
                                public_key=user.public_key,
                                role=user.role,
                                works=works)))
            response.set_cookie('token', f'{token}')
            return response
        else:
            response = make_response(redirect(url_for('profile', user_id=user.id,
                                first_name=user.first_name,
                                last_name=user.last_name,
                                department=user.department,
                                public_key=user.public_key,
                                role=user.role)))
            response.set_cookie('token', f'{token}')
            return response
    return render_template('login.html')

@app.route('/profile/<user_id>')
def profile(user_id):
    # Получение пользователя по его айди
    user = User.query.filter_by(id=user_id).first()

    document = Work.query.filter_by(user_id=user_id).all()

    work = Work.query.filter_by(approved="No").all()

    # Рендер шаблона и передача в него информации 
    return render_template('profile.html',
                           first_name=user.first_name,
                           last_name=user.last_name,
                           username=user.username,
                           department=user.department,
                           public_key=user.public_key,
                           role=user.role,
                           documents=document,
                           works=work)

@app.route('/upload')
# Жэвэтэ токен который не пущает на сайт неавторизованного пользователя
@jwt_required
def upload_file():
   # Просто возвращает страницу, на которой происходит загрузка файла 
   return render_template('upload.html')
	
@app.route('/uploader', methods = ['POST'])
# Жэвэтэ токен который не пущает на сайт неавторизованного пользователя
@jwt_required
def uploader_file():
    # Получает токен из куки
    token = request.cookies.get("token")
    
    # Декодирование жэвэтэ токена
    data = jwt.decode(token, 'SECRET', "HS256")
    
    # Получение из запроса фалйа и его проверка 
    f = request.files['file']
    filename = secure_filename(f.filename)

    # Логика такова, если у пользователя нету его личной папки с файлами, то она создается и потом туда сгружается файл
    try:
        # Проверка наличия папки пользователя заливающего файл
        result = subprocess.check_output(f"ls downloads | grep {data['username']}", stderr=subprocess.STDOUT)
    except FileNotFoundError:
        # Создание папки если ее нету
        os.system(f"mkdir downloads/{data['username']}")
    finally:
        # Загрузка файла 
        filepath = os.path.join(app.config['UPLOAD_FOLDER']+f"/{data['username']}", filename)
        f.save(filepath)

        # Добавление в бд информации о загруженном файле
        user = User.query.filter_by(username=data['username']).first()
        new_record = Work(user_id=user.id,
                          work_name=filename,
                          approved="No",
                          base_hash=calculate_pdf_hash(filepath))
        db.session.add(new_record)
        db.session.commit()

    return 'file uploaded successfully'

@app.route('/works', methods=['GET', 'POST'])
def works():
    rows = [
        {'first_name': 'John', 'last_name': 'Doe', 'department': 'Sales', 'work_name': 'Sale Report', 'id': 1},
        {'first_name': 'Jane', 'last_name': 'Doe', 'department': 'Marketing', 'work_name': 'Social Media Campaign', 'id': 2},
        {'first_name': 'Bob', 'last_name': 'Smith', 'department': 'Engineering', 'work_name': 'Product Design', 'id': 3},
    ]
    return render_template('works.html', rows=rows)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()