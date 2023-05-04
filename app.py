from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/')
def main():
    return 'Welcome to the main page!'

@app.route('/profile/<user_id>')
def profile(user_id):
    first_name = 'John'
    last_name = 'Doe'
    department = 'Sales'
    public_key = 'AABBCCDDEEFF00112233445566778899'
    status = 'Active'
    return render_template('profile.html', first_name=first_name, last_name=last_name, department=department, public_key=public_key, status=status)

@app.route('/works', methods=['GET', 'POST'])
def works():
    if request.method == 'GET':
        return 'Here are the works'
    elif request.method == 'POST':
        work_name = request.form['work_name']
        return f'Added work: {work_name}'

if __name__ == '__main__':
    app.run()