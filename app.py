from flask import Flask, render_template

app = Flask(__name__)

@app.route('/profile')
def profile():
    # These variables would normally come from your application logic or a database
    first_name = 'John'
    last_name = 'Doe'
    department = 'Sales'
    public_key = 'AABBCCDDEEFF00112233445566778899'
    status = 'Active'
    return render_template('profile.html', first_name=first_name, last_name=last_name, department=department, public_key=public_key, status=status)

if __name__ == '__main__':
    app.run()