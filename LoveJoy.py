from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///main.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username



@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()

        if existing_user:
            flash('Username or email already exists', 'error')
            return render_template('signup.html')

        new_user = User(username=username, email=email, password=password)

        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully', 'success')
        return redirect(url_for('welcome'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username, password=password).first()

        if user:
            flash('Login successful', 'success')
            # Redirect to the homepage for the logged-in user
            return redirect(url_for('homepage', username=username))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        new_password = request.form['new_password']

        user = User.query.filter_by(email=email, username=username).first()

        if user:
            # Update the user's password
            user.password = generate_password_hash(new_password)
            db.session.commit()

            flash('Password updated successfully', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid email or username', 'error')

    return render_template('forgot_password.html')

@app.route('/homepage/<username>')
def homepage(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return render_template('homepage.html', user=user)
    else:
        flash('User not found', 'error')
        return redirect(url_for('welcome'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5002, debug=True)
