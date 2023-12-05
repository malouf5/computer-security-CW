from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///main.db'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = 'static/images/profile_pics'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    profile_picture = db.Column(db.String(255))
    is_admin = db.Column(db.Boolean, default=False)
    evaluations = db.relationship('Evaluation', backref='user', lazy=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Evaluation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    image = db.Column(db.String(255))
    age = db.Column(db.Integer)
    request = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def create_upload_folder():
    upload_folder = app.config['UPLOAD_FOLDER']
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)

create_upload_folder()

@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        profile_pic = request.files.get('profile_picture')

        if profile_pic and allowed_file(profile_pic.filename):
            filename = secure_filename(profile_pic.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            profile_pic.save(file_path)
        else:
            file_path = "profile_pics/blank-profile.png"

        # Check if there are any users in the database
        existing_users = User.query.all()

        if existing_users:
            is_admin = False
        else:
            is_admin = True

        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            profile_picture=file_path,
            is_admin=is_admin
        )

        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully', 'success')
        login_user(new_user)
        return redirect(url_for('homepage'))

    return render_template('signup.html')

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    # Check if the user is an admin
    if not current_user.is_admin:
        abort(403)

    # Query all evaluations for the admin dashboard
    evaluations = Evaluation.query.all()

    return render_template('admin_dashboard.html', evaluations=evaluations)

@app.route('/admin_process_evaluation', methods=['POST'])
@login_required
def admin_process_evaluation():
    # Check if the user is an admin
    if not current_user.is_admin:
        abort(403)

    # Get the evaluation_id and action from the form
    evaluation_id = request.form.get('evaluation_id')
    action = request.form.get('action')

    # Retrieve the evaluation
    evaluation = Evaluation.query.get(evaluation_id)

    # Process the evaluation based on the action
    if action == 'accept':
        # Implement logic for accepting the evaluation
        # For example, update the evaluation status
        evaluation.status = 'accepted'
    elif action == 'decline':
        # Implement logic for declining the evaluation
        # For example, update the evaluation status
        evaluation.status = 'declined'

    # Commit changes to the database
    db.session.commit()

    # Redirect back to the admin dashboard
    return redirect(url_for('admin_dashboard'))

@app.route('/uploaded_file/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful', 'success')
            return redirect(url_for('homepage'))
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
            user.password = generate_password_hash(new_password)
            db.session.commit()

            flash('Password updated successfully', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid email or username', 'error')

    return render_template('forgot_password.html')

@app.route('/evaluation', methods=['GET', 'POST'])
@login_required
def evaluation():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        image = request.files.get('image')
        age = request.form.get('age')
        request_text = request.form['request']

        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(file_path)
        else:
            file_path = None

        new_evaluation = Evaluation(
            name=name,
            description=description,
            image=file_path,
            age=age,
            request=request_text,
            user_id=current_user.id
        )

        db.session.add(new_evaluation)
        db.session.commit()

        flash('Evaluation submitted successfully', 'success')
        return redirect(url_for('homepage', username=current_user.username))

    return render_template('evaluationpage.html')

@app.route('/homepage')
@login_required
def homepage():
    return render_template('homepage.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('welcome'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5002, debug=True)
