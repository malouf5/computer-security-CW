from flask import Flask, render_template, request, redirect, flash, send_from_directory, abort, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from flask import session
from flask_wtf.csrf import CSRFProtect, CSRFError
import requests
import random
import string
import os



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///main.db'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg'}
app.config['UPLOAD_FOLDER'] = 'static/images/profile_pics'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  
app.config['MAIL_PORT'] = 587 
app.config['MAIL_USERNAME'] = 'LoveJoy.information@gmail.com'  
app.config['MAIL_PASSWORD'] = 'hsny vclm houg odds'  
app.config['MAIL_USE_TLS'] = True  
app.config['MAIL_DEFAULT_SENDER'] = 'LoveJoy.information@gmail.com' 
app.config['SECRET_KEY'] = '07c3a155ab1be52a26fe36abaa50cbb7'




mail = Mail(app)

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
    security_ans_1 = db.Column(db.String(255), nullable=True)
    security_ans_2 = db.Column(db.String(255), nullable=True)
    security_ans_3 = db.Column(db.String(255), nullable=True)
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_timestamp = db.Column(db.DateTime, nullable=True)

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

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def create_upload_folder():
    upload_folder = app.config['UPLOAD_FOLDER']
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)

create_upload_folder()

csrf = CSRFProtect(app)
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return 'CSRF error occurred: {}'.format(e.description), 400

@app.route('/')
def welcome():
    return render_template('welcome.html')

def generate_2fa_code():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))


@app.route('/signup', methods=['GET', 'POST'])
def signup():

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        profile_pic = request.files.get('profile_picture')

        # File handling for profile picture
        if profile_pic and allowed_file(profile_pic.filename):
            filename = secure_filename(profile_pic.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            profile_pic.save(file_path)
        else:
            file_path = "profile_pics/blank-profile.png"

        # Check if this is the first user (to be made admin)
        is_first_user = User.query.count() == 0

        # Create a new user instance
        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            profile_picture=file_path,
            security_ans_1=request.form.get('security_answer1'),
            security_ans_2=request.form.get('security_answer2'),
            security_ans_3=request.form.get('security_answer3'),
            is_admin=is_first_user,  # Make the first user an admin
        )

        # Add new user to the database
        db.session.add(new_user)
        db.session.commit()

        # Generate and send 2FA code
        code = generate_2fa_code()
        session['2fa_code'] = code
        session['user_id'] = new_user.id

        msg = Message("Your 2FA Code", recipients=[new_user.email])
        msg.body = f"Your 2FA code is: {code}"
        mail.send(msg)

        return redirect(url_for('two_factor_auth'))

    # Render the signup page for GET requests
    return render_template('signup.html')

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
            # Generate and send 2FA code
            code = generate_2fa_code()
            session['2fa_code'] = code
            session['user_id'] = user.id

            msg = Message("Your 2FA Code", recipients=[user.email])
            msg.body = f"Your 2FA code is: {code}"
            mail.send(msg)

            flash('2FA code sent to your email. Please enter the code to proceed.', 'info')
            return redirect(url_for('two_factor_auth'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/two_factor_auth', methods=['GET', 'POST'])
def two_factor_auth():
    if request.method == 'POST':
        user_code = request.form['code']
        session_code = session.get('2fa_code')
        user_id = session.get('user_id')

        print("User Code:", user_code)  
        print("Session Code:", session_code)  
        print("User ID:", user_id) 

        if user_code and session_code and user_code == session_code:
            user = User.query.get(user_id)
            if user:
                login_user(user)
                print("Login successful, redirecting...") 
                return redirect(url_for('homepage'))
            else:
                print("User not found.") 
        else:
            flash('Invalid 2FA code', 'error')
            print("Invalid 2FA code.") 

    return render_template('two_factor_auth.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        token = request.form['token']
        security_answer1 = request.form['security_answer1']
        security_answer2 = request.form['security_answer2']
        security_answer3 = request.form['security_answer3']
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']
        
        user = User.query.filter_by(reset_token=token).first()

        if user and user.reset_token_timestamp and datetime.utcnow() <= user.reset_token_timestamp:
            # Verify security answers
            if (
                user.security_ans_1 == security_answer1 and
                user.security_ans_2 == security_answer2 and
                user.security_ans_3 == security_answer3
            ):
                # Check if passwords match
                if new_password == confirm_new_password:
                    # Update user's password
                    user.password = generate_password_hash(new_password)

                    # Clear reset token fields
                    user.reset_token = None
                    user.reset_token_timestamp = None

                    # Commit changes to the database
                    db.session.commit()

                    flash('Password reset successful. You can now log in with your new password.', 'success')
                    return redirect(url_for('login'))  
                else:
                    flash('Passwords do not match.', 'error')
            else:
                flash('Incorrect security answers.', 'error')
        else:
            flash('Invalid or expired reset token.', 'error')

    # Render the forgot password form
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
            
            upload_subfolder = 'uploads'
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], upload_subfolder, filename)

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

@app.route('/explore')
@login_required
def explore_antiques():

    evaluations = Evaluation.query.all()
    print(evaluations)
    return render_template('explore_antiques.html', evaluations=evaluations)

@app.route('/admin_counsel')
@login_required
def admin_counsel():
    if not current_user.is_admin:
        abort(403)  # HTTP Forbidden access if user is not an admin
    return render_template('admin_counsel.html')

@app.route('/evaluated_items')
@login_required
def evaluated_items():
    user_evaluations = Evaluation.query.filter_by(user_id=current_user.id).all()
    return render_template('evaluated_items.html', user_evaluated_items=user_evaluations, user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('welcome'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  
    app.run(host="0.0.0.0", port=5002, debug=True)