from flask import Flask, render_template, request, redirect, url_for, flash, session
from skimage.metrics import structural_similarity
import os, cv2
import numpy as np
from collections.abc import Sequence
from typing import Any, Mapping
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_bcrypt import Bcrypt, bcrypt
from flask_login import login_user, logout_user, UserMixin, login_manager, current_user, LoginManager, login_required, AnonymousUserMixin
from flask_sqlalchemy import SQLAlchemy
#from flask_oauthlib.client import OAuth



app = Flask(__name__)
#Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login_page'
login_manager.login_message_category = 'info'

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
#FACEBOOK_CLIENT_ID = '1457480128138479'
#FACEBOOK_CLIENT_SECRET = 'b61953735d1d35dc480abbc20e2b49e7'

app.config['SECRET_KEY'] = '6564021b5e50383abd8c8dcc'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.app_context().push()
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
#oauth = OAuth(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



class RegistrationForm(FlaskForm):
    def validate_email(self, email_to_check):
        user_email = User.query.filter_by(email=email_to_check.data).first()
        if user_email:
            raise ValidationError('Email already exists! please try other email')
    def validate_username(self, username_to_check):
        user_name = User.query.filter_by(username=username_to_check.data).first()
        if user_name:
            raise ValidationError('Username already exists! please try other username')
    
    username = StringField('Username:', validators=[DataRequired(), Length(min=3, max=20)])
    email = StringField('Email:', validators=[DataRequired(), Email()])
    password = PasswordField('Password:', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password:', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email:', validators=[DataRequired(), Email()])
    password = PasswordField('Password:', validators=[DataRequired()])
    submit = SubmitField('Login')

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    image = db.relationship('ImageComparison', backref='owned_user', lazy=True)

    @property
    def is_authenticated(self):
        #Return True if the user is authenticated.
        if isinstance(self, AnonymousUserMixin):
            return False
        else:
            return True
    
    @property
    def set_password(self):
        return self.set_password
    
    @set_password.setter
    def set_password(self, text_password):
        #set password
        self.password = bcrypt.generate_password_hash(text_password).decode('utf-8')

    def check_password(self, value):
        #check password
        return bcrypt.check_password_hash(self.password, value)
    
class ImageComparison(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_image_path = db.Column(db.String(100), nullable=False)
    second_image_path = db.Column(db.String(100), nullable=False)
    score = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"ImageComparison('{self.first_image_path}', '{self.second_image_path}', '{self.score}')"


def compare_images(first_image, second_image):
    first_gray = cv2.cvtColor(first_image, cv2.COLOR_BGR2GRAY)
    second_gray = cv2.cvtColor(second_image, cv2.COLOR_BGR2GRAY)
    score, _ = structural_similarity(first_gray, second_gray, full=True)
    return score
    
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Check if files were uploaded
        first_img = request.files['firstImage']
        second_img = request.files['secondImage']
        
    
        first_img_path = os.path.join(app.config['UPLOAD_FOLDER'], first_img.filename)
        second_img_path = os.path.join(app.config['UPLOAD_FOLDER'], second_img.filename)

        first_img.save(first_img_path)
        second_img.save(second_img_path)
        
        first = cv2.imread(first_img_path)
        second = cv2.imread(second_img_path)
      
        score = compare_images(first, second)

        # Remove uploaded images
        os.remove(first_img_path)
        os.remove(second_img_path)

        #Render result template with score and image paths
        return render_template('result.html', score=score, first_img_path='static/first.jpg', second_img_path='static/second.jpg')
    return render_template('result.html')

@app.route('/')
@app.route('/home')
def home_page():
    return render_template('home.html')
    
@app.route('/about')
def about_page():
    return render_template('about.html')
    
@app.route('/comparI')
@login_required
def result_page():
    image = ImageComparison.query.all()
    return render_template('result.html', image=image)

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(value=form.password.data):
            login_user(user)
            flash(f'Success! you are logged in as: {user.username}', category='success')
            return redirect(url_for('result_page'))
        else:
            flash('Please check email and password not match', category='danger')
    return render_template('login.html', title='Login', form=form)
    
@app.route('/register', methods=['GET', 'POST'])
def register_page():
    form = RegistrationForm()
    if form.validate_on_submit():
        user_to_create = User(username=form.username.data,
                                email=form.email.data,
                                set_password = form.password.data
                                )
        db.session.add(user_to_create)
        db.session.commit()
        login_user(user_to_create)
        flash('You account has been created! You are now able to login as: {user_to_create.username}', category='success')
        return redirect(url_for('login_page'))
    if form.errors != {}:
        for err_msg in form.errors.values():
            flash(f'There was an error with creating a user; {err_msg}', category='danger')
    return render_template('register.html', title='Register', form=form)
    
@app.route('/logout')
def logout_page():
    login_user()
    flash("Successfully logged out!", category='info')
    return redirect(url_for('home_page'))

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)

