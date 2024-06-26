from flask import Flask, render_template, redirect, url_for, request, flash
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError

from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from bson.objectid import ObjectId

app = Flask(__name__)
app.config['SECRET_KEY'] = "mysecretkey"
app.config['MONGO_URI'] = 'mongodb://localhost:27017/login_system'
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.route("/")
def index():
    return redirect(url_for('login'))

class User(UserMixin):
    def __init__(self, username, email, password, id=None):
        self.username = username
        self.email = email
        self.password = password
        self.id = id

    @staticmethod
    def get(user_id):
        user_data = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        if user_data:
            return User(username=user_data['username'], email=user_data['email'], password=user_data['password'], id=str(user_data['_id']))
        return None

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')
    def validate_username(self, username):
        user = mongo.db.users.find_one({"username": username.data})
        if user:
            flash('Username already exists!', 'danger')
            raise ValidationError('That username is already in use. Please choose a different one.')
        
    def validate_email(self, email):
        user = mongo.db.users.find_one({"email": email.data})
        if user:
            flash('That email is already in use. Please choose a different one.', 'danger')
            raise ValidationError('That email is already in use. Please choose a different one.')
    


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = {'username': form.username.data, 'email': form.email.data, 'password': hashed_password}
        mongo.db.users.insert_one(user)
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', title='Sign Up', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = mongo.db.users.find_one({"email": form.email.data})
        if user and bcrypt.check_password_hash(user['password'], form.password.data):
            user_obj = User(username=user['username'], email=user['email'], password=user['password'], id=str(user['_id']))
            login_user(user_obj)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/home")
@login_required
def home():
    return render_template('home.html', title='Home')

if __name__ == '__main__':
    app.run(debug=True)
