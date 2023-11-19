from flask import Flask, render_template, request, redirect, url_for, flash #import Flask ,Flask-SQLAlchemy,Flask-login
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField
from wtforms.validators import DataRequired, Length
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, LoginManager, login_required, current_user, logout_user


db = SQLAlchemy()#import Flask SQLAchemy, initializes database
app = Flask(__name__)
app.config['SECRET_KEY'] = "my-secrets"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///video-meeting.db" #directory database its gonna be started
db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


@login_manager.user_loader#Register call back function for reloading user from the session which used to check if the user have logined
def load_user(user_id):#Get user id from session
    return Register.query.get(int(user_id))


class Register(db.Model):#Create database 
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def is_active(self):#Generated value when the user changes their password
        return True

    def get_id(self):
        return str(self.id)

    def is_authenticated(self):#attribute when user is authenticated
        return True #only authenticated users will fullfill the criteria of login-required


with app.app_context():#Call to create table
    db.create_all()

#Create and Define registration form contain email 
#import validate
class RegistrationForm(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired()])
    first_name = StringField(label="First Name", validators=[DataRequired()])
    last_name = StringField(label="Last Name", validators=[DataRequired()])
    username = StringField(label="Username", validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField(label="Password", validators=[DataRequired(), Length(min=8, max=20)])

#Define Login form
class LoginForm(FlaskForm):#Using a Flask SqlAlchemy database, fields for username and password hash.
    email = EmailField(label='Email', validators=[DataRequired()])
    password = PasswordField(label="Password", validators=[DataRequired()])


@app.route("/")#Home route that redirect to Login page
def home():
    return redirect(url_for("login"))#url_for used to prepare an URL


@app.route("/login", methods=["POST", "GET"])
def login():
    form = LoginForm()
    if request.method == "POST" and form.validate_on_submit(): #verify the information in the specified field and carry out the necessary actions.
        email = form.email.data
        password = form.password.data
        user = Register.query.filter_by(email=email, password=password).first()#Validate the data in login
        if user:#Validate user login if it is correct and grant access to the program
            login_user(user)
            return redirect(url_for("dashboard"))

    return render_template("login.html", form=form)


@app.route("/logout", methods=["GET"]) #logout the meeting
@login_required#Every page access to login or check user login in database
def logout():
    logout_user()
    flash("You have been logged out successfully!", "info")
    return redirect(url_for("login"))


@app.route("/register", methods=["POST", "GET"]) #Collects the data 
def register():
    form = RegistrationForm() #Past Form from Register
    if request.method == "POST" and form.validate_on_submit(): #if form is POST the data will be extracted
        new_user = Register(
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            username=form.username.data,
            password=form.password.data
        )
        db.session.add(new_user)#send the data to the database
        db.session.commit()# commit the current transaction on all current database connections that have a transaction in progress
        flash("Account created Successfully! <br>You can now log in.", "success")#will be display if once user created sucessfully
        return redirect(url_for("login"))#redirect to login page

    return render_template("register.html", form=form)


@app.route("/dashboard")#define dashboard
@login_required#Every page access to login or check user login in database
def dashboard():
    return render_template("dashboard.html", first_name=current_user.first_name, last_name=current_user.last_name)#past name to the dashboard


@app.route("/meeting")#define meeting
@login_required#Every page access to login or check user login in database
def meeting():
    return render_template("meeting.html", username=current_user.username)#return meeting.html


@app.route("/join", methods=["GET", "POST"])
@login_required#Every page access to login or check user login in database
def join():
    if request.method == "POST":
        room_id = request.form.get("roomID")#Get room id
        return redirect(f"/meeting?roomID={room_id}")#redirect to the room id

    return render_template("join.html")


if __name__ == "__main__":#executing python program
    app.run(debug=True)