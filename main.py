import werkzeug
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_ckeditor import CKEditor, CKEditorField

from sqlalchemy.orm import relationship
from forms import CreateListForm, RegisterForm, LoginForm
from sqlalchemy import Table, Column, Integer, ForeignKey
from flask_bootstrap import Bootstrap
from datetime import date


app = Flask(__name__)
Bootstrap(app)
ckeditor = CKEditor(app)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///to-do-list-users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#CONFIGURE LOGIN MANAGER
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    lists = relationship("List", back_populates="author")


#TO-DO LIST TABLES
class List(db.Model):
    __tablename__ = "todo_lists"
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(250), nullable=False)
    item1 = db.Column(db.String(250), nullable=False)
    item2 = db.Column(db.String(250), nullable=True)
    item3 = db.Column(db.String(250), nullable=True)
    item4 = db.Column(db.String(250), nullable=True)
    item5 = db.Column(db.String(250), nullable=True)
    item6 = db.Column(db.String(250), nullable=True)
    item7 = db.Column(db.String(250), nullable=True)
    item8 = db.Column(db.String(250), nullable=True)
    item9 = db.Column(db.String(250), nullable=True)

    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the "posts" refers to the posts property in the User class.
    author = relationship("User", back_populates="lists")


#Line below only required once, when creating DB.
with app.app_context():
    db.create_all()


@app.route('/', methods=['POST','GET'])
def home():
    return render_template("index.html")

@app.route('/login', methods=['POST','GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        # Find user by email entered.
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("This email has not been registered. Please Register.")
            return redirect(url_for('register'))
        # Check stored password hash against entered password hashed.
        if check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('view_lists'))
        else:
            flash("Password incorrect.Please try again.")
            return redirect(url_for('login'))
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)

@app.route('/register', methods=['GET','POST'])
def register():
    form=RegisterForm()
    if form.validate_on_submit():
        # FIRST, CHECK TO SEE IF EMAIL IS ALREADY IN RECORD
        if User.query.filter_by(email=form.email.data).first():
            # User already exists
            flash("Your email address has been registered, log in instead!")
            return redirect(url_for('login'))

        # CREATE RECORD
        plaintext_password = form.password.data
        new_user = User(
            email=form.email.data,
            password=generate_password_hash(plaintext_password, method='pbkdf2:sha256', salt_length=8),
            name=form.name.data
        )
        db.session.add(new_user)
        db.session.commit()
        # Log in and authenticate user after adding details to database.
        flash("You can now log in to begin!")
        return redirect(url_for('login'))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/my_lists')
def view_lists():
    lists = List.query.all()
    return render_template("lists.html", all_lists=lists, logged_in=current_user.is_authenticated, current_user=current_user)

@app.route("/list/<int:list_id>", methods=['GET','POST'])
def show_list(list_id):
    requested_list = List.query.get(list_id)
    return render_template("my_list.html", list=requested_list, current_user=current_user, logged_in=current_user.is_authenticated)

@app.route("/new-list", methods=['GET','POST'])
def add_new_list():
    form = CreateListForm()
    if form.validate_on_submit():
        new_list = List(
            item1=form.item1.data,
            item2=form.item2.data,
            item3=form.item3.data,
            item4=form.item4.data,
            item5=form.item5.data,
            item6=form.item6.data,
            item7=form.item7.data,
            item8=form.item8.data,
            item9=form.item9.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_list)
        db.session.commit()
        return redirect(url_for("view_lists"))
    return render_template("new_list.html", form=form, current_user=current_user, logged_in=current_user.is_authenticated)

@app.route("/delete/<int:list_id>")
def delete_list(list_id):
    list_to_delete = List.query.get(list_id)
    db.session.delete(list_to_delete)
    db.session.commit()
    return redirect(url_for('view_lists'))


if __name__ == "__main__":
    app.run(debug=True)