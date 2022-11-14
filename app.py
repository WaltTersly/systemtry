"""_the entry point into the application and database
"""
import datetime
import pdfkit
from flask import Flask, render_template, session, make_response
from flask import request, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import sha256_crypt

DATA_URL = 'mysql+pymysql://root:''@localhost/systry'

db = SQLAlchemy()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DATA_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'hardsetsecret'
db.init_app(app)
app.app_context().push()


class Register(db.Model):
    """Generating the register table using Models

    Args:
        db (Table): Register table
    """
    __tablename__ = "register"

    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(120), nullable=False)
    lastname = db.Column(db.String(120))
    address = db.Column(db.String(80))
    city = db.Column(db.String(80))
    zipcode = db.Column(db.String(50))
    register_date = db.Column(db.DateTime(timezone=True),
                              default=datetime.datetime.utcnow, nullable=False)
    email = db.Column(db.String(90), unique=True, nullable=False)
    password = db.Column(db.String(512), unique=True, nullable=False)

    def __repr__(self):
        return f"{self.firstname} {self.lastname} is {self.city}"


@app.route('/')
def index():
    """index function

    Returns:
        The dashboard or home page
    """
    return render_template("home.html")


@app.route('/register', methods=['GET', 'POST'])
def registration():
    """route to the register page
    """
    if request.method == "POST":
        first_name = request.form.get("FirstName")
        last_name = request.form.get("LastName")
        address = request.form.get("Address")
        city = request.form.get("City")
        zipcode = request.form.get("Zipcode")
        email_address = request.form.get("Email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirmPassword")
        secure_pass = sha256_crypt.encrypt(str(password))

        if password == confirm_password:
            user = Register(firstname=first_name, lastname=last_name,
                            address=address, city=city, zipcode=zipcode,
                            email=email_address, password=secure_pass)

            db.session.add(user)
            db.session.commit()

            flash("you are registered!! you can login", "success")
            return redirect(url_for('login'))
        else:
            flash('your password does not match', 'warning')
            return render_template('register.html')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """route to the Login page
    """
    if request.method == "POST":
        email_req = request.form.get("email")
        password_req = request.form.get("password")

        user = Register.query.filter_by(email=email_req).first()
        userpass = user.password
        if user is None:
            flash("The user does not exist", "danger")
            return render_template('login.html')
        else:
            if sha256_crypt.verify(password_req, userpass):
                # SESSION FOR LOGINING IN
                session['logged'] = True
                session['username'] = email_req
                flash("You have successfully logged in! Welcome!!", "success")
                return redirect(url_for('reports'))
            else:
                flash("Invalid email or password!! Try Again!!!", "danger")
                return render_template('login.html')
    return render_template('login.html')


@app.route('/reports')
def reports():
    """Reports module
    """
    users = Register.query.order_by(Register.register_date).all()
    user_no = Register.query.count()
    return render_template("report.html", users=users, user_no=user_no)


@app.route('/download')
def download():
    """download module
    """
    users = Register.query.order_by(Register.register_date).all()
    user_no = Register.query.count()
    out = render_template("report.html", users=users, user_no=user_no)

    pdf = pdfkit.from_string(out, False)

    response = make_response(pdf)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "attachment;filename=output.pdf"
    return response


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """Logout
    """
    session['logged'] = False
    session.pop('username', None)
    session.clear()
    flash("You Have logged out successful", "success")
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)
