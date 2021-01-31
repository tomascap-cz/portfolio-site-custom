from flask import Flask, render_template, redirect, url_for, request, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm, RecaptchaField
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, TextAreaField, SubmitField, PasswordField
import email_validator
from wtforms.validators import DataRequired, Email
from smtplib import SMTP
from werkzeug.security import generate_password_hash, check_password_hash
from mongoengine import connect, Document, URLField, StringField as MongoStrField
from flask_mongoengine import MongoEngine
from flask_login import UserMixin, LoginManager, current_user, login_user
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['RECAPTCHA_PUBLIC_KEY'] = os.environ.get('RECAPTCHA_PUBLIC_KEY')
app.config['RECAPTCHA_PRIVATE_KEY'] = os.environ.get('RECAPTCHA_PRIVATE_KEY')
csrf = CSRFProtect(app)
bootstrap = Bootstrap(app)

# login_manager = LoginManager()
# login_manager.init_app(app)


class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    message = TextAreaField('Message', validators=[DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField('Send')


# class LoginForm(FlaskForm):
#     name = StringField('Name', validators=[DataRequired()])
#     password = PasswordField('Password', validators=[DataRequired(), Email()])
#     submit = SubmitField('Log in')


@app.route("/")
def get_home():
    return render_template("index.html")


@app.route("/portfolio")
def get_portfolio():
    return render_template("portfolio.html")


@app.route("/contact", methods=["GET", "POST"])
def contact_form():
    form = ContactForm()
    if form.validate_on_submit():
        with SMTP(os.environ.get('MAIL_SERVER')) as connection:
            connection.starttls()
            connection.login(user=os.environ.get('EMAIL'), password=os.environ.get('EMAIL_PWD'))
            connection.sendmail(from_addr=os.environ.get('EMAIL'),
                                to_addrs=os.environ.get('EMAIL'),
                                msg=f"Subject:New Form Message\n\n"
                                    f"From: {form.name.data}\n"
                                    f"E-mail: {form.email.data}\n"
                                    f"Message: {form.message.data}")
        flash("Thank you for your message. I will get back to you as soon as possible!")
        return render_template("contact.html", form=form)
    return render_template("contact.html", form=form)


# @app.route("/login", methods=["GET", "POST"])
# def login():
#     # if current_user.is_authenticated == True:
#     #     return redirect(url_for('/'))
#     form = LoginForm()
#     if request.method == "POST":
#         name = form.name.data
#         user = User.objects(name=name).first()
#         if user:
#             print("User found.")
#             if check_password_hash(user.password, form.password.data):
#                 print("Passwords match.")
#     return render_template("login.html", form=form)


if __name__ == "__main__":
    app.run(debug=True)