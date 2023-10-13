from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, EmailField, SubmitField, BooleanField, SelectField
from wtforms.validators import Length, DataRequired, EqualTo, Email, ValidationError
from blog.models import Users
from flask_login import current_user


class Register(FlaskForm):
    def validate_username(self, username_to_check):
        user = Users.query.filter_by(username=username_to_check.data).first()
        if user:
            raise ValidationError('Username already exist! please try a different username')

    def validate_email(self, email_to_check):
        user = Users.query.filter_by(email=email_to_check.data).first()
        if user:
            raise ValidationError('Email already exist! please try a different email address')

    username = StringField(label='Username', validators=[Length(min=2, max=30), DataRequired()])
    email = EmailField(label='Email', validators=[Email(), DataRequired()])
    password = PasswordField(label='Password', validators=[
        Length(min=6, message='password should be at least %(min)d characters long'),
        DataRequired()])
    show_password = BooleanField(label='Show Password')
    confirm_password = PasswordField(label='Confirm_password', validators=[
        EqualTo('password', message='both password field must be equal'), DataRequired()])
    submit = SubmitField(label='Create Account')


class LoginForm(FlaskForm):
    email = EmailField(label='Email', validators=[Email()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    remember = BooleanField(label='Remember me')
    submit = SubmitField(label='Sign In')


class PostForm(FlaskForm):
    title = StringField(label='Title', validators=[DataRequired()])
    content = StringField(label='Content', validators=[DataRequired()])
    post_img = FileField(label='Add Image')
    submit = SubmitField(label='Create Post')


class UpdateForm(FlaskForm):
    username = StringField(label='Username', validators=[Length(min=2, max=30), DataRequired()])
    email = EmailField(label='Email', validators=[Email(), DataRequired()])
    picture = FileField(label='Update Profile Picture')
    submit = SubmitField(label='Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = Users.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Username already exist! please try a different username')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = Users.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('Email already exist! please try a different email address')


class RequestResetForm(FlaskForm):
    email = EmailField(label='Email', validators=[Email(), DataRequired()])
    submit = SubmitField(label='Request Password')

    def validate_email(self, email_to_check):
        user = Users.query.filter_by(email=email_to_check.data).first()
        if user is None:
            raise ValidationError('Email is not Registered')


class ResetPasswordForm(FlaskForm):
    password = PasswordField(label='Password', validators=[
        Length(min=6, message='password should be at least %(min)d characters long'),
        DataRequired()])
    confirm_password = PasswordField(label='Confirm_password', validators=[
        EqualTo('password', message='both password field must be equal'), DataRequired()])
    submit = SubmitField(label='Reset Password')


class AddNewAdmin(FlaskForm):
    def validate_username(self, username_to_check):
        user = Users.query.filter_by(username=username_to_check.data).first()
        if user:
            raise ValidationError('Username already exist! please try a different username')

    def validate_email(self, email_to_check):
        user = Users.query.filter_by(email=email_to_check.data).first()
        if user:
            raise ValidationError('Email already exist! please try a different email address')

    username = StringField(label='Username', validators=[Length(min=2, max=30), DataRequired()])
    email = EmailField(label='Email', validators=[Email(), DataRequired()])
    role = SelectField('Role', choices=[('', 'select role'), ('AD', 'Admin'), ('US', 'User')])
    password = PasswordField(label='Password', validators=[
        Length(min=6, message='password should be at least %(min)d characters long'),
        DataRequired()])
    show_password = BooleanField(label='Show Password')
    confirm_password = PasswordField(label='Confirm_password', validators=[
        EqualTo('password', message='both password field must be equal'), DataRequired()])
    submit = SubmitField(label='Add New Admin')
