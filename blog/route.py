import os
import secrets
from PIL import Image
from flask import render_template, redirect, url_for, flash, request, abort
from blog import app, db, mail
from blog.forms import Register, LoginForm, PostForm, UpdateForm, ResetPasswordForm, RequestResetForm, AddNewAdmin
from passlib import hash
from .models import Users, Post
from flask_login import login_user, logout_user, current_user, login_required
from flask_mail import Message


@app.route('/')
@app.route('/home')
def home():
    posts = Post.query.all()
    return render_template('index.html', posts=posts)


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/blog')
def blog():
    return render_template('blog.html')


@app.route('/single')
def single():
    return render_template('single.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = Register()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        password_hash = hash.apr_md5_crypt.hash(password)
        user_data = Users(username=username, email=email, password=password_hash)
        db.session.add(user_data)
        db.session.commit()
        flash(f'Account created for {username} successful!', category='success')
        return redirect(url_for('signin'))
    return render_template('signup.html', title='Register Page', form=form)


@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user and hash.apr_md5_crypt.verify(form.password.data, user.password):
            login_user(user, form.remember.data)
            role = current_user.role
            if role == 'Admin':
                return redirect(url_for('dashboard'))
            else:
                flash(f'Welcome {user.username}', category='success')
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash(f'Incorrect username or password', category='danger')
    return render_template('signin.html', form=form, title='Login Page')


@app.route('/logout')
def logout():
    logout_user()
    flash(f'You Have Been Logged Out Successfully', category='info')
    return redirect(url_for('home'))


@app.route('/post/new', methods=['GET', 'POST'])
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        img_data = request.form.get('pictureData')
        post = Post(title=title, content=content, author=current_user, post_img=img_data)
        db.session.add(post)
        db.session.commit()
        flash('Successfully Added', category='success')
        return redirect(url_for('home'))
    return render_template('create_post.html', form=form, heading='Add Post', title='Create Post')


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 150)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn


@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.img_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.img_file)
    return render_template('account.html', image_file=image_file, title='Profile Page', form=form)


@app.route('/post_detail/<int:post_id>')
def post_detail(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post_detail.html', post=post)


@app.route('/post_detail/<int:post_id>/update', methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        post.post_img = request.form.get('pictureData')
        db.session.commit()
        flash(f'Post has been updated', 'success')
        return redirect(url_for('post_detail', post_id=post.id))
    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content

    return render_template('create_post.html', form=form, heading='Update Post')


@app.route('/post_detail/<int:post_id>/delete', methods=['GET', 'POST'])
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash(f'Your post has been deleted!', 'success')
    return redirect(url_for('home'))


sitename = ''


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')
        tel = request.form.get('tel')
        if not name or not email or not tel or not message:
            flash(f'failed to send email')
            return render_template('contact.html', failed=True)
        else:
            msg = Message(subject=f'Mail from {sitename}',
                          body=f'Name: {name}\nEmail: {email}\nPhone: {tel}\n\n\nMessage: {message}',
                          sender=email,
                          recipients=['Your Email'])
            mail.send(msg)
            print(f'name: {name} email: {email} phone: {tel} message: {message}')
            flash(f'successful')
            return render_template('contact.html', success=True)
    return render_template('contact.html')


def send_reset_mail(user):
    token = user.get_reset_token()
    msg = Message('Password Request Reset',
                  sender='dlghtsabina@gmail.com',
                  recipients=[user.email])
    msg.body = f'''To Reset Your Password, Click Here: {url_for('reset_token', token=token, _external=True)} '''
    mail.send(msg)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        send_reset_mail(user)
        flash('email has been sent', 'success')
        return redirect(url_for('signin'))
    return render_template('reset_request.html', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = Users.verify_reset_token(token)
    if user is None:
        flash(f'That is invalid or expired token', 'warning')
        return redirect(url_for('reset_password'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        password_hash = hash.apr_md5_crypt.hash(form.password.data)
        user.password = password_hash
        db.session.commit()
        flash(f'Your password has been updated', 'success')
        return redirect(url_for('signin'))
    return render_template('reset_token.html', form=form)


@app.route('/dashboard')
def dashboard():
    role = current_user.role
    if role == 'Admin':

        return render_template('dashboard/dashboard.html')
    else:
        flash('Sorry, you can not access the this page.', 'danger')
        return redirect(url_for('home'))


@app.route('/user_table')
def user_table():
    role = current_user.role
    if role == 'Admin':
        users = Users.query.all()
        return render_template('dashboard/users_table.html', users=users)
    else:
        return redirect(url_for('home'))


@app.route('/post_table')
def post_table():
    role = current_user.role
    if role == 'Admin':
        posts = Post.query.all()
        return render_template('dashboard/users_table.html', posts=posts)
    else:
        return redirect(url_for('home'))



@app.route('/add_admin')
def add_admin():
    form = AddNewAdmin()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        role = form.role.data
        password = form.password.data
        password_hash = hash.apr_md5_crypt.hash(password)
        user_data = Users(username=username, email=email, role=role, password=password_hash)
        db.session.add(user_data)
        db.session.commit()
        flash(f'Account created for {username} successful!', category='success')
        return redirect(url_for('signin'))
    return render_template('dashboard/add_new_admin.html', form=form)
