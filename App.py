from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:postgres:postgres @localhost/db_uts'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = ‘key_uts’

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Define the User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


# Define the Task model
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    encrypted_description = db.Column(db.LargeBinary, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('tasks', lazy=True))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def encrypt_data(data, key):
    cipher = Cipher(algorithms.AES(key), modes.CFB(b'\0' * 16), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
    return encrypted_data


def decrypt_data(encrypted_data, key):
    cipher = Cipher(algorithms.AES(key), modes.CFB(b'\0' * 16), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data.decode()


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            flash('Login successful', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your username and password.', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    tasks = Task.query.filter_by(user_id=current_user.id).all()
    for task in tasks:
        if task.encrypted_description:
            task.description = decrypt_data(task.encrypted_description, app.config['SECRET_KEY'])
    return render_template('dashboard.html', tasks=tasks)


@app.route('/task/add', methods=['GET', 'POST'])
@login_required
def add_task():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        encrypted_description = encrypt_data(description, app.config['SECRET_KEY'])
        new_task = Task(title=title, encrypted_description=encrypted_description, user_id=current_user.id)
        db.session.add(new_task)
        db.session.commit()
        flash('Task added successfully', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_task.html')


@app.route('/task/edit/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = Task.query.get(task_id)
    if request.method == 'POST':
        task.title = request.form['title']
        description = request.form['description']
        task.encrypted_description = encrypt_data(description, app.config['SECRET_KEY'])
        db.session.commit()
        flash('Task updated successfully', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_task.html', task=task)


@app.route('/task/delete/<int:task_id>')
@login_required
def delete_task(task_id):
    task = Task.query.get(task_id)
    db.session.delete(task)
    db.session.commit()
    flash('Task deleted successfully', 'success')
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
