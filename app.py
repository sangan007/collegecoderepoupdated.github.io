from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

# Initialize Flask app
app = Flask(__name__)
app.secret_key = "your_secret_key"

# Configure the database
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:%40Sangan%20007@127.0.0.1/code_repo"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configure file upload settings
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # "student" or "teacher"
    password = db.Column(db.String(150), nullable=False)

class Repository(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    student = db.relationship('User', backref='repositories')

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    repository_id = db.Column(db.Integer, db.ForeignKey('repository.id'))
    repository = db.relationship('Repository', backref='projects')
    score = db.Column(db.Integer, nullable=True)
    file_path = db.Column(db.String(300), nullable=True)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = request.form['id']
        password = request.form['password']
        user = User.query.filter_by(id=user_id).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            flash('Login successful!', 'success')
            return redirect(url_for('student_dashboard' if user.role == 'student' else 'teacher_dashboard'))
        flash('Invalid credentials', 'error')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        user_id = request.form['id']
        password = request.form['password']
        role = request.form['role']
        
        existing_user = User.query.filter_by(id=user_id).first()
        if existing_user:
            flash('User ID already exists. Please choose a different one.', 'error')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)
        new_user = User(id=user_id, name=name, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/student_dashboard')
def student_dashboard():
    if 'user_id' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    repositories = Repository.query.filter_by(student_id=session['user_id']).all()
    notifications = Notification.query.filter_by(student_id=session['user_id']).order_by(Notification.created_at.desc()).all()
    return render_template('student_dashboard.html', repositories=repositories, notifications=notifications)

@app.route('/teacher_dashboard')
def teacher_dashboard():
    if 'user_id' not in session or session['role'] != 'teacher':
        return redirect(url_for('login'))
    repositories = Repository.query.all()
    return render_template('teacher_dashboard.html', repositories=repositories)

@app.route('/create_repository', methods=['POST'])
def create_repository():
    if 'user_id' in session and session['role'] == 'student':
        name = request.form['name']
        description = request.form['description']
        new_repository = Repository(name=name, description=description, student_id=session['user_id'])
        db.session.add(new_repository)
        db.session.commit()
        flash('Repository created successfully.', 'success')
        return redirect(url_for('student_dashboard'))
    flash('Unauthorized access.', 'error')
    return redirect(url_for('login'))

@app.route('/repository/<int:repo_id>')
def view_repository(repo_id):
    repository = Repository.query.get(repo_id)
    if not repository or (session['role'] == 'student' and repository.student_id != session['user_id']):
        flash('Access Denied', 'error')
        return redirect(url_for('student_dashboard' if session['role'] == 'student' else 'teacher_dashboard'))
    return render_template('repository.html', repository=repository)

@app.route('/add_project/<int:repo_id>', methods=['POST'])
def add_project(repo_id):
    if 'user_id' in session and session['role'] == 'student':
        name = request.form['name']
        description = request.form['description']
        project_file = request.files['project_file']
        
        if project_file and allowed_file(project_file.filename):
            filename = secure_filename(project_file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            project_file.save(file_path)
        else:
            file_path = None

        new_project = Project(name=name, description=description, repository_id=repo_id, file_path=file_path)
        db.session.add(new_project)
        db.session.commit()
        flash('Project added successfully.', 'success')
        return redirect(url_for('view_repository', repo_id=repo_id))
    flash('Unauthorized access.', 'error')
    return redirect(url_for('login'))

@app.route('/assign_project/<int:repo_id>', methods=['POST'])
def assign_project(repo_id):
    if 'user_id' in session and session['role'] == 'teacher':
        student_id = Repository.query.get(repo_id).student_id
        message = request.form['message']
        notification = Notification(message=message, student_id=student_id)
        db.session.add(notification)
        db.session.commit()
        flash('Project assigned successfully.', 'success')
        return redirect(url_for('teacher_dashboard'))
    flash('Unauthorized access.', 'error')
    return redirect(url_for('login'))

@app.route('/add_score/<int:project_id>', methods=['POST'])
def add_score(project_id):
    if 'user_id' in session and session['role'] == 'teacher':
        score = request.form['score']
        project = Project.query.get(project_id)
        project.score = score
        db.session.commit()

        student_id = project.repository.student_id
        notification = Notification(message=f'Score added to project {project.name}', student_id=student_id)
        db.session.add(notification)
        db.session.commit()
        flash('Score added successfully.', 'success')
        return redirect(url_for('teacher_dashboard'))
    flash('Unauthorized access.', 'error')
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

# Run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
