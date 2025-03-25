from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
import hashlib
import random
import string

app = Flask(__name__)

# Configure RDS MySQL (replace with your RDS details later)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://admin:password@flask-db.c7qis4oe8os2.ap-south-1.rds.amazonaws.com:3306/flaskDB'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

PEPPER = "s3cr3tP3pp3r"  # Secret pepper used for all users

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    salt = db.Column(db.String(8), nullable=False)
    hashed_password = db.Column(db.String(64), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

# Create tables (run once locally or on deployment)
with app.app_context():
    db.create_all()

def generate_salt(length=8):
    """Generate a random salt."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def hash_password(password, salt):
    """Hash the password using SHA-256 with salt and pepper."""
    return hashlib.sha256((password + salt + PEPPER + salt).encode()).hexdigest()

# Route to render registration page
@app.route('/register.html', methods=['GET'])
def render_register():
    return render_template('register.html')

# Route to handle registration POST request
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    password = data['password']

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "User already exists!"}), 400

    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    new_user = User(username=username, salt=salt, hashed_password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Registration successful!"})

# Route to render login page
@app.route('/login.html', methods=['GET'])
def render_login():
    return render_template('login.html')

# Route to handle login POST request
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"message": "Invalid username or password!"}), 400

    hashed_input_password = hash_password(password, user.salt)
    if hashed_input_password == user.hashed_password:
        return jsonify({"message": "Login successful!"})
    else:
        return jsonify({"message": "Invalid username or password!"}), 400

if __name__ == '__main__':
    app.run(debug=True)