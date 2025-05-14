# Import necessary libraries and modules
import os  # For environment variables and operating system interactions
import signal  # To handle graceful shutdown signals
import sys  # System-level operations
import ssl  # For secure connections using SSL/TLS
from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify  # Core Flask functionalities
from flask_sqlalchemy import SQLAlchemy  # ORM for database handling
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect  # Real-time communication features
from flask_wtf import FlaskForm  # Flask-WTF for form handling
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, EmailField, ValidationError, validators  # Form fields
from wtforms.validators import InputRequired, Length, Email, EqualTo, DataRequired, Regexp, Optional  # Form validation rules
from werkzeug.security import generate_password_hash, check_password_hash  # Secure password hashing
import logging  # Logging for debugging and tracking errors
from threading import Lock  # Thread-safe operations
from logging.handlers import RotatingFileHandler  # Manage log file sizes
from datetime import datetime  # Working with dates and times
from flask_cors import CORS  # Handle Cross-Origin Resource Sharing (CORS)
from pytz import timezone  # Time zone management
import tzlocal  # Detect local time zone
from dotenv import load_dotenv  # Load environment variables from .env
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature  # For secure token generation

# Load variables from .env file
load_dotenv()

# Initialize the Flask application
app = Flask(__name__)

# Database configuration using SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chatapp.db'  # SQLite database file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking to save resources
app.secret_key = os.getenv('SECRET_KEY', 'secretkey')  # Secret key for session management

# Set session timeout (30 minutes)
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  

# Initialize SQLAlchemy for database handling and CORS for cross-origin requests
db = SQLAlchemy(app)
CORS(app)  

# Initialize SocketIO for real-time communication
socketio = SocketIO(app, cors_allowed_origins="*")

# Configure logging to track events and errors with log file rotation
log_lock = Lock()  # Ensure thread-safe logging
handler = RotatingFileHandler('chat_app.log', maxBytes=10000, backupCount=3)  # Limit log size and backups
handler.setLevel(logging.INFO)  
logging.basicConfig(level=logging.INFO, handlers=[handler], format='%(asctime)s - %(levelname)s - %(message)s')

# Helper function for thread-safe logging
def thread_safe_log(message):
    with log_lock:
        logging.info(message)

# Graceful shutdown handler for when the app is interrupted (Ctrl+C)
def handle_shutdown(signal, frame):
    print("Shutting down gracefully...")
    socketio.stop()  # Stop SocketIO
    sys.exit(0)  # Exit the program

# User model for database storage
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)  # Unique usernames
    email = db.Column(db.String(120), unique=True, nullable=False)  # Unique emails
    password_hash = db.Column(db.String(128), nullable=False)  # Store hashed passwords
    messages = db.relationship('Message', backref='author', lazy=True)  # Relationship with messages

    # Store a hashed password
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Check if the input password matches the stored hash
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Message model to store chat messages
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)  # Message content
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Link to the user
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone('Africa/Nairobi')))  # Timestamp with Nairobi time zone

# Define registration form with fields and validation rules
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    email = EmailField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=20)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')

# Define login form with fields and validation rules
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=20)])
    submit = SubmitField('Login')

# Serializer for generating and validating tokens
serializer = URLSafeTimedSerializer(app.secret_key)

# Password reset request form
class PasswordResetRequestForm(FlaskForm):
    email = EmailField('Email', validators=[InputRequired(), Email()])
    submit = SubmitField('Request Password Reset')

# Password reset form
class PasswordResetForm(FlaskForm):
    password = PasswordField('New Password', validators=[InputRequired(), Length(min=6, max=20)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Reset Password')

# Define profile form with fields and validation rules
class ProfileForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    email = EmailField('Email', validators=[InputRequired(), Email()])
    current_password = PasswordField('Current Password', validators=[InputRequired()])
    new_password = PasswordField('New Password', validators=[Optional(), Length(min=6, max=20)])
    confirm_password = PasswordField('Confirm New Password', validators=[EqualTo('new_password', message='Passwords must match')])
    submit = SubmitField('Update Profile')

# Handle unexpected internal server errors
@app.errorhandler(500)
def internal_error(error):
    logging.error(f"Internal Server Error: {error}")
    return jsonify({"error": "An internal error occurred. Please try again later."}), 500

# Handle 'resource not found' errors (404)
@app.errorhandler(404)
def not_found_error(error):
    logging.warning(f"Not Found: {error}")
    return jsonify({"error": "Resource not found."}), 404

# Catch-all for unhandled Socket.IO errors
@socketio.on_error_default  
def default_error_handler(e):
    logging.error(f"SocketIO Error: {e}")
    emit('receive_message', {'user': 'System', 'msg': 'A server error occurred. Please try again.'})

# Route: Handle user login
@app.route('/', methods=['GET', 'POST'])
def index():
    form = LoginForm()  # Initialize the login form
    if form.validate_on_submit():  # Check if form data is valid
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()  # Retrieve the user from the database

        # Verify the password
        if user and user.check_password(password):
            session['username'] = user.username  # Save username in the session
            timestamp = datetime.now(timezone('Africa/Nairobi')).isoformat()  # Current timestamp in Nairobi timezone
            socketio.emit('receive_message', {'user': 'System', 'msg': f'{username} has logged in.', 'timestamp': timestamp})
            return redirect(url_for('chat'))  # Redirect to the chat page
        else:
            flash('Invalid credentials, please try again.', 'error')  # Show error message if login fails
    return render_template('index.html', form=form, messages=[])

# Route: Handle user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # Extract form data
        username = form.username.data
        email = form.email.data
        password = form.password.data
        
        # Check if the username or email already exists
        existing_user = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()
        
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')
        elif existing_email:
            flash('Email already exists. Please choose a different one.', 'error')
        else:
            # Create and save the new user
            new_user = User(username=username, email=email)
            new_user.set_password(password)  # Hash the password
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

# Route: Handle user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()  # Initialize the login form
    if form.validate_on_submit():  # Check if form data is valid
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()  # Retrieve the user from the database

        # Verify the password
        if user and user.check_password(password):
            session['username'] = user.username  # Save username in the session
            flash('Login successful!', 'success')
            timestamp = datetime.now(timezone('Africa/Nairobi')).isoformat()  # Current timestamp in Nairobi timezone
            socketio.emit('receive_message', {'user': 'System', 'msg': f'{username} has logged in.', 'timestamp': timestamp})
            return redirect(url_for('chat'))  # Redirect to the chat page
        else:
            flash('Invalid credentials, please try again.', 'error')  # Show error message if login fails
    return render_template('login.html', form=form)  # Display the login form template

# Route: Handle user logout
@app.route('/logout')
def logout():
    username = session.get('username')  # Get the username from the session
    session.pop('username', None)  # Remove the username from the session
    thread_safe_log(f"{username} logged out.")  # Log the logout event
    socketio.emit('receive_message', {'user': 'System', 'msg': f'{username} has logged out.'}, to='/')
    flash('You have been logged out.', 'info')  # Show a logout success message
    return redirect(url_for('login'))  # Redirect to the login page

# Route: Display the chat page
@app.route('/chat')
def chat():
    if 'username' not in session:  # Ensure the user is logged in
        return redirect(url_for('index'))  # Redirect to the login page if not logged in
    messages = Message.query.order_by(Message.timestamp.desc()).limit(50).all()  # Fetch the latest 50 messages
    return render_template('index.html', messages=messages)  # Display the chat page template with messages

# Route: Request password reset
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password_request():
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = serializer.dumps(user.email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            # Simulate sending email by logging the reset link
            logging.info(f"Password reset link for {user.email}: {reset_url}")
            flash('A password reset link has been sent to your email (check logs for demo).', 'info')
        else:
            flash('No account found with that email.', 'error')
    return render_template('reset_password_request.html', form=form)

# Route: Reset password using token
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)  # 1 hour expiry
    except (SignatureExpired, BadSignature):
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('login'))
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=email).first()
        if user:
            user.set_password(form.password.data)
            db.session.commit()
            flash('Your password has been reset. You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('User not found.', 'error')
            return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

# Route: View and update user profile
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' not in session:
        flash('Please log in to access your profile.', 'error')
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('login'))
    
    form = ProfileForm()
    
    # Pre-populate form fields with current user data
    if request.method == 'GET':
        form.username.data = user.username
        form.email.data = user.email
    
    if form.validate_on_submit():
        # Verify current password
        if not user.check_password(form.current_password.data):
            flash('Current password is incorrect.', 'error')
            return render_template('profile.html', form=form)
        
        # Check if username is changed and not already taken
        if form.username.data != user.username:
            existing_user = User.query.filter_by(username=form.username.data).first()
            if existing_user:
                flash('Username already exists. Please choose a different one.', 'error')
                return render_template('profile.html', form=form)
        
        # Check if email is changed and not already taken
        if form.email.data != user.email:
            existing_email = User.query.filter_by(email=form.email.data).first()
            if existing_email:
                flash('Email already exists. Please choose a different one.', 'error')
                return render_template('profile.html', form=form)
        
        # Update user data
        old_username = user.username
        user.username = form.username.data
        user.email = form.email.data
        
        # Update password if provided
        if form.new_password.data:
            user.set_password(form.new_password.data)
            
        db.session.commit()
        
        # Update session if username changed
        if old_username != user.username:
            session['username'] = user.username
            
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
        
    return render_template('profile.html', form=form)

# Socket.IO event: When a user joins a chat room
@socketio.on('join')
def on_join(username):
    join_room(username)  # Add the user to a room identified by their username
    timestamp = datetime.now(timezone('Africa/Nairobi')).isoformat()  # Current timestamp
    emit('receive_message', {'user': 'System', 'msg': f'{username} has joined the chat.', 'timestamp': timestamp}, to='/')  # Notify all users

# Socket.IO event: When a user disconnects
@socketio.on('disconnect')
def handle_disconnect():
    username = session.get('username')  # Get the username from the session
    if username:
        logging.warning(f"User disconnected: {username}")  # Log the disconnection
        timestamp = datetime.now(timezone('Africa/Nairobi')).isoformat()
        emit('receive_message', {'user': 'System', 'msg': f'{username} has left the chat.', 'timestamp': timestamp}, broadcast=True)
    leave_room(username)  # Remove the user from the room

# Socket.IO event: Handle incoming messages
@socketio.on('send_message')
def handle_message(data):
    username = session.get('username')  # Get the username from the session
    if not username:
        # If the user is not logged in, send a message asking them to log in again
        emit('receive_message', {'user': 'System', 'msg': 'Please log in again.'})
        socketio.sleep(2)  # Wait for the message to be delivered to the client
        disconnect()  # Disconnect the user
        return

    try:
        # Save the message to the database
        user = User.query.filter_by(username=username).first()
        if not user:
            emit('receive_message', {'user': 'System', 'msg': 'User not found.'})
            return

        new_message = Message(content=data['msg'], author=user)
        db.session.add(new_message)
        db.session.commit()  # Commit the message to the database

        timestamp = new_message.timestamp.isoformat()  # Get the message timestamp

        # Broadcast the message to all connected clients
        emit('receive_message', {'user': username, 'msg': data['msg'], 'timestamp': timestamp}, broadcast=True)

    except Exception as e:
        logging.error(f"Error processing message: {e}")  # Log the error
        db.session.rollback()  # Rollback the transaction if there's an error
        emit('receive_message', {'user': 'System', 'msg': 'An error occurred while sending your message.'})  # Notify the user of the error

# Run the Flask application with SSL (if enabled)
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables if they don't exist

    # Load SSL configuration securely from environment variables
    ssl_enabled = os.getenv('SSL_ENABLED', 'True').lower() == 'true'  # Check if SSL is enabled
    if ssl_enabled:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # Create SSL context for secure communication
        ssl_context.load_cert_chain('127.0.0.1.pem', '127.0.0.1-key.pem')  # Load SSL certificates
        socketio.run(app, host='0.0.0.0', port=5000, debug=True, ssl_context=ssl_context)  # Run with SSL
    else:
        socketio.run(app, host='0.0.0.0', port=5000, debug=True)  # Run without SSL

    # Handle graceful shutdown signals (Ctrl+C)
    signal.signal(signal.SIGINT, handle_shutdown)
