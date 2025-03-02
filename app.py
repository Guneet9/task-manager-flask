import datetime
import logging
import os
from functools import wraps
from logging.handlers import RotatingFileHandler

import jwt
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Configure logging
if not os.path.exists("logs"):
    os.mkdir("logs")

# Set up logger
logger = logging.getLogger("task_manager")
logger.setLevel(logging.INFO)

# Create handlers
file_handler = RotatingFileHandler(
    "logs/task_manager.log", maxBytes=10485760, backupCount=10
)
console_handler = logging.StreamHandler()
# Create formatters
file_formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
console_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

# Set formatters to handlers
file_handler.setFormatter(file_formatter)
console_handler.setFormatter(console_formatter)

# Add handlers to logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)
# Application Configuration
app = Flask(__name__)
app.config.update(
    SECRET_KEY="your_jwt_secret_key",  # Change this in production
    SQLALCHEMY_DATABASE_URI="sqlite:///task_manager.sqlite",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

# Set port from environment or use 8019 as default
PORT = int(os.environ.get("PORT", 8019))

# Log Flask app startup
logger.info(f"Starting Task Manager application on port {PORT}")

db = SQLAlchemy(app)


# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    tasks = db.relationship(
        "Task", backref="user", lazy=True, cascade="all, delete-orphan"
    )


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False)


# Create tables within app context
with app.app_context():
    logger.info("Creating database tables if they don't exist")
    db.create_all()


# Routes
@app.route("/")
def index():
    logger.info("Index page accessed")
    return render_template("index.html")


@app.route("/register")
def register_page():
    logger.info("Register page accessed")
    return render_template("register.html")


@app.route("/login")
def login_page():
    logger.info("Login page accessed")
    return render_template("login.html")


@app.route("/tasks")
def tasks_page():
    logger.info("Tasks page accessed")
    return render_template("tasks.html")


# JWT Token Authentication Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Check if token is in the request headers
        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]
        if not token:
            logger.warning("Authentication failed: Token is missing")
            return jsonify({"message": "Token is missing!"}), 401

        try:
            # Decode the token
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data["user_id"]).first()
            logger.debug(f"User {current_user.username} authenticated successfully")

        except Exception as e:
            logger.error(f"Authentication failed: Invalid token - {str(e)}")
            return jsonify({"message": "Token is invalid!"}), 401

        return f(current_user, *args, **kwargs)

    return decorated


# API Routes
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()

    if not data or not data.get("username") or not data.get("password"):
        logger.warning("Registration failed: Missing username or password")
        return jsonify({"message": "Username and password are required!"}), 400

    username = data.get("username").strip()
    password = data.get("password")

    if User.query.filter_by(username=username).first():
        logger.warning(f"Registration failed: Username {username} already exists")
        return jsonify({"message": "Username already exists!"}), 400

    hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

    new_user = User(username=username, password=hashed_password)

    try:
        db.session.add(new_user)
        db.session.commit()
        logger.info(f"User {username} registered successfully")
        return jsonify({"message": "User registered successfully!"}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration error for {username}: {str(e)}")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data or not data.get("username") or not data.get("password"):
        logger.warning("Login failed: Missing username or password")
        return jsonify({"message": "Username and password are required!"}), 400

    username = data.get("username").strip()
    password = data.get("password")

    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        logger.warning(f"Login failed: Invalid credentials for username {username}")
        return jsonify({"message": "Invalid credentials!"}), 401
    # Generate JWT token
    token = jwt.encode(
        {
            "user_id": user.id,
            "username": user.username,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24),
        },
        app.config["SECRET_KEY"],
        algorithm="HS256",
    )
    logger.info(f"User {username} logged in successfully")
    return (
        jsonify(
            {"message": "Login successful!", "token": token, "username": user.username}
        ),
        200,
    )


@app.route("/api/tasks", methods=["GET"])
@token_required
def get_tasks(current_user):
    tasks = Task.query.filter_by(user_id=current_user.id).all()

    output = []
    for task in tasks:
        task_data = {"id": task.id, "title": task.title, "completed": task.completed}
        output.append(task_data)

    logger.info(f"User {current_user.username} retrieved {len(output)} tasks")
    return jsonify({"tasks": output})


@app.route("/api/tasks", methods=["POST"])
@token_required
def create_task(current_user):
    data = request.get_json()

    if not data or not data.get("title"):
        logger.warning(
            f"User {current_user.username} attempted to create task without title"
        )
        return jsonify({"message": "Task title is required!"}), 400

    title = data.get("title").strip()

    if not title:
        logger.warning(
            f"User {current_user.username} attempted to create task with empty title"
        )
        return jsonify({"message": "Task title cannot be empty!"}), 400

    new_task = Task(title=title, user_id=current_user.id)

    try:
        db.session.add(new_task)
        db.session.commit()
        logger.info(f'User {current_user.username} created task: "{title}"')

        return (
            jsonify(
                {
                    "message": "Task created!",
                    "task": {
                        "id": new_task.id,
                        "title": new_task.title,
                        "completed": new_task.completed,
                    },
                }
            ),
            201)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Task creation error for user {current_user.username}: {str(e)}")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500


@app.route("/api/tasks/<task_id>", methods=["PUT"])
@token_required
def update_task(current_user, task_id):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first()

    if not task:
        logger.warning(
            f"User {current_user.username} attempted to update non-existent task ID: {task_id}"
        )
        return jsonify({"message": "Task not found!"}), 404

    data = request.get_json()

    if "completed" in data:
        task.completed = bool(data["completed"])

    if "title" in data and data["title"].strip():
        task.title = data["title"].strip()
    try:
        db.session.commit()
        logger.info(f"User {current_user.username} updated task ID: {task_id}")
        return jsonify(
            {
                "message": "Task updated!",
                "task": {
                    "id": task.id,
                    "title": task.title,
                    "completed": task.completed,
                },
            }
        )
    except Exception as e:
        db.session.rollback()
        logger.error(
            f"Task update error for user {current_user.username}, task ID {task_id}: {str(e)}"
        )
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500


@app.route("/api/tasks/<task_id>", methods=["DELETE"])
@token_required
def delete_task(current_user, task_id):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first()

    if not task:
        logger.warning(
            f"User {current_user.username} attempted to delete non-existent task ID: {task_id}"
        )
        return jsonify({"message": "Task not found!"}), 404

    try:
        db.session.delete(task)
        db.session.commit()
        logger.info(f"User {current_user.username} deleted task ID: {task_id}")
        return jsonify({"message": "Task deleted!"})
    except Exception as e:
        db.session.rollback()
        logger.error(
            f"Task deletion error for user {current_user.username}, task ID {task_id}: {str(e)}"
        )
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500


# Error handlers
@app.errorhandler(404)
def not_found(error):
    logger.warning(f"404 error: {request.path}")
    return jsonify({"message": "Resource not found!"}), 404


@app.errorhandler(500)
def server_error(error):
    logger.error(f"500 error: {str(error)}")
    return jsonify({"message": "Internal server error occurred!"}), 500


if __name__ == "__main__":
    logger.info(f"Starting Flask development server on port {PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=True)
