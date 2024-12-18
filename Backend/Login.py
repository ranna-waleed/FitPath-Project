from flask import render_template
from werkzeug.security import generate_password_hash, check_password_hash
from app import db 
from flask import Blueprint


def authenticate_user(form):
    """
    Handles user login authentication.
    :param form: The submitted login form.
    :return: Tuple (success: bool, user: User object or None, message: str)
    """
    user = User.query.filter_by(username=form.username.data).first()
    if user and check_password_hash(user.password, form.password.data):
        return True, user, "Login successful."
    return False, None, "Invalid username or password."


def register_user(form):
    """
    Handles the user registration process.
    :param form: The submitted registration form.
    :return: Tuple (success: bool, message: str)
    """
    if User.query.filter_by(username=form.username.data).first():
        return False, "Username already exists."
    if User.query.filter_by(email=form.email.data).first():
        return False, "Email already exists."

    hashed_password = generate_password_hash(form.password.data)
    new_user = User(
        full_name=form.full_name.data,
        username=form.username.data,
        email=form.email.data,
        password=hashed_password
    )
    db.session.add(new_user)
    db.session.commit()

    user_role = Roles.query.filter_by(name='User').first()
    if user_role:
        new_user_role = UserRole(user_id=new_user.id, role_id=user_role.id)
        db.session.add(new_user_role)
        db.session.commit()
    else:
        return False, "Role 'User' not found in the database. Contact admin."

    return True, "Registration successful. You can now log in."

    

login_bp = Blueprint('login', __name__)

@login_bp.route('/login')
def login():
    return "Login Page"
