import logging
from urllib.parse import urlparse
from flask import Flask, render_template, request, redirect, url_for, session,flash
from flask_bcrypt import Bcrypt
from flask_login import login_required, logout_user, login_user
import urllib
from flask_sqlalchemy import SQLAlchemy
from Backend.Support import *
from Backend.Admin import *
from Backend.Login import *
from models import *

app = Flask(__name__)

app.config['SECRET_KEY'] = 'login'

params = urllib.parse.quote_plus("DRIVER={ODBC Driver 17 for SQL Server};"
    "SERVER=Mariam;"  # or your server name/IP
    "DATABASE=FitPath_DB;"  # your database name
    "Trusted_Connection=yes;")

app.config['SQLALCHEMY_DATABASE_URI'] = f"mssql+pyodbc:///?odbc_connect={params}"
engine = create_engine(f"mssql+pyodbc:///?odbc_connect={params}")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app) 
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)  

@app.errorhandler(404)
def page_not_found(e):
    url = request.url
    # Extract the path from the URL
    parsed_url = urlparse(url).path
    # Slice the last part of the URL (e.g., 'team.html')
    last_part = parsed_url.split('/')[-1]
    if last_part == "classes.html":
        last_part = "class-details.html"
    # Log the error
    logging.error('404 error occurred at URL: %s', url)
    logging.error('Last part of URL: %s', last_part)

    # Write to a specific log file
    with open('error.log', 'a') as f:
        f.write(f'404 error occurred at URL: {url}, Sliced Part: {last_part}\n')

    try:
        return render_template(last_part), 404
    except Exception as ex:
        logging.error(f"Error rendering {last_part}: {ex}")

    return render_template('404.html'), 404

@app.context_processor
def inject_name():
    return {'name': getName()}

class User(db.Model, UserMixin):
    __tablename__ = 'Users'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))  # Use UUIDs for user IDs
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=True)
    PasswordHash = db.Column(db.String(80), nullable=False)
    FullName = db.Column(db.String(40), nullable=False)
    State = db.Column(db.Boolean, nullable=False, default=True)
    phonenumber = db.Column(db.String(15), nullable=True)  # Add phone number column

class Roles(db.Model):
    __tablename__ = 'UserRoles'
    UserId = db.Column(db.String(450),  primary_key=True, nullable=False)
    RoleId = db.Column(db.String(450),  primary_key=True, nullable=False)
    
class RegisterForm(FlaskForm):
    username = StringField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Username"}
    )
    email = StringField(
        validators=[InputRequired(), Length(min=6, max=120), Email()],
        render_kw={"placeholder": "Email"}
    )
    full_name = StringField(
        validators=[InputRequired(), Length(min=2, max=100)],
        render_kw={"placeholder": "Full Name"}
    )
    password = PasswordField(
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Password"}
    )
    submit = SubmitField("Register")
    
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different one.")
    
    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError("That email is already registered. Please choose a different one.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"id": "floatingText"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"id": "floatingPassword"})
    remember_me = BooleanField('Remember Me')
    submit = SubmitField("Login")

def getCurrentrole():
    user_id = current_user.id
    with engine.connect() as connection:
        result = connection.execute(
            text("SELECT RoleId FROM UserRoles WHERE UserId = :user_id"), {"user_id": user_id}
        )
        role_id = result.scalar()  

        if role_id is None:
            return []  
        # Fetch the claims for the retrieved RoleId
        claims_result = connection.execute(
            text("SELECT ClaimValue FROM RoleClaims WHERE RoleId = :role_id"), {"role_id": role_id}
        )

        # Fetch all claims as a list of strings
        claims = claims_result.fetchall()
        claims_list = [claim[0] for claim in claims]

    return claims_list

def authorize(module, action):
    claims_list = getCurrentrole()  # Get the current role's claims

    # Check if the module and action are in the claims_list
    for claim in claims_list:
        # Check if both module and action are present in the claim
        if f"{module}.{action}" in claim:
            return True  # Authorization granted
    
    return False  # Authorization denied

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

def getName():
    if current_user.is_authenticated:
        user_id = current_user.id
        print(f"Authenticated user ID: {user_id}")
        try:
            with engine.connect() as connection:
                result = connection.execute(
                    text("SELECT UserName FROM Users WHERE Id = :user_id AND State = 1"), {"user_id": user_id}
                )
                UserName = result.scalar()
                print("UserName: ", UserName)
                return UserName
        except Exception as e:
            print(f"Error fetching user name: {e}")
            return 'Guest'
    else:
        print("User is not authenticated")
        return 'Guest'

@app.route('/')
def home():
    return render_template('index.html')

@app.context_processor
def inject_authorize():
    return dict(authorize=authorize)

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        login_input = form.username.data
        if '@' in login_input:
            user = User.query.filter_by(email=login_input).first()
        else:
            user = User.query.filter_by(username=login_input).first()
        if user:
            if bcrypt.check_password_hash(user.PasswordHash, form.password.data):
                login_user(user)
                session['user'] = user.username  # Set the user key in the session
                return redirect(url_for('dashboard'))
            else:
                print("Invalid password")
        else:
            print("User not found")
    return render_template("login.html", form=form)

@app.route("/logout", methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8') 
        new_user = User(
            id=str(uuid.uuid4()),  
            username=form.username.data,
            email=form.email.data,  
            PasswordHash=hashed_password,
            password=form.password.data,
            FullName=form.full_name.data,  
        )
        db.session.add(new_user)
        db.session.commit()
        print("User registered and added to database.")
        return redirect(url_for('login'))
    else:
        print("Form validation failed.")
        print(form.errors)  
    return render_template("register.html", form=form)

@app.route('/about-us')
def about_us():
    return render_template('about-us.html')

@app.route('/support')
def support():
    if 'user' not in session:
        return redirect(url_for('dashboard'))
    problems = getProblems()
    return render_template('support.html', problems=problems)

@app.route('/add_problem', methods=['POST'])
@login_required
def addProblem():
    description = request.form.get('description')
    success, message = add_problem(description)
    flash(message, 'success' if success else 'danger')
    return redirect(url_for('support'))

@app.route('/admin_viewproblems')
@login_required
def view_PendingProblems():
    problems = getPending_Problems()
    return render_template("all_problems.html", problems=problems)

@app.route('/edit_problemstatus/<int:problem_id>', methods=['GET', 'POST'])
@login_required
def editStatus(problem_id):
    if request.method == 'POST':
        new_status = request.form.get('status')
        success, message = update_problem_status(problem_id, new_status)
        flash(message, 'success' if success else 'danger')
        if success:
            return redirect(url_for('view_PendingProblems'))
    problem = Problem.query.get_or_404(problem_id)
    return render_template('edit_problem_status.html', problem=problem)

###################################################################################################################################################
@app.route('/payment', methods=['GET', 'POST'])
def payment():
    if request.method == 'POST':
        return redirect(url_for('confirmation'))
    return render_template('payment.html')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user' not in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        return redirect(url_for('profile'))
    
    return render_template('profile.html')

@app.route('/classes')
def classes():
    logging.debug('Rendering classes page')
    return render_template('class-details.html')

@app.route('/services')
def services():
    logging.debug('Rendering services page')
    return render_template('services.html')

@app.route('/team')
def team():
    return render_template('team.html')

@app.route('/class-timetable')
def class_timetable():
    logging.debug('Rendering class timetable page')
    return render_template('class-timetable.html')

@app.route('/bmi-calculator')
def bmi_calculator():
    return render_template('bmi-calculator.html')

@app.route('/gallery')
def gallery():
    return render_template('gallery.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    # Example data for the dashboard
    user_data = {
        'fitness_goals': 'Lose 5kg in 3 months',
        'workouts': '3 workouts per week',
        'nutrition': '1500 calories per day',
        'progress': {
            'weight_loss': [70, 69, 68, 67, 66],
            'calories_consumed': [1600, 1500, 1400, 1300, 1200]
        }
    }
    return render_template('dashboard.html', user_data=user_data)

@app.route('/blog')
def blog():
    return render_template('blog.html')

@app.route('/404')
def error_404():
    return render_template('404.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/class-details')
def class_details():
    return render_template('class-details.html')

@app.route('/blog-details')
def blog_details():
    return render_template('blog-details.html')


@app.route('/editforfitnessgoals', methods=['GET', 'POST'])
def editforfitnessgoals():
    if 'user' not in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        
        flash('Fitness goals updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('editforfitnessgoals.html')


@app.route('/editforhealthmetric', methods=['GET', 'POST'])
def editforhealthmetric():
    if 'user' not in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        flash('Health metrics updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('editforhealthmetric.html', health_metrics=session.get('user_data', {}))

@app.route('/main')
def main():
    return render_template('main.html')

if __name__ == '__main__':
    app.run(debug=True)