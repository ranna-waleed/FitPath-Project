import logging
from urllib.parse import urlparse
from flask import Flask, render_template, request, redirect, url_for, session,flash
from flask_bcrypt import Bcrypt

from flask_login import login_required, logout_user, login_user,current_user
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship

import urllib
from flask import jsonify
from datetime import date
from flask_sqlalchemy import SQLAlchemy
from Backend.Support import *
from Backend.Admin import *
from Backend.Login import *
from models import *
from datetime import datetime, timedelta, timezone, time

app = Flask(__name__)

app.config['SECRET_KEY'] = 'login'

params = urllib.parse.quote_plus("DRIVER={ODBC Driver 17 for SQL Server};"
    "SERVER=Mariam;"  
    "DATABASE=FitPath_DB;"  
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
    user = User.query.get(user_id)
    if user:
        return user
    else:
        return None 

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

class DatabaseHelper:
    def __init__(self, db_session):
        self.db_session = db_session

    def execute_and_commit(self, sql_command):
        """Add an object and commit changes."""
        self.db_session.add(sql_command)
        self.db_session.commit()

    def delete_and_commit(self, sql_command):
        """Delete an object and commit changes."""
        self.db_session.delete(sql_command)
        self.db_session.commit()

    def query(self, model, **filters):
        """Query the database."""
        return self.db_session.query(model).filter_by(**filters).all()

    def execute_raw_sql(self, sql, params=None):
        """
        Execute a raw SQL command.
        
        :param sql: The raw SQL query as a string.
        :param params: Optional parameters for the SQL query.
        :return: Result of the execution.
        """
        result = self.db_session.execute(sql, params or {})
        self.db_session.commit()
        return result

class Problem(db.Model):
    __tablename__ = 'problems'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  
    description = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default='Pending')
    user_id = db.Column(db.String(36), db.ForeignKey('Users.id', ondelete='CASCADE'), nullable=False)
    
    user = db.relationship('User', back_populates='problems')

class User(db.Model, UserMixin): 
    __tablename__ = 'Users' 
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid4())) 
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False) 
    password = db.Column(db.String(80), nullable=True) 
    PasswordHash = db.Column(db.String(80), nullable=False) 
    FullName = db.Column(db.String(40), nullable=False) 
    State = db.Column(db.Boolean, nullable=False, default=True) 
    phonenumber = db.Column(db.String(15), nullable=True) 
    
    problems = db.relationship('Problem', back_populates='user') 
    meals = db.relationship('Meal', back_populates='user') 
    assigned_workouts = db.relationship('WorkoutAssignment', back_populates='user')
    workout_plan = db.relationship('WorkoutPlan', back_populates='user')

class Trainer(db.Model):
    __tablename__ = 'Trainers'

    id = db.Column('ID', db.Integer, primary_key=True, autoincrement=True)
    trainer_id = db.Column('TrainerID', db.String(450), nullable=False, unique=True)
    name = db.Column('Name', db.String(256), nullable=False)
    email = db.Column('Email', db.String(256), nullable=False)

    # Relationship with Meals
    meals = db.relationship('Meal', back_populates='trainer')

    def __repr__(self):
        return f"<Trainer(id={self.id}, name={self.name}, email={self.email})>"
    
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
        existing_user_username = User.query.filter_by(username=username.data).first_or_404()
        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different one.")
    
    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first_or_404()
        if existing_user_email:
            raise ValidationError("That email is already registered. Please choose a different one.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"id": "floatingText"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"id": "floatingPassword"})
    remember_me = BooleanField('Remember Me')
    submit = SubmitField("Login")

class UserRole(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)

class HealthMetrics(db.Model):
    __tablename__ = 'health_metrics'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(450), db.ForeignKey('Users.id'), nullable=False)  # Match User model id
    bmi = db.Column(db.Float, nullable=False)  
    weight = db.Column(db.Float, nullable=False)  
    height = db.Column(db.Float, nullable=False)  
    created_at = db.Column('Date', db.Date, nullable=False, default=db.func.current_date())  # Match column name 'Date'
    notes = db.Column('Notes', db.Text, nullable=True)  # Match column name 'Notes'
    

    user = db.relationship('User', backref=db.backref('health_metrics', lazy=True))
    
    def __repr__(self):
        return f'<HealthMetrics {self.id} for User {self.user_id}>'

class Goal(db.Model):
    __tablename__ = 'Goal'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(450), db.ForeignKey('Users.id'), nullable=False)  # Match User model id
    goal = db.Column('Goal', db.String(50), nullable=False) 
    activity_level = db.Column('ActivityLevel', db.String(10), nullable=False)  
    exercise_frequency = db.Column('ExerciseFrequency', db.SmallInteger, nullable=False)  
    target_date = db.Column('TargetDate', db.Date, nullable=True)
    notes = db.Column('Notes', db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)  # Added created_at column

    
    user = db.relationship('User', backref=db.backref('goals', lazy=True))
    def __repr__(self):
        return f'<Goal {self.id} for User {self.user_id}: {self.goal}>'

class caloriesTracker(db.Model):
    __tablename__ = 'caloriesTracker'
    
    Id = db.Column(db.Integer, primary_key=True)
    User_id = db.Column(db.String(450), db.ForeignKey('Users.id'), nullable=False)  
    Calories = db.Column(db.Integer, nullable=False)  
    Date = db.Column(db.Date, nullable=False, default=db.func.current_date())
    

    user = db.relationship('User', backref=db.backref('caloriesTracker', lazy=True))
    
    def __repr__(self):
        return f'<caloriesTracker {self.id} for User {self.user_id}>'

class weightTracker(db.Model):
    __tablename__ = 'weightTracker'
    
    Id = db.Column(db.Integer, primary_key=True)
    User_id = db.Column(db.String(450), db.ForeignKey('Users.id'), nullable=False)
    Week = db.Column(db.SmallInteger, nullable=False)  
    Weight = db.Column(db.DECIMAL(5,2), nullable=False)
    

    user = db.relationship('User', backref=db.backref('weightTracker', lazy=True))
    
    def __repr__(self):
        return f'<weightTracker {self.id} for User {self.user_id}>'
    
class Meal(db.Model):
    __tablename__ = 'Meals'

    id = db.Column('Id', db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column('User_id', db.String(450), db.ForeignKey('Users.id'), nullable=False)
    trainer_id = db.Column('Trainer_id', db.Integer, db.ForeignKey('Trainers.ID'), nullable=False)
    meal_name = db.Column('MealName', db.String(100), nullable=False)
    meal_type = db.Column('MealType', db.String(20), nullable=False)
    calories = db.Column('Calories', db.Integer, nullable=False)
    protein = db.Column('Protein', db.Numeric(5, 2), nullable=True)
    carbs = db.Column('Carbs', db.Numeric(5, 2), nullable=True)
    fats = db.Column('Fats', db.Numeric(5, 2), nullable=True)
    notes = db.Column('Notes', db.Text, nullable=True)
    created_at = db.Column('CreatedAt', db.DateTime, nullable=False)

    # Relationships
    user = db.relationship('User', back_populates='meals')
    trainer = db.relationship("Trainer", back_populates="meals")

    def __repr__(self):
        return f"<Meal(id={self.id}, meal_name={self.meal_name}, user_id={self.user_id})>"

class Workout(db.Model):
    __tablename__ = 'workouts'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(150), nullable=False)
    type = db.Column(db.String(100))  
    duration = db.Column(db.Integer)  
    description = db.Column(db.String)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    assigned_workouts = db.relationship('WorkoutAssignment', back_populates='workout')

class WorkoutPlan(db.Model):
    __tablename__ = 'workout_plans'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.String(450), db.ForeignKey('Users.id'), nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User', back_populates='workout_plan') 

class WorkoutAssignment(db.Model):
    __tablename__ = 'assigned_workouts'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    workout_id = db.Column(db.Integer, db.ForeignKey('workouts.id'), nullable=False)
    user_id = db.Column(db.String(450), db.ForeignKey('Users.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    completed = db.Column(db.Integer, default=0)  
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    workout = db.relationship('Workout', back_populates='assigned_workouts')
    user = db.relationship('User', back_populates='assigned_workouts') 
    
def getCurrentrole():
    user_id = current_user.id
    with engine.connect() as connection:
        result = connection.execute(
            text("SELECT RoleId FROM UserRoles WHERE UserId = :user_id"), {"user_id": user_id}
        )
        role_id = result.scalar()  

        if role_id is None:
            return []  

        claims_result = connection.execute(
            text("SELECT ClaimValue FROM RoleClaims WHERE RoleId = :role_id"), {"role_id": role_id}
        )

        claims = claims_result.fetchall()
        claims_list = [claim[0] for claim in claims]

    return claims_list

def authorize(module, action):
    claims_list = getCurrentrole()  

    for claim in claims_list:
        if f"{module}.{action}" in claim:
            return True 
    
    return False  

def authenticate_user(form):
    """
    Handles user login authentication.
    :param form: The submitted login form.
    :return: Tuple (success: bool, user: User object or None, message: str)
    """
    user = User.query.filter_by(username=form.username.data).first_or_404()
    if user and check_password_hash(user.password, form.password.data):
        return True, user, "Login successful."
    return False, None, "Invalid username or password."

def register_user(form):
    """
    Handles the user registration process.
    :param form: The submitted registration form.
    :return: Tuple (success: bool, message: str)
    """
    if User.query.filter_by(username=form.username.data).first_or_404():
        return False, "Username already exists."
    if User.query.filter_by(email=form.email.data).first_or_404():
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

    user_role = Roles.query.filter_by(name='User').first_or_404()
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

def getPending_Problems(status='Pending'):
    problems = Problem.query.filter_by(user_id=current_user.id, status=status).all()
    return [{'description': p.description, 'status': p.status} for p in problems]

def getProblems():
    problems = Problem.query.filter_by(user_id=current_user.id).all()
    return [{'description': p.description, 'status': p.status, 'id': p.id} for p in problems]

def add_problem(description):
    """
    Adds a new problem to the database.
    :param description: The problem description.
    :return: Tuple (success: bool, message: str)
    """
    if not description:
        return False, "Description is required."  
    
    try:
        new_problem = Problem(description=description, status='Pending', user_id=current_user.id)
        db.session.add(new_problem)
        db.session.commit()
        return True, "Problem added successfully!"  
    except Exception as e:
        db.session.rollback()  
        return False, f"Error adding problem: {str(e)}"  

def update_problem_status(problem_id, new_status):
    """
    Updates the status of an existing problem in the database.
    :param problem_id: The ID of the problem to update.
    :param new_status: The new status to assign to the problem.
    :return: Tuple (success: bool, message: str)
    """
    try:
        problem = Problem.query.get(problem_id)
        if problem:
            problem.status = new_status  
            db.session.commit()  
            return True, "Problem status updated successfully!"
        else:
            return False, "Problem not found."  
    except Exception as e:
        db.session.rollback()  
        return False, f"Error updating problem status: {str(e)}"  

def addGoal(user_id, goal, activity_level, exercise_frequency, target_date, notes):
    if not all([goal, activity_level, exercise_frequency, target_date]):
        return False, "All fields except notes are required."
    
    try:
        newGoal = Goal(user_id=user_id, goal=goal, activity_level=activity_level, exercise_frequency=exercise_frequency, target_date=target_date, notes=notes)
        db.session.add(newGoal)
        db.session.commit()
        return True, "new goal added successfully!"
    except Exception as e:
        db.session.rollback()
        return False, f"Error adding goal:{str(e)}"
    
def addHmetrics(user_id, bmi, weight, height, notes):
    if not all([bmi, weight, height]):
        return False, "BMI, Weight, and Height are required." 
    try: 
        new_metrics= HealthMetrics(user_id=user_id, bmi=bmi, weight=weight, height=height, notes=notes)
        db.session.add(new_metrics)
        db.session.commit()
        return True, "new metrics added successfully!"  
    except Exception as e:
        db.session.rollback()  
        return False, f"Error adding metrics: {str(e)}" 
    
def getUserGoal():
    goal = Goal.query.filter_by(user_id=current_user.id).order_by(Goal.created_at.desc()).first_or_404()
    
    if goal:
        return {
            'id': goal.id,
            'goal': goal.goal,
            'activity_level': goal.activity_level,
            'exercise_frequency': goal.exercise_frequency,
            'target_date': goal.target_date,
            'notes': goal.notes  # Ensure 'notes' is passed
        }
    else:
        return None

def getUserMetrics():
    metrics = HealthMetrics.query.filter_by(user_id=current_user.id).order_by(HealthMetrics.created_at.desc()).first_or_404()
    
    if metrics:
        return {
            'id': metrics.id,
            'weight': metrics.weight,
            'height': metrics.height,
            'bmi': metrics.bmi,
            'notes': metrics.notes  # Ensure 'notes' is passed
        }
    else:
        return None

def update_goal(goal_id, goal, activity_level, exercise_frequency, target_date, notes):
    goal_to_update = Goal.query.filter_by(id=goal_id, user_id=current_user.id).first_or_404()
    if goal_to_update:
        goal_to_update.goal = goal
        goal_to_update.activity_level = activity_level
        goal_to_update.exercise_frequency = exercise_frequency
        goal_to_update.target_date = target_date
        goal_to_update.notes = notes
        db.session.commit()
        flash("Goal updated successfully!", "success")
    else:
        flash("Goal not found.", "danger")

def viewUserMeals():
    try:
        user_meals = Meal.query.filter_by(user_id=current_user.id).all()
        print(user_meals)
        return user_meals
    except Exception as e:
        print(f"Error fetching meals: {e}")
        return []

def get_user_email():
    user = User.query.filter_by(id=current_user.id).first()
    if user:
        return user.email
    else:
        return None  
    
def get_user_number():
    user = User.query.filter_by(id=current_user.id).first()
    if user:
        return user.phonenumber
    else:
        return None  

def getUserInfo():
    Name = getName() 
    Email = get_user_email()
    Phonenumber = get_user_number()
    
    return Name, Email, Phonenumber

def getTodaysWorkout():
    user_id = current_user.id
    today = datetime.now(timezone.utc).date()
    
    todays_workouts = db.session.query(WorkoutAssignment).join(
    User, WorkoutAssignment.user_id == User.id
    ).filter(
    WorkoutAssignment.user_id == user_id,
    WorkoutAssignment.date == today
    ).all()


    return todays_workouts

def getFullWorkoutPlan():
    user_id = current_user.id
    
    today = datetime.now(timezone.utc).date()  
    
    days_since_saturday = (today.weekday() - 5) % 7  
    start_of_week = today - timedelta(days=days_since_saturday)
    end_of_week = start_of_week + timedelta(days=6)
    
    start_of_week = datetime.combine(start_of_week, time.min, tzinfo=timezone.utc)  
    end_of_week = datetime.combine(end_of_week, time.max, tzinfo=timezone.utc)  
    
    all_workouts = db.session.query(WorkoutAssignment).join(
        WorkoutAssignment.workout 
    ).filter(
        WorkoutAssignment.user_id == user_id,
        WorkoutAssignment.date >= start_of_week,
        WorkoutAssignment.date <= end_of_week
    ).order_by(WorkoutAssignment.date).all()
    
    return all_workouts

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
            user = User.query.filter_by(email=login_input).first_or_404()
        else:
            user = User.query.filter_by(username=login_input).first_or_404()
        if user:
            if bcrypt.check_password_hash(user.PasswordHash, form.password.data):
                login_user(user)
                session['user'] = user.username  
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
    session.clear()
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
        return redirect(url_for('healthMetrics_insert'))
    else:
        print("Form validation failed.")
        print(form.errors)  
    return render_template("register.html", form=form)

@app.route('/about-us')
def about_us():
    return render_template('about-us.html')

@app.route('/support')
@login_required
def support():

    problems = getProblems()  
    return render_template('support.html', problems=problems)  

@app.route('/add_problem', methods=['POST'])
@login_required
def addProblem():
    description = request.form.get('description')  
    success, message = add_problem(description)  
    flash(message, 'success' if success else 'danger')  
    return redirect(url_for('support'))  

@app.route('/Healthmetrics_Insert', methods=['GET','POST'])  
def healthMetrics_insert():
    if request.method == 'POST':
        user_id = current_user.id
        bmi = float(request.form.get('bmi'))
        weight = float(request.form.get('weight'))
        height = float(request.form.get('height'))
        notes = request.form.get('notes', '')

        success, message = addHmetrics(user_id, bmi, weight, height, notes)
        if success:
            return redirect(url_for('userGoal_insert'))
        else:
            return message, 400

    return render_template('healthmetrics.html')

@app.route('/GoalInsert', methods=['GET', 'POST'])  
def userGoal_insert():
    if request.method == 'POST':
        userId = current_user.id
        goal = request.form.get('goal')
        activity_level = request.form.get('activity_level')
        exercise_frequency = request.form.get('exercise_frequency')
        target_date = request.form.get("target_date")
        notes = request.form.get('notes', '')
    
        success, message = addGoal(userId, goal, activity_level, exercise_frequency, target_date, notes)
        if success:
            return redirect(url_for('login'))  
        else:
            return message, 400
    return render_template('goals.html')

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    user_id = current_user.id
    
    # Get the user's latest goal
    user_goal_data = getUserGoal()
    if user_goal_data:
        user_goal = f"{user_goal_data.get('goal', 'Unknown Goal')} before {user_goal_data.get('target_date', 'No target date')}"
    else:
        user_goal = "No goals set"
    
    # Get the user's latest health metrics
    metrics = getUserMetrics()  
    
    # Fetch all goals for the user 
    goals = Goal.query.filter_by(user_id=user_id)
    
    return render_template('dashboard.html', metrics=metrics, goals=goals, user_goal=user_goal)

@app.route('/weight-data', methods=['GET'])
@login_required
def get_weight_data():
    user_id = current_user.id
    weight_data = db.session.query(weightTracker.Week, weightTracker.Weight).filter_by(User_id=user_id).all()
    if weight_data:
        for data in weight_data:
            print(f"Week: {data.Week}, Weight: {data.Weight}")
            
    else:
        print("No data in weight_data")
    return jsonify([{'week': f"Wk {w[0]}", 'weight': float(w[1])} for w in weight_data])

@app.route('/calories-data', methods=['GET'])
@login_required
def get_calories_data():
    user_id = current_user.id
    calories_data = db.session.query(caloriesTracker.Date, caloriesTracker.Calories).filter_by(User_id=user_id).all()
    if calories_data:
        for data in calories_data:
            print(f"Date: {data.Date}, Calories: {data.Calories}")
            
    else:
        print("No data in calories tracker")
    # Format date into readable day names
    formatted_data = [{'day': d.Date.strftime('%A'), 'calories': d.Calories} for d in calories_data]
    return jsonify(formatted_data)

@app.route('/update-goals', methods=['GET', 'POST'])
@login_required
def update_goals():
    if request.method == 'POST':
        goal_id = request.form['goal_id']
        goal = request.form['goal']
        activity_level = request.form['activity_level']
        exercise_frequency = request.form['exercise_frequency']
        target_date = request.form['target_date']
        notes = request.form['notes']

        if not goal or not activity_level or not exercise_frequency or not target_date:
            flash("Please fill out all required fields", "danger")
            return redirect(url_for('update_goals'))

        # Save a new row for the updated goal
        new_goal = Goal(
            user_id=current_user.id,
            goal=goal,
            activity_level=activity_level,
            exercise_frequency=exercise_frequency,
            target_date=target_date,
            notes=notes
        )
        db.session.add(new_goal)
        db.session.commit()

        flash("Goal updated successfully!", "success")
        return redirect(url_for('dashboard'))  # Redirect to dashboard

    # On GET, fetch the latest goal to display in the form
    goal = getUserGoal()
    if goal:
        return render_template('edit_goals.html', goal=goal)
    else:
        flash("No goals found", "warning")
        return redirect(url_for('dashboard'))

########################New#####################
@app.route('/view-meals', methods=['GET'])
@login_required
def view_meals():
    meals = viewUserMeals()
    return render_template('view_meals.html', meals=meals)

@app.route('/edit-health-metrics', methods=['GET', 'POST'])
@login_required
def edit_health_metrics():
    health_metrics = HealthMetrics.query.filter_by(user_id=current_user.id).first_or_404()

    if request.method == 'POST':
        # Fetch form data
        weight = request.form.get('weight')
        height = request.form.get('height')
        bmi = request.form.get('bmi')
        notes = request.form.get('notes')

        # Validate required fields
        if not weight or not height or not bmi:
            flash("Please fill out all required fields", "danger")
            return redirect(url_for('edit_health_metrics'))

        try:
            # Update the health metrics record
            health_metrics.weight = float(weight)
            health_metrics.height = float(height)
            health_metrics.bmi = float(bmi)
            health_metrics.notes = notes
            db.session.commit()

            flash("Health metrics updated successfully!", "success")
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f"An error occurred while updating health metrics: {e}", "danger")
            return redirect(url_for('edit_health_metrics'))

    # On GET: Render the edit form with current health metrics
    return render_template(
        'update_health_metrics.html',
        Weight=health_metrics.weight,
        Height=health_metrics.height,
        BMI=health_metrics.bmi,
        notes=health_metrics.notes
    )

#Profile
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user' not in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        return redirect(url_for('profile'))
    
    return render_template('profile.html')

@app.route('/goalProfile')
@login_required
def profilegoal():
    usergoal = getUserGoal()
    return render_template("view_goals.html", goal = usergoal)

@app.route('/metricsProfile')
@login_required
def profilemetrics():
    usermetrics = getUserMetrics()
    return render_template("view_health_metrics.html", metrics = usermetrics)

@app.route('/infoProfile')
@login_required
def userInfoProfile():
    userInfo = getUserInfo()
    return render_template("personal_info.html", userInfo = userInfo)

@app.route('/edit_infoProfile', methods=['GET', 'POST'])
@login_required
def editUserInfo():
    userinfo = User.query.filter_by(id=current_user.id).first_or_404()

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')

        if not name or not email or not phone:
            flash("Please fill out all required fields", "danger")
            return redirect(url_for('edit_infoProfile'))

        try:
            userinfo.name = name
            userinfo.email = email
            userinfo.phone = phone
            db.session.commit()

            flash("Profile updated successfully!", "success")
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f"An error occurred while updating Profile: {e}", "danger")
            return redirect(url_for('editUserInfo'))

    return render_template(
        'personal_info.html',
        name=userinfo.weight,
        email=userinfo.height,
        phone=userinfo.bmi
    )

#Workout
@app.route('/todays-workout')
def todays_workout():
    todays_workouts = getTodaysWorkout()

    return render_template('todays_workout.html', workouts=todays_workouts)

@app.route('/full-workout')
def workout_plan():    
    all_workouts = getFullWorkoutPlan()
    
    for workout in all_workouts:
        print(workout.workout.name, workout.date)

    return render_template('workout_plan.html', workouts=all_workouts)
    

#NOT TESTED
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


# @app.route('/view-meals')
# def view_meals():
#     return render_template('view_meals.html')

# @app.route('/edit-meals')
# def edit_meals():
#     return render_template('edit_meals.html')

# @app.route('/create-meals')
# def create_meals():
#     return render_template('create_meals.html')


# @app.route('/view-health-metrics')
# def view_health_metrics():
#     return render_template('view_health_metrics.html')

# @app.route('/view-goals')
# def view_goals():
#     return render_template('view_goals.html')

# @app.route('/edit-goals')
# def edit_goals():
#     return render_template('edit_goals.html')

# @app.route('/goals')
# def goals():
#     return render_template('goals.html')


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

@app.route('/main')
def main():
    return render_template('main.html')

if __name__ == '__main__':
    app.run(debug=True)