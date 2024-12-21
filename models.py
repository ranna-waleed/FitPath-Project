# from extensions import db
# from flask_login import UserMixin
# from flask_wtf import FlaskForm
# from wtforms import StringField, PasswordField, SubmitField, BooleanField
# from wtforms.validators import InputRequired, Length, ValidationError, Email, EqualTo
# from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
# from sqlalchemy.orm import relationship
# from datetime import datetime
# from uuid import uuid4

# class Problem(db.Model):
#     __tablename__ = 'problems'
#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)  
#     description = db.Column(db.String(200), nullable=False)
#     status = db.Column(db.String(20), default='Pending')
#     user_id = db.Column(db.String(36), db.ForeignKey('Users.id', ondelete='CASCADE'), nullable=False)
    
#     user = db.relationship('User', back_populates='problems')

# class User(db.Model, UserMixin): 
#     __tablename__ = 'Users' 
#     id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid4())) 
#     username = db.Column(db.String(20), unique=True, nullable=False)
#     email = db.Column(db.String(100), unique=True, nullable=False) 
#     password = db.Column(db.String(80), nullable=True) 
#     PasswordHash = db.Column(db.String(80), nullable=False) 
#     FullName = db.Column(db.String(40), nullable=False) 
#     State = db.Column(db.Boolean, nullable=False, default=True) 
#     phonenumber = db.Column(db.String(15), nullable=True) 
    
#     problems = db.relationship('Problem', back_populates='user') 
#     meals = db.relationship('Meal', back_populates='user') 
#     assigned_workouts = db.relationship('WorkoutAssignment', back_populates='user')
#     workout_plan = db.relationship('WorkoutPlan', back_populates='user')
#     meal_assignments = db.relationship('MealAssignment', back_populates='user')
#     roles = db.relationship('Roles', secondary='UserRoles', back_populates='users', lazy='dynamic')
#     trainer_assignment = db.relationship("UserTrainerAssignment", back_populates="user")

# class Trainer(db.Model):
#     __tablename__ = 'Trainers'

#     id = db.Column('ID', db.Integer, primary_key=True, autoincrement=True)
#     trainer_id = db.Column('TrainerID', db.String(450), nullable=False, unique=True)
#     name = db.Column('Name', db.String(256), nullable=False)
#     email = db.Column('Email', db.String(256), nullable=False)

#     meals = db.relationship('Meal', back_populates='trainer')
#     users = relationship("UserTrainerAssignment", back_populates="trainer")

#     def __repr__(self):
#         return f"<Trainer(id={self.id}, name={self.name}, email={self.email})>"

# class UserTrainerAssignment(db.Model):
#     __tablename__ = 'UserTrainerAssignment'

#     user_id = db.Column('UserID',db.String(450), ForeignKey('Users.id'), primary_key=True)
#     trainer_id = db.Column('TrainerID', db.Integer, ForeignKey('Trainers.ID'), primary_key=True)

#     user = relationship("User", back_populates="trainer_assignment")
#     trainer = relationship("Trainer", back_populates="users")
        
# class RegisterForm(FlaskForm):
#     username = StringField(
#         validators=[InputRequired(), Length(min=4, max=20)],
#         render_kw={"placeholder": "Username"}
#     )
#     email = StringField(
#         validators=[InputRequired(), Length(min=6, max=120), Email()],
#         render_kw={"placeholder": "Email"}
#     )
#     full_name = StringField(
#         validators=[InputRequired(), Length(min=2, max=100)],
#         render_kw={"placeholder": "Full Name"}
#     )
#     password = PasswordField(
#         validators=[InputRequired(), Length(min=4, max=20)],
#         render_kw={"placeholder": "Password"}
#     )
#     confirm_password = PasswordField(
#         validators=[InputRequired(), EqualTo('password', message='Passwords must match')],
#         render_kw={"placeholder": "Confirm Password"}
#     )
#     submit = SubmitField("Register")
    
#     def validate_username(self, username):
#         existing_user_username = User.query.filter_by(username=username.data).first_or_404()
#         if existing_user_username:
#             raise ValidationError("That username already exists. Please choose a different one.")
    
#     def validate_email(self, email):
#         existing_user_email = User.query.filter_by(email=email.data).first_or_404()
#         if existing_user_email:
#             raise ValidationError("That email is already registered. Please choose a different one.")

# class LoginForm(FlaskForm):
#     username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"id": "floatingText"})
#     password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"id": "floatingPassword"})
#     remember_me = BooleanField('Remember Me')
#     submit = SubmitField("Login")

# class HealthMetrics(db.Model):
#     __tablename__ = 'health_metrics'
    
#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.String(450), db.ForeignKey('Users.id'), nullable=False)  # Match User model id
#     bmi = db.Column(db.Float, nullable=False)  
#     weight = db.Column(db.Float, nullable=False)  
#     height = db.Column(db.Float, nullable=False)  
#     created_at = db.Column('Date', db.Date, nullable=False, default=db.func.current_date())  # Match column name 'Date'
#     notes = db.Column('Notes', db.Text, nullable=True)  # Match column name 'Notes'
    

#     user = db.relationship('User', backref=db.backref('health_metrics', lazy=True))
    
#     def __repr__(self):
#         return f'<HealthMetrics {self.id} for User {self.user_id}>'

# class Goal(db.Model):
#     __tablename__ = 'Goal'
    
#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.String(450), db.ForeignKey('Users.id'), nullable=False)  # Match User model id
#     goal = db.Column('Goal', db.String(50), nullable=False) 
#     activity_level = db.Column('ActivityLevel', db.String(10), nullable=False)  
#     exercise_frequency = db.Column('ExerciseFrequency', db.SmallInteger, nullable=False)  
#     target_date = db.Column('TargetDate', db.Date, nullable=True)
#     notes = db.Column('Notes', db.Text, nullable=True)
#     created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)  # Added created_at column

    
#     user = db.relationship('User', backref=db.backref('goals', lazy=True))
#     def __repr__(self):
#         return f'<Goal {self.id} for User {self.user_id}: {self.goal}>'

# class caloriesTracker(db.Model):
#     __tablename__ = 'caloriesTracker'
    
#     Id = db.Column(db.Integer, primary_key=True)
#     User_id = db.Column(db.String(450), db.ForeignKey('Users.id'), nullable=False)  
#     Calories = db.Column(db.Integer, nullable=False)  
#     Date = db.Column(db.Date, nullable=False, default=db.func.current_date())
    

#     user = db.relationship('User', backref=db.backref('caloriesTracker', lazy=True))
    
#     def __repr__(self):
#         return f'<caloriesTracker {self.id} for User {self.user_id}>'

# class weightTracker(db.Model):
#     __tablename__ = 'weightTracker'
    
#     Id = db.Column(db.Integer, primary_key=True)
#     User_id = db.Column(db.String(450), db.ForeignKey('Users.id'), nullable=False)
#     Week = db.Column(db.SmallInteger, nullable=False)  
#     Weight = db.Column(db.DECIMAL(5,2), nullable=False)
    

#     user = db.relationship('User', backref=db.backref('weightTracker', lazy=True))
    
#     def __repr__(self):
#         return f'<weightTracker {self.id} for User {self.user_id}>'
    
# class Meal(db.Model):
#     __tablename__ = 'Meals'

#     id = db.Column('Id', db.Integer, primary_key=True, autoincrement=True)
#     user_id = db.Column('User_id', db.String(450), db.ForeignKey('Users.id'), nullable=False)
#     trainer_id = db.Column('Trainer_id', db.Integer, db.ForeignKey('Trainers.ID'), nullable=False)
#     meal_name = db.Column('MealName', db.String(100), nullable=False)
#     meal_type = db.Column('MealType', db.String(20), nullable=False)
#     calories = db.Column('Calories', db.Integer, nullable=False)
#     protein = db.Column('Protein', db.Numeric(5, 2), nullable=True)
#     carbs = db.Column('Carbs', db.Numeric(5, 2), nullable=True)
#     fats = db.Column('Fats', db.Numeric(5, 2), nullable=True)
#     notes = db.Column('Notes', db.Text, nullable=True)
#     created_at = db.Column('CreatedAt', db.DateTime, nullable=False)

#     # Relationships
#     user = db.relationship('User', back_populates='meals')
#     trainer = db.relationship("Trainer", back_populates="meals")
#     meal_assignments = db.relationship('MealAssignment', back_populates='meal')


#     def __repr__(self):
#         return f"<Meal(id={self.id}, meal_name={self.meal_name}, user_id={self.user_id})>"

# class MealAssignment(db.Model):
#     __tablename__ = 'meal_assignments'

#     id = Column(Integer, primary_key=True, autoincrement=True)
#     meal_id = Column(Integer, ForeignKey('Meals.Id'), nullable=False)
#     user_id = Column(String(450), ForeignKey('Users.id'), nullable=False)
#     date = Column(DateTime, nullable=False)  
#     calories = Column(Integer)  
#     created_at = Column(DateTime, default=datetime.utcnow)
#     updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

#     # Relationships
#     meal = relationship('Meal', back_populates='meal_assignments')
#     user = relationship('User', back_populates='meal_assignments')

# class Workout(db.Model):
#     __tablename__ = 'workouts'
    
#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     name = db.Column(db.String(150), nullable=False)
#     type = db.Column(db.String(100))  
#     duration = db.Column(db.Integer)  
#     description = db.Column(db.String)
#     created_at = db.Column(db.DateTime, default=datetime.utcnow)
#     updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

#     assigned_workouts = db.relationship('WorkoutAssignment', back_populates='workout')

# class WorkoutPlan(db.Model):
#     __tablename__ = 'workout_plans'

#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     user_id = db.Column(db.String(450), db.ForeignKey('Users.id'), nullable=False)
#     start_date = db.Column(db.DateTime, nullable=False)
#     end_date = db.Column(db.DateTime)
#     created_at = db.Column(db.DateTime, default=datetime.utcnow)
#     updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

#     user = db.relationship('User', back_populates='workout_plan') 

# class WorkoutAssignment(db.Model):
#     __tablename__ = 'assigned_workouts'
    
#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     workout_id = db.Column(db.Integer, db.ForeignKey('workouts.id'), nullable=False)
#     user_id = db.Column(db.String(450), db.ForeignKey('Users.id'), nullable=False)
#     date = db.Column(db.DateTime, nullable=False)
#     completed = db.Column(db.Integer, default=0)  
#     created_at = db.Column(db.DateTime, default=datetime.utcnow)
#     updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

#     workout = db.relationship('Workout', back_populates='assigned_workouts')
#     user = db.relationship('User', back_populates='assigned_workouts') 
    
# class UserRoles(db.Model):
#     __tablename__ = 'UserRoles'
    
#     UserId = db.Column(db.String(450), db.ForeignKey('Users.id'), primary_key=True, nullable=False)
#     RoleId = db.Column(db.String(450), db.ForeignKey('Roles.id'), primary_key=True, nullable=False)
    
#     user = db.relationship('User', backref=db.backref('user_roles', lazy='dynamic'))
#     role = db.relationship('Roles', backref=db.backref('role_users', lazy='dynamic'))

# # Roles Model
# class Roles(db.Model):
#     __tablename__ = 'Roles'
    
#     id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid4()))
#     Name = db.Column(db.String(50), nullable=True, unique=True)
    
#     users = db.relationship('User', secondary='UserRoles', back_populates='roles', lazy='dynamic')
#     def __repr__(self):
#         return f"<Role {self.Name}>"
