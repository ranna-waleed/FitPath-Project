from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import InputRequired, Length, ValidationError, Email
from datetime import datetime
import uuid
from app import db



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
    description = db.Column(db.Text, nullable=False)  
    status = db.Column(db.String(50), nullable=False, default='Pending')  
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)  
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)  

    def __repr__(self):
        return f'<Problem {self.id} - {self.description[:20]}... (Status: {self.status})>'
    
class UserRole(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    
