import unittest
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin
import sys
import os

# Add the parent directory to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))) 
from models import User, Problem

class TestApp(unittest.TestCase):

    def setUp(self):
        # Create a test Flask application
        self.app = Flask(__name__) 
        self.app.config['TESTING'] = True
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

        # Initialize extensions
        self.db = SQLAlchemy(self.app)
        self.bcrypt = Bcrypt(self.app)
        self.login_manager = LoginManager()
        self.login_manager.init_app(self.app)

        # Create tables
        with self.app.app_context():
            self.db.create_all()

    def tearDown(self):
        # Drop all tables after each test
        with self.app.app_context():
            self.db.session.remove()
            self.db.drop_all()

    def test_user_creation(self):
        with self.app.app_context():
            # Create a new user
            user = User(username='testuser', email='test@example.com', password=self.bcrypt.generate_password_hash('password').decode('utf-8'))
            self.db.session.add(user)
            self.db.session.commit()

            # Query the user and check if it exists
            queried_user = User.query.filter_by(username='testuser').first()
            self.assertIsNotNone(queried_user)
            self.assertEqual(queried_user.email, 'test@example.com')

    def test_problem_creation(self):
        with self.app.app_context():
            # Create a new user and problem
            user = User(username='testuser', email='test@example.com', password=self.bcrypt.generate_password_hash('password').decode('utf-8'))
            self.db.session.add(user)
            self.db.session.commit()

            problem = Problem(description='Test problem', status='Pending', user_id=user.id)
            self.db.session.add(problem)
            self.db.session.commit()

            # Query the problem and check if it exists
            queried_problem = Problem.query.filter_by(description='Test problem').first()
            self.assertIsNotNone(queried_problem)
            self.assertEqual(queried_problem.status, 'Pending')

if __name__ == '_main_':
    unittest.main()