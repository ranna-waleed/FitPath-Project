import unittest
from unittest.mock import patch, MagicMock
from flask import Flask
from app import app, add_problem, addHmetrics, addGoal, getUserGoal, getUserMetrics

class FlaskAppTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_home(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)

    def test_login(self):
        response = self.app.get('/login')
        self.assertEqual(response.status_code, 200)

    def test_register(self):
        response = self.app.get('/register')
        self.assertEqual(response.status_code, 200)

    def test_about_us(self):
        response = self.app.get('/about-us')
        self.assertEqual(response.status_code, 200)

    def test_support(self):
        with patch('app.getProblems', return_value=[]):
            response = self.app.get('/support', follow_redirects=True)
            self.assertEqual(response.status_code, 200)

    def test_add_problem(self):
        with patch('app.add_problem', return_value=(True, "Problem added successfully!")):
            response = self.app.post('/add_problem', data=dict(description='Test problem'), follow_redirects=True)
            self.assertEqual(response.status_code, 200)

    def test_healthMetrics_insert(self):
        response = self.app.get('/Healthmetrics_Insert')
        self.assertEqual(response.status_code, 200)

    def test_userGoal_insert(self):
        response = self.app.get('/GoalInsert')
        self.assertEqual(response.status_code, 200)

    def test_dashboard(self):
        with patch('app.get_user_role', return_value="User"):
            response = self.app.get('/dashboard', follow_redirects=True)
            self.assertEqual(response.status_code, 200)

    def test_user_dashboard(self):
        with patch('app.getUserGoal', return_value={'goal': 'Lose weight', 'target_date': '2024-12-31'}):
            with patch('app.getUserMetrics', return_value={'weight': 70, 'height': 175, 'bmi': 22.9}):
                response = self.app.get('/user_dashboard', follow_redirects=True)
                self.assertEqual(response.status_code, 200)

    def test_get_weight_data(self):
        with patch('app.db.session.query', return_value=MagicMock(all=MagicMock(return_value=[]))):
            response = self.app.get('/weight-data', follow_redirects=True)
            self.assertEqual(response.status_code, 200)

    def test_get_calories_data(self):
        with patch('app.db.session.query', return_value=MagicMock(all=MagicMock(return_value=[]))):
            response = self.app.get('/calories-data', follow_redirects=True)
            self.assertEqual(response.status_code, 200)

    def test_update_goals(self):
        response = self.app.get('/update-goals', follow_redirects=True)
        self.assertEqual(response.status_code, 200)

    def test_view_meals(self):
        with patch('app.viewUserMeals', return_value=[]):
            response = self.app.get('/view-meals', follow_redirects=True)
            self.assertEqual(response.status_code, 200)

    def test_profilegoal(self):
        with patch('app.getUserGoal', return_value={'goal': 'Lose weight', 'target_date': '2024-12-31'}):
            response = self.app.get('/goalProfile', follow_redirects=True)
            self.assertEqual(response.status_code, 200)

    def test_profilemetrics(self):
        with patch('app.getUserMetrics', return_value={'weight': 70, 'height': 175, 'bmi': 22.9}):
            response = self.app.get('/metricsProfile', follow_redirects=True)
            self.assertEqual(response.status_code, 200)

    def test_userInfoProfile(self):
        with patch('app.getUserInfo', return_value=('John Doe', 'john@example.com', '1234567890')):
            response = self.app.get('/infoProfile', follow_redirects=True)
            self.assertEqual(response.status_code, 200)

    def test_todays_workout(self):
        with patch('app.getTodaysWorkout', return_value=[]):
            response = self.app.get('/todays-workout', follow_redirects=True)
            self.assertEqual(response.status_code, 200)

    def test_workout_plan(self):
        with patch('app.getFullWorkoutPlan', return_value=[]):
            response = self.app.get('/full-workout', follow_redirects=True)
            self.assertEqual(response.status_code, 200)

    def test_todays_nutrition(self):
        with patch('app.getTodaysMeals', return_value=[]):
            response = self.app.get('/todays-nutrition', follow_redirects=True)
            self.assertEqual(response.status_code, 200)

    def test_weekly_nutrition(self):
        with patch('app.getWeeklyMeals', return_value=[]):
            response = self.app.get('/weekly-nutrition', follow_redirects=True)
            self.assertEqual(response.status_code, 200)

if __name__ == '__main__':
    unittest.main()