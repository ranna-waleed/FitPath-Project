# class HealthMetrics(db.Model):
#     __tablename__ = 'health_metrics'
    
#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.String(450),  db.ForeignKey('user.id'), nullable=False) 
#     bmi = db.Column(db.Float, nullable=False)  
#     weight = db.Column(db.Float, nullable=False)  
#     height = db.Column(db.Float, nullable=False)  
#     created_at = db.Column(db.DateTime, nullable=False, default=db.func.now())  
#     note = db.Column(db.text, nullable=True, default ="NULL")

#     user = db.relationship('User', backref=db.backref('health_metrics', lazy=True))

#     def __repr__(self):
#         return f'<HealthMetrics {self.id} for User {self.user_id}>'

# class Goal(db.Model):
#     __tablename__ = 'Goal'
    
#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.String(450),  db.ForeignKey('user.id'), nullable=False) 
#     goal = db.Column(db.String(100), nullable=False) 
#     activity_level = db.Column(db.String(50), nullable=False)  
#     exercise_frequency = db.Column(db.Integer, nullable=False)  
#     targetDate = db.Column(db.Date, nullable=True)
#     note = db.Column(db.text, nullable=True)
#     user = db.relationship('User', backref=db.backref('Goal', lazy=True))

#     def __repr__(self):
#         return f'<Goal {self.id} for User {self.user_id}: {self.goal}>'

# def addGoal(user_id, goal, activity_level, exercise_frequency, target_date, notes):
#     if not all([goal, activity_level, exerciseFrequency, targetDate]):
#         return False, "All fields except note are required."
    
#     try:
#         newGoal = Goal(user_id=user_id.id, goal=goal, activity_level=activity_level, exercise_frequency=exercise_frequency, target_date=target_date, notes=notes)
#         db.session.add(newGoal)
#         db.session.commit()
#         return True, "new goal added successfully!"
#     except Exception as e:
#         db.session.rollback()
#         return False, f"Error adding goal:{str(e)}"
    
# def addHmetrics(user_id, bmi, weight, height, note):
#     if not all([bmi, weight, height]):
#         return False, "BMI, Weight, and Height are required." 
#     try: 
#         new_metrics= Healthmetrics(user_id=user_id.id,bmi=bmi, weight=weight, height=height, note=note)
#         db.session.add(new_metrics)
#         db.session.commit()
#         return True, "new metrics added successfully!"  
#     except Exception as e:
#         db.session.rollback()  
#         return False, f"Error adding metrics: {str(e)}" 

# app.route('/Healthmetrics_Insert', methods=['POST'])  
# def healthMetrics_insert():
#     user_id = current_user.id
#     bmi = request.form.get('bmi') 
#     weight = request.form.get('weight') 
#     height = request.form.get('height') 
#     note = request.form.get('notes', '') 
    
#     success, message = addHmetrics(user_id, bmi, weight, height, note)
#     if success:
#         return redirect(url_for('userGoal_insert'))
#     else:
#         return message, 400 
   
# app.route('/GoalInsert', methods=['POST'])  
# def userGoal_insert():
#     userId = current_user.id
#     goal = request.form.get('goal')
#     activity_level = request.form.get('activity_level')
#     exercise_frequency = request.form.get('exercise_frequency')
#     target_date = request.form.get("target_date")
#     notes = request.form.get('notes', '')
    
#     success, message = addGoal(user_id, goal, activity_level, exercise_frequency, target_date, notes)
#     if success:
#         return redirect(url_for('login'))  
#     else:
#         return message, 400

  

def getUserGoal():
    goals = Goal.query.filter_by(user_id=current_user.id).order_by(desc(Goal.created_at)).first()
    if goals:
        return [{'id': g.id, 'Goal': g.goal, 'Activity level': g.activity_level,'Frequency': g.exercise_frequency, 'target date':g.target_date } for g in goals]
    else:
        return None
def getUserMetrics():
    metrics = HealthMetrics.query.filter_by(user_id=current_user.id).order_by(desc(HealthMetrics.created_at)).first()
    if metrics:
        return [{'id': m.id, 'height': m.height, 'weight': m.weight, 'bmi': m.bmi} for m in metrics]
    else: 
        return None