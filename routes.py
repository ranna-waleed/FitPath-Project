from app import app, db, bcrypt
from flask import render_template, redirect, url_for, request, session, flash
from flask_login import login_required, login_user, logout_user, current_user
from models import User
from forms import RegisterForm, LoginForm




@app.route('/')
def home():
    return render_template('index.html')



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


@app.route('/view-meals')
def view_meals():
    return render_template('view_meals.html')


@app.route('/edit-meals')
def edit_meals():
    return render_template('edit_meals.html')


@app.route('/create-meals')
def create_meals():
    return render_template('create_meals.html')


@app.route('/view-health-metrics')
def view_health_metrics():
    return render_template('view_health_metrics.html')


@app.route('/edit-health-metrics')
def edit_health_metrics():
    return render_template('edit_health_metrics.html')


@app.route('/update-health-metrics')
def update_health_metrics():
    return render_template('update_health_metrics.html')


@app.route('/view-goals')
def view_goals():
    return render_template('view_goals.html')


@app.route('/edit-goals')
def edit_goals():
    return render_template('edit_goals.html')


@app.route('/goals')
def goals():
    return render_template('goals.html')


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