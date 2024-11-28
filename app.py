from flask import Flask, render_template, request, redirect, url_for, session,flash

# app = Flask(__name__)
# app.secret_key = 'your_secret_key'  # Needed for session management

# @app.route('/')
# def home():
#     return render_template('index.html')

# @app.route('/about-us')
# def about_us():
#     return render_template('about-us.html')

# @app.route('/classes')
# def classes():
#     return render_template('classes.html')

# @app.route('/services')
# def services():
#     return render_template('services.html')

# @app.route('/team')
# def team():
#     return render_template('team.html')


# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         # Temporarily bypass credential check
#         email = request.form['email']
#         session['user'] = email
#         return redirect(url_for('dashboard'))
#     return render_template('login.html')
  

# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         # Handle the form submission
#         # Redirect to the payment page
#         return redirect(url_for('payment'))
#     return render_template('register.html')

# @app.route('/class-timetable')
# def class_timetable():
#     return render_template('class-timetable.html')


# @app.route('/bmi-calculator')
# def bmi_calculator():
#     return render_template('bmi-calculator.html')

# @app.route('/gallery')
# def gallery():
#     return render_template('gallery.html')

# @app.route('/blog')
# def blog():
#     return render_template('blog.html')

# @app.route('/payment', methods=['GET', 'POST'])
# def payment():
#     if request.method == 'POST':
#         # Handle the payment submission
#         return redirect(url_for('confirmation'))
#     return render_template('payment.html')

# @app.route('/404')
# def error_404():
#     return render_template('404.html')

# @app.route('/contact')
# def contact():
#     return render_template('contact.html')

# @app.route('/class-details')
# def class_details():
#     return render_template('class-details.html')

# @app.route('/blog-details')
# def blog_details():
#     return render_template('blog-details.html')

# @app.route('/main')
# def main():
#     return render_template('main.html')

# @app.route('/dashboard')
# def dashboard():
#     if 'user' not in session:
#         return redirect(url_for('login'))
#     # Example data for the dashboard
#     user_data = {
#         'fitness_goals': 'Lose 5kg in 3 months',
#         'workouts': '3 workouts per week',
#         'nutrition': '1500 calories per day',
#         'progress': {
#             'weight_loss': [70, 69, 68, 67, 66],
#             'calories_consumed': [1600, 1500, 1400, 1300, 1200]
#         }
#     }
#     return render_template('dashboard.html', user_data=user_data)

# if __name__ == '__main__':
#     app.run(debug=True)
import logging
from urllib.parse import urlparse
from flask import Flask, render_template, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Set this to a unique and secret value

logging.basicConfig(level=logging.DEBUG)

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

    # Fall back to a generic 404 template
    return render_template('404.html'), 404

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/support')
def support():
    if 'user' not in session:
        return redirect(url_for('dashboard'))
    return render_template('support.html')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user' not in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Handle form submission to update user details, goals, or health metrics
        # For now, just redirect back to the profile page
        return redirect(url_for('profile'))
    
    return render_template('profile.html')

@app.route('/payment', methods=['GET', 'POST'])
def payment():
    if request.method == 'POST':
        # Handle the payment submission
        return redirect(url_for('confirmation'))
    return render_template('payment.html')

@app.route('/about-us')
def about_us():
    return render_template('about-us.html')

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

@app.route('/main')
def main():
    return render_template('main.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Temporarily bypass credential check
        email = request.form['email']
        session['user'] = email
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Handle the form submission
        # Redirect to the payment page
        return redirect(url_for('payment'))
    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)