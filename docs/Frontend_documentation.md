## Frontend Documentation for FitPath

# Introduction
The FitPath Frontend is designed to provide users and trainers with a seamless and responsive interface to manage fitness, health, and wellness goals. Built using a Bootstrap template, the frontend has been customized to meet the project's specific requirements. It integrates with the backend for dynamic content and provides an intuitive user experience.

# Third-Party Libraries:

- Bootstrap: Used for responsive design and prebuilt components.
- D3.js: Used for dynamic visualizations.

# Pages and Components

1. Home Page (Landing Page)
Purpose: Serve as the entry point for users and introduce them to the platform.
- Features:
Welcoming headline (e.g., "Track Your Fitness Goals and Achieve Your Best Self!").
Navigation bar for navigating to sections like About and Support Request.
Login/Register Buttons: Redirect users to the Login or Registration pages.

2. Registration Page
Purpose: Allow new users to sign up.
- Features:
Form Fields: Name, email, password, phone number, and password confirmation.
Validation: Ensures all inputs meet requirements (e.g., valid email format, password strength).
Next Button: Redirects users to the Payment Page.
After payment, a Login Button redirects users to the Login Page.

3. Payment Page
- Purpose: Enable users to complete payment to activate their accounts.
- Features:
Payment Form: Secure fields for payment information.
Confirmation Message: Displays success upon transaction completion.
Redirection Button: Navigates users to the Login Page after successful payment.

4. Login Page
- Purpose: Authenticate users.
- Features:
Email and Password Fields: For user credentials.
Login Button: Redirects authenticated users to the Dashboard Page.
Registration Link: Redirects new users to the Registration Page.

5. Dashboard Page
- Purpose: Provide an overview of user progress and activities.
- Features:
Displays summaries of fitness goals, workouts, and nutrition progress.
Quick Links: Navigate to meal logs, health metrics updates, and goal management pages.
Visualization: Progress graphs/charts created with D3.js.

6. Trainer Login Page (Trainer Role)
- Purpose: Authenticate trainers.
- Features:
Email and Password Fields: For trainer credentials.
Login Button: Redirects trainers to the Trainer Dashboard Page.

7. Trainer Dashboard Page (Trainer Role)
- Purpose: Allow trainers to manage their assigned users.
- Features:
Assigned Users List: View all assigned users.
User Management: Assign workout and nutrition plans.
Progress Monitoring: View and track user progress and goals.

8. Support Page
- Purpose: Enable users to submit and track support requests.
- Features:
Support Form: Fields for request description and type.
Request Status: Displays submitted requests and their current status (e.g., submitted, resolved).
Contact Information/FAQ: Additional support resources.

9. About Page
- Purpose: Provide information about the platform.
- Features:
Mission and vision of the platform.
Team members or contributors.
Links to social media or other external resources.

# API Integration

The frontend interacts with the backend using a set of RESTful APIs to provide dynamic functionality and ensure a seamless user experience.