# Milestone 1 - User Authentication System

## Project Title
Secure User Authentication with Streamlit, SQLite, and JWT

## Description
In this milestone, we developed a secure user authentication system using Streamlit for the frontend, SQLite for the database, and JWT (JSON Web Tokens) for session management. The application implements a complete authentication flow, including user registration with strict validation, secure login, a protected dashboard, and a multi-step password recovery system using security questions. The system is designed to be lightweight, secure, and easily deployable via Ngrok.

## Features Implemented
- **User Signup:** Registration form with strict validation for email format and password strength (requires 8+ characters, 1 uppercase, 1 number).
- **Secure Storage:** Passwords are hashed using SHA-256 before storage in a local SQLite database.
- **JWT Authentication:** Custom implementation of JSON Web Tokens to manage user sessions and auto-logout functionality.
- **Password History:** The system enforces a policy that prevents users from reusing their last 3 passwords.
- **Forgot Password Wizard:** A multi-step recovery process that verifies the email, challenges the user with their specific security question, and allows for a secure password reset.
- **Protected Dashboard:** A restricted area accessible only to users with a valid, non-expired session token.

## Steps to Run the Application

### 1. Install Dependencies
Open your terminal and install the required Python libraries:<br>
`pip install streamlit streamlit-antd-components pyjwt`

### 2. Run the Application
Navigate to the project directory and execute the Streamlit application:<br>
`streamlit run app.py`

### 3. Expose via Ngrok (Optional)
To make the application accessible remotely, open a new terminal and run:<br>
`ngrok http 8501`

## Screenshots

### Signup Page
![Signup Page Screenshot](screenshots/SignUp.png)


### Login Page
![Signup Page Screenshot](screenshots/LogIn.png)

### Dashboard
![Signup Page Screenshot](screenshots/Dashboard.png)

### Forgot Password Page
![Signup Page Screenshot](screenshots/ForgotPassword.png)
