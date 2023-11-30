Auth_Api_Django

This Django REST API project provides endpoints for user authentication, registration, login, and password reset via email.

- User registration with email confirmation
- User login and authentication
- Password reset functionality via email
- RESTful API endpoints for handling user-related actions


1. Clone the repository: 
   ```bash
   git clone https://github.com/theprerakshah/Auth_Api_Django.git
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure settings:
   - Update `settings.py` with necessary configurations (e.g., database settings, email settings).

4. Apply migrations:
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

## Usage

1. Run the development server:
   ```bash
   python manage.py runserver
   ```

2. Access the API endpoints:
   - Registration: `/api/user/register/`
   - Login: `/api/user/login/`
   - Profile View: `/api/user/profile/`
   - Change Password: `/api/user/change-password/`
   - Password Reset Mail: `api/user/reset-password-email/`
   - Password Reset: `/api/user/reset-password/Userid/PasswordResetToken/`

## Configuration

In Addition to the basic configuration  you need to add **.env** file which contains the your emailId and password using which you want to send mail on PasswordResetMail functionality.

