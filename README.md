# **README for CSC2031 Assignment:From Exercise 7 to Exercise 23**

## **Author**
- **Name**: Saud Al-Najem
- **Student ID**: 230266960

## **Exercise 7: Authenticating User Identities**
- I implemented login functionality using `LoginForm` with fields for email, password, and submit.
- To enhance security, I created a `verify_password()` method in the `User` model for validating credentials.
- Users are redirected based on authentication results with clear flash messages, ensuring a smooth user experience.

## **Exercise 8: Enforcing Strong Passwords**
- I enforced robust password validation during registration, adhering to the rules of 8-15 characters, with at least one uppercase, one lowercase, one digit, and one special character.

## **Exercise 9: Validating Human Presence**
- To prevent automated attacks, I integrated Google reCAPTCHA into the login form and configured reCAPTCHA keys in `config.py`.

## **Exercise 10: Limiting Authentication Attempts**
- I implemented a mechanism to lock accounts after 3 invalid login attempts.
- A rate limiter was applied to restrict login attempts to 20 per minute.
- I created a custom error page to handle rate limit breaches effectively.

## **Exercise 11: Multi-Factor Authentication (MFA)**
- I introduced MFA during registration, allowing users to set up manual code entry.
- MFA verification was added to the login process, with users redirected to an MFA setup page if required.

## **Exercise 12: Managing User Logins**
- Using Flask-Login, I implemented login and logout functionality.
- Users’ posts are now associated with their accounts and displayed on the **View Posts** page.
- The **Account** page shows logged-in user details and their created posts.

## **Exercise 13: User Access Management**
- I enforced strict access rules:
  - Anonymous users are blocked from account-related and post creation/update pages.
  - Authenticated users cannot access registration or login pages or modify others' posts.

### **Note**
- When pressing **Login** or **Registration** while logged in, the user is redirected based on their role instead of being redirected to **View Posts** as required. This decision avoids access issues since `sec_admin` and `db_admin` roles should not access **View Posts**.

## **Exercise 14: Role-Based Access Control**
- I added roles (`end_user`, `db_admin`, `sec_admin`) to the `User` model.
- Each role has specific permissions, such as:
  - `end_user`: Limited to posts.
  - `db_admin`: Access to database tables.
  - `sec_admin`: Access to the security page.
- **Approach**: I embedded role-checking logic directly into view functions instead of using a `@roles_required` decorator. This ensured:
  - Adherence to the exercise requirements by extending existing code.
  - Simplicity for debugging and step-by-step verification.
  - Flexibility for future scalability and refactoring.

## **Exercise 15: Event Logging**
- I implemented database logs to record user registration and login events.
- A `security.log` file captures user actions like post creation, updates, and unauthorized access attempts.
- The **Security** page displays relevant log entries.

## **Exercise 16: Password Hashing**
- I securely hashed passwords using bcrypt during registration and verified them during login.

## **Exercise 17: Symmetric Encryption**
- Post titles and bodies are encrypted using user-specific keys.
- I enabled decryption for viewing and updating posts while maintaining data security.

## **Exercise 18: Input Validation**
- I enforced strict validation for:
  - Proper email formats.
  - Names containing only letters or hyphens.
  - Valid UK landline phone numbers with specific formats.

## **Exercise 19: Hardcoded Data**
- All configuration settings were moved to a `.env` file, including secret key generation.

## **Exercise 20: Handling Errors**
- I added user-friendly error pages for:
  - Bad request (400).
  - Not found (404).
  - Internal server error (500).
  - Not implemented (501).

## **Exercise 21: Firewall Rules**
- To enhance security, I implemented rules to block:
  - SQL injection (`union`, `select`, etc.).
  - XSS (`<script>`, `<iframe>`).
  - Path traversal (`../`).
- Users attempting such actions are redirected to a custom firewall error page.

## **Exercise 22: Data Transmission**
- I enabled secure HTTPS using a self-signed certificate.
- Updated all links and redirects to ensure secure communication.

## **Exercise 23: Security Headers**
- Using Flask-Talisman, I added HTTP security headers to enhance security.
- I switched to Bootstrap 5.2.2 to ensure compatibility with CSP while maintaining styling.

### **Note**
- Duplicate flash messages may appear because I added a flash message handler in `base.html`. This was necessary as some flash messages written in the `.py` files using Flask's `flash()` method were not appearing in the templates. Despite trying multiple approaches, this was the most reliable solution to ensure all messages are displayed.
