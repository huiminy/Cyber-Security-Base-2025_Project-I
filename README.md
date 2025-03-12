# Cyber Security Base 2025 - Project I

LINK: _https://github.com/huiminy/Cyber-Security-Base-2025_Project-I.git_

## **Basic Information**
- This project refers to the OWASP Top 10 - **2021** list
  - Flaw 1 and flaw 4 are the same flaw (A03:2021-Injection), but I thought it would be good to put both since it's pretty important I believe
  - Flaws addressed:
    - A03:2021-Injection
    - A01:2021-Broken Access Control
    - A05:2021-Security Misconfiguration
    - A07:2021-Identification and Authentication Failures
    - A02:2021-Cryptographic Failures
- Screenshots are all in `/screenshots` (https://github.com/huiminy/Cyber-Security-Base-2025_Project-I/tree/main/screenshots)
   
- Two (2) sample products and their reviews have been added to the database already - but if more reviews/products are needed, please follow the instructions in step number seven (7)
  
- User accounts created for testing:
  - **Superuser** (admin account that can also access the `/admin/` side of the server):
    - Username: jane
    - Password: janeloveshopping
      
  - **Normal user** (more normal users can be created for testing via the `/register/` side of the server - **DO NOT LOG INTO SUPERUSER ACCOUNT WHILE DOING THIS**):
    - Username: harry
    - Password: harry
    - Maiden name: evans

## **Instructions to set up:** 
_Ensure that you have python installed in your device before continuing_

1. Git clone:
    - `git clone https://github.com/huiminy/Cyber-Security-Base-2025_Project-I.git`
      
2. Accesing file & activating virtual environment
    - `cd mysite`
    - `python -m venv venv`
    - `venv\Scripts\activate`
      
3. Install dependencies:
    - `pip install django `
    
4. Initialise database:
    - `python manage.py makemigrations store`
    - `python manage.py migrate`
    
5. Create a superuser:
    - `python manage.py createsuperuser`
    
6. Run the server:
    - `python manage.py runserver`

7. Using the server:
   
    **Access the server link that is shown when you run step number 6 (`python manage.py runserver`) to see the website created**

    - To add more **reviews**: Click on the `View Details` button under the product's name on the home page, then add your review
    - To add more **products**: Add `/admin/` to the end of the server link below, navigate to `Store/Products`, then add your sample data

 
## **FLAW 1: A03:2021-Injection**
_https://github.com/huiminy/Cyber-Security-Base-2025_Project-I/blob/main/mysite/store/views.py#L426_

### **Description:**
The application contains an SQL injection vulnerability in the `search_reviews` function. The function takes user input and directly incorporates it into a raw SQL query without any sanitisation. This vulnerability allows an attacker to manipulate the SQL query by injecting malicious code. For example, if an attacker inputs something like `' OR '1'='1`, this would return all reviews in the database - hence bypassing the intended filtering. 

### **Solution:**
_https://github.com/huiminy/Cyber-Security-Base-2025_Project-I/blob/main/mysite/store/views.py#L446_

The fix involves using parameterised queries or an ORM (Object-Relational Mapping) instead of direct string concatenation. Django's ORM already provides a secure way to perform queries with user input. By using Django's ORM method filter(comment__icontains=query), the query parameter is automatically sanitised and properly escaped before being used in the SQL query, thus preventing SQL injection attacks.


## **FLAW 2: A01:2021-Broken Access Control**
_https://github.com/huiminy/Cyber-Security-Base-2025_Project-I/blob/main/mysite/store/views.py#L330_

### **Description:**
The application has a broken access control vulnerability in the `api_product_info` function. While the `admin_panel` view correctly checks if a user is a superuser before granting access, the API endpoint for product information has no authentication or authorization checks. This means that any user - whether they are authenticated or not, can access product data through the API. If there are products that should be accessible only to certain users (like superusers), this endpoint would expose that data to everyone.

### **Solution:**
_https://github.com/huiminy/Cyber-Security-Base-2025_Project-I/blob/main/mysite/store/views.py#L345_

The fix involves adding proper authentication and authorisation checks to the API endpoint. By adding the @login_required decorator, I have ensured that only authenticated users can access the endpoint. Additionally, I've added a check to verify that the user has appropriate permissions to view the product.


## **FLAW 3: A05:2021-Security Misconfiguration**
_https://github.com/huiminy/Cyber-Security-Base-2025_Project-I/blob/main/mysite/mysite/settings.py#L23_

### **Description:**
The application has several security misconfigurations in its Django settings:
- Debug mode is enabled in production
- Secret key is hardcoded in the settings file
- ALLOWED_HOSTS is set to accept all hosts (`['*']`)
- Password validation is disabled
- CSRF protection is disabled
- Clickjacking protection is disabled

These misconfigurations expose the application to various security risks:
- Debug mode reveals sensitive information in error pages
- A hardcoded secret key can be discovered through code access
- Allowing all hosts enables host header attacks
- Weak password policies allow easily-guessable passwords
- Disabled CSRF protection enables cross-site request forgery
- Disabled clickjacking protection allows the application to be embedded in malicious frames

### **Solution:**
_https://github.com/huiminy/Cyber-Security-Base-2025_Project-I/blob/main/mysite/mysite/settings.py#L130_

The fix involves properly configuring Django's security settings, which ensure that:
- The secret key is stored in environment variables
- Debug mode is disabled in production
- Only specific hosts are allowed
- Password policies are enforced
- CSRF protection is enabled
- Clickjacking protection is enabled
- Additional security headers are set


## **FLAW 4: A03:2021-Injection**
_https://github.com/huiminy/Cyber-Security-Base-2025_Project-I/blob/main/mysite/store/views.py#L365_

### **Description:**
The application contains a command injection vulnerability in the `admin_command` function. While it does check if the user is a superuser, it directly executes any command provided by the user without sanitisation. The use of `shell=True` is quite dangerous as it allows command chaining through shell operators like `;`, `&&`, or `|`. An attacker with the superuser access could execute arbitrary commands on the server, potentially leading to full system compromise.

### **Solution:**
_https://github.com/huiminy/Cyber-Security-Base-2025_Project-I/blob/main/mysite/store/views.py#L378_

The fix involves using a whitelist of allowed commands rather than executing arbitrary user input. This approach offers several security improvements:
- Only pre-defined commands are allowed
- `shell=False` prevents command chaining
- Using `.split()` on the command string avoids shell interpretation
- The UI can be updated to offer only allowed commands via a dropdown menu


## **FLAW 5: A07:2021-Identification and Authentication Failures**
_https://github.com/huiminy/Cyber-Security-Base-2025_Project-I/blob/main/mysite/store/views.py#L148_

### **Description:**
The application has multiple identification and authentication weaknesses:
- CSRF protection is disabled on login and registration pages
- No rate limiting for login attempts
- No email verification for new accounts
- No password complexity requirements (in settings.py)
- Generic error messages to protect against username enumeration has been implemented.
- No logging of login activities
- No secure handling of session cookies

These issues make it easier for attackers to brute-force passwords, enumerate valid usernames, perform CSRF attacks, and hijack sessions.

### **Solution:**
_https://github.com/huiminy/Cyber-Security-Base-2025_Project-I/blob/main/mysite/store/views.py#L194_

The fix involves implementing several security measures:
- CSRF protection (by removing the @csrf_exempt decorator)
- Basic rate limiting is implemented through failed_attempts in session and is_suspicious_login to redirect to verification
- Generic error messages to prevent username enumeration
- Additional checks for suspicious login attempts


## **FLAW 6: A02:2021-Cryptographic Failures**
_https://github.com/huiminy/Cyber-Security-Base-2025_Project-I/blob/main/mysite/store/views.py#L48_
_https://github.com/huiminy/Cyber-Security-Base-2025_Project-I/blob/main/mysite/store/models.py#L33_

### **Description:**
The application exhibits a cryptographic failure related to the handling of security answers during password resets. While user passwords themselves are stored using a proper hashing algorithm, the security answers used for password recovery were initially stored in plaintext within the `UserProfile` model. As demonstrated by the "flaw-6-before-1.png" screenshot, the `/debug-security/` endpoint exposed these plaintext security answers, allowing anyone with administrative privileges or direct database access to view this sensitive information. Additionally, the vulnerable `reset_password` function directly updated the database with a new password _without_ hashing it - which would be set to an empty string or any value without hashing.

### **Solution:**
_https://github.com/huiminy/Cyber-Security-Base-2025_Project-I/blob/main/mysite/store/views.py#L71_
_https://github.com/huiminy/Cyber-Security-Base-2025_Project-I/blob/main/mysite/store/models.py#L35_

The implemented fix addresses these vulnerabilities through the following measures:

-   Secure Storage of Security Answers: The application now stores the _hash_ of the security answer rather than the plaintext value. The `security_answer_hash` field in the `UserProfile` model stores the result of hashing the security answer using Django's `make_password()` function during user registration. The original plaintext `security_answer` field is then cleared to prevent its storage.
-   Password Handling with `set_password()`: The `reset_password` function now utilizes Django's built-in `set_password()` method to securely set new passwords - ensuring that they are properly hashed before being stored in the database.
-   Mitigation of Timing Attacks: To increase security of the reset code, this code has included protection against timing attacks with random delays
-   Username Enumeration Protection: Adds consistent error messages to protect against username enumeration.

The effectiveness of these solutions is confirmed by inspecting the `/debug-security/` endpoint _after_ the fixes are applied. 
