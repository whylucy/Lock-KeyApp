import sqlite3
from hashlib import sha256
import pyotp
from flask import Flask, request, jsonify
from cryptography.fernet import Fernet

# Generate a key for encryption (you should securely store this key)
def generate_key():
    """
    Generates a new encryption key.

    Returns:
        bytes: The generated encryption key.
    """
    return Fernet.generate_key()

# Create an instance of Fernet with the encryption key
key = generate_key()
cipher_suite = Fernet(key)

# Function to encrypt data
def encrypt_data(data):
    """
    Encrypts the provided data using Fernet encryption.

    Args:
        data (str): The plaintext data to be encrypted.

    Returns:
        bytes: The encrypted data.
    """
    return cipher_suite.encrypt(data.encode())

# Function to decrypt data
def decrypt_data(encrypted_data):
    """
    Decrypts the provided data using Fernet encryption.

    Args:
        encrypted_data (bytes): The encrypted data to be decrypted.

    Returns:
        str: The decrypted plaintext data.
    """
    return cipher_suite.decrypt(encrypted_data).decode()

# Function to register a new user
def register_user(username, password, email):
    """
    Registers a new user by inserting their details into the database.

    Args:
        username (str): The username of the new user.
        password (str): The plaintext password of the new user.
        email (str): The email address of the new user.

    Returns:
        dict: Status message indicating success or failure.
        int: HTTP status code.
    """
    with sqlite3.connect('E:/Mthree/LockAndKey/app.db') as conn:
        cursor = conn.cursor()

        # Check if the email already exists
        cursor.execute('SELECT * FROM Users WHERE email = ?', (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            return {'status': 'failure', 'message': 'Email already registered'}, 409  # 409 Conflict

        # If not, proceed with registration
        hashed_password = sha256(password.encode()).hexdigest()
        totp_secret = pyotp.random_base32()
        cursor.execute('''
            INSERT INTO Users (username, hashed_password, email, totp_secret)
            VALUES (?, ?, ?, ?)
        ''', (username, hashed_password, email, totp_secret))

        return {'status': 'success'}, 201  # 201 Created

# Function to verify user login
def verify_login(username, password, otp_code):
    """
    Verifies if the provided username, password, and TOTP code match a user in the database.

    Args:
        username (str): The username of the user attempting to log in.
        password (str): The plaintext password provided by the user.
        otp_code (str): The TOTP code provided by the user.

    Returns:
        bool: True if the username, password, and OTP code match a user, False otherwise.
    """
    with sqlite3.connect('E:/Mthree/LockAndKey/app.db') as conn:
        cursor = conn.cursor()

        # Hash the provided password
        hashed_password = sha256(password.encode()).hexdigest()

        # Check if the username and hashed password match any entry in the Users table
        cursor.execute('''
            SELECT totp_secret FROM Users WHERE username=? AND hashed_password=?
        ''', (username, hashed_password))

        user = cursor.fetchone()

        if user:
            totp_secret = user[0]
            totp = pyotp.TOTP(totp_secret)
            return totp.verify(otp_code)
        return False

# Basic Flask app to handle HTTP requests
app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    """
    API endpoint to check if the server is running.

    Returns:
        str: A simple welcome message.
    """
    return "Welcome to the Lock and Key API!", 200

# Route to handle user registration
@app.route('/register', methods=['POST'])
def register():
    """
    API endpoint to register a new user.

    Expects JSON data with 'username', 'password', and 'email'.
    """
    data = request.get_json()  # Get JSON data from the request
    if not data or not all(k in data for k in ('username', 'password', 'email')):
        return jsonify({'status': 'failure', 'message': 'Invalid input'}), 400

    # Call the register_user function
    response, status_code = register_user(data['username'], data['password'], data['email'])
    return jsonify(response), status_code

# Route to handle user login
@app.route('/login', methods=['POST'])
def login():
    """
    API endpoint to log in a user.

    Expects JSON data with 'username', 'password', and 'otp_code'.
    """
    data = request.get_json()  # Get JSON data from the request
    if not data or not all(k in data for k in ('username', 'password', 'otp_code')):
        return jsonify({'status': 'failure', 'message': 'Invalid input'}), 400

    success = verify_login(data['username'], data['password'], data['otp_code'])
    return jsonify({'status': 'success' if success else 'failure'})
import sqlite3
from hashlib import sha256
import pyotp
from flask import Flask, request, jsonify
from cryptography.fernet import Fernet

# Generate a key for encryption (you should securely store this key)
def generate_key():
    """
    Generates a new encryption key.

    Returns:
        bytes: The generated encryption key.
    """
    return Fernet.generate_key()

# Create an instance of Fernet with the encryption key
key = generate_key()
cipher_suite = Fernet(key)

# Function to encrypt data
def encrypt_data(data):
    """
    Encrypts the provided data using Fernet encryption.

    Args:
        data (str): The plaintext data to be encrypted.

    Returns:
        bytes: The encrypted data.
    """
    return cipher_suite.encrypt(data.encode())

# Function to decrypt data
def decrypt_data(encrypted_data):
    """
    Decrypts the provided data using Fernet encryption.

    Args:
        encrypted_data (bytes): The encrypted data to be decrypted.

    Returns:
        str: The decrypted plaintext data.
    """
    return cipher_suite.decrypt(encrypted_data).decode()

# Function to register a new user
def register_user(username, password, email):
    """
    Registers a new user by inserting their details into the database.

    Args:
        username (str): The username of the new user.
        password (str): The plaintext password of the new user.
        email (str): The email address of the new user.

    Returns:
        dict: Status message indicating success or failure.
        int: HTTP status code.
    """
    with sqlite3.connect('E:/Mthree/LockAndKey/app.db') as conn:
        cursor = conn.cursor()

        # Check if the email already exists
        cursor.execute('SELECT * FROM Users WHERE email = ?', (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            return {'status': 'failure', 'message': 'Email already registered'}, 409  # 409 Conflict

        # If not, proceed with registration
        hashed_password = sha256(password.encode()).hexdigest()
        totp_secret = pyotp.random_base32()
        cursor.execute('''
            INSERT INTO Users (username, hashed_password, email, totp_secret)
            VALUES (?, ?, ?, ?)
        ''', (username, hashed_password, email, totp_secret))

        return {'status': 'success'}, 201  # 201 Created

# Function to verify user login
def verify_login(username, password, otp_code):
    """
    Verifies if the provided username, password, and TOTP code match a user in the database.

    Args:
        username (str): The username of the user attempting to log in.
        password (str): The plaintext password provided by the user.
        otp_code (str): The TOTP code provided by the user.

    Returns:
        bool: True if the username, password, and OTP code match a user, False otherwise.
    """
    with sqlite3.connect('E:/Mthree/LockAndKey/app.db') as conn:
        cursor = conn.cursor()

        # Hash the provided password
        hashed_password = sha256(password.encode()).hexdigest()

        # Check if the username and hashed password match any entry in the Users table
        cursor.execute('''
            SELECT totp_secret FROM Users WHERE username=? AND hashed_password=?
        ''', (username, hashed_password))

        user = cursor.fetchone()

        if user:
            totp_secret = user[0]
            totp = pyotp.TOTP(totp_secret)
            return totp.verify(otp_code)
        return False

# Basic Flask app to handle HTTP requests
app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    """
    API endpoint to check if the server is running.

    Returns:
        str: A simple welcome message.
    """
    return "Welcome to the Lock and Key API!", 200

# Route to handle user registration
@app.route('/register', methods=['POST'])
def register():
    """
    API endpoint to register a new user.

    Expects JSON data with 'username', 'password', and 'email'.
    """
    data = request.get_json()  # Get JSON data from the request
    if not data or not all(k in data for k in ('username', 'password', 'email')):
        return jsonify({'status': 'failure', 'message': 'Invalid input'}), 400

    # Call the register_user function
    response, status_code = register_user(data['username'], data['password'], data['email'])
    return jsonify(response), status_code

# Route to handle user login
@app.route('/login', methods=['POST'])
def login():
    """
    API endpoint to log in a user.

    Expects JSON data with 'username', 'password', and 'otp_code'.
    """
    data = request.get_json()  # Get JSON data from the request
    if not data or not all(k in data for k in ('username', 'password', 'otp_code')):
        return jsonify({'status': 'failure', 'message': 'Invalid input'}), 400

    success = verify_login(data['username'], data['password'], data['otp_code'])
    return jsonify({'status': 'success' if success else 'failure'})

if __name__ == '__main__':
    app.run(debug=True)

if __name__ == '__main__':
    app.run(debug=True)
