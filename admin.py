# this file will only get executed when creating a new admin account!
import sqlite3
from werkzeug.security import generate_password_hash
import getpass

import secrets


# Generate a strong 32-character secret key
secret_key = secrets.token_urlsafe(32)
print(secret_key)

def create_admin_user(db_path='database.db'):
    # Prompt for admin credentials
    print("=== Admin Account Creation ===")
    username = input("Enter admin username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return

    # Use getpass to securely input the password without echoing
    password = getpass.getpass("Enter admin password: ")
    confirm_password = getpass.getpass("Confirm admin password: ")

    if password != confirm_password:
        print("Passwords do not match. Aborting.")
        return

    if not password:
        print("Password cannot be empty. Aborting.")
        return

    # Hash the password
    hashed_password = generate_password_hash(password)

    # Connect to the SQLite database
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if the username already exists
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            print(f"Error: Username '{username}' already exists.")
            return

        # Insert the new admin user
        cursor.execute("""
            INSERT INTO users (username, password, is_active, is_admin)
            VALUES (?, ?, ?, ?)
        """, (username, hashed_password, 1, 1))

        conn.commit()
        print(f"Success: Admin user '{username}' has been created.")

    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    create_admin_user()
