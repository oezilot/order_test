from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'secret_key'  # For session management

# Database setup, sodass tabelle entsteht und informationnnach restart nicht verloren geht. wenn man nachträglich eine kolonne oder so einfügt wird diese einfach dazugefügt (in diesem fall werden aber die daten glaubs gelöscht!)
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Drop the old tables (be careful with this step if you have important data)
    # c.execute('DROP TABLE IF EXISTS users')
    # c.execute('DROP TABLE IF EXISTS posts')

    # Create users table with 'is_active' column for soft deletion
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT,
                    is_active BOOLEAN DEFAULT 1)''')  # Default is_active = 1 (active)

    # Create posts table with 'is_active' column for soft deletion
    c.execute('''CREATE TABLE IF NOT EXISTS posts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    content TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    FOREIGN KEY(user_id) REFERENCES users(id))''')

    conn.commit()
    conn.close()

# Call the function to initialize the database
init_db()


# Helper function to get DB connection
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# landing.html
@app.route('/')
def landing():
    # If the user is logged in, redirect them to the main index page
    if 'user_id' in session:
        return redirect(url_for('index'))        
    
    # If the user is not logged in, show the landing page
    return render_template('landing.html')

# about.html
@app.route('/about')
def about():
    return render_template('about.html')



# das ist die haupt-page auf der die posts als zusammenfassung alle engezeigt werden
@app.route('/buchseiten/inhaltsverzeichnis')
def index():
    conn = get_db_connection()

    if 'user_id' not in session:
        # No user logged in, set has_post and user_post to None or False
        user_post = None
        has_post = False
    else:
        # Check if the logged-in user has a post
        user_post = conn.execute('SELECT * FROM posts WHERE user_id = ? AND is_active = 1', (session['user_id'],)).fetchone()
        has_post = user_post is not None

    # Query to get all active users and their active posts
    users = conn.execute('SELECT username FROM users WHERE is_active = 1 ORDER BY username ASC').fetchall()

    # Query each user's active posts
    user_posts = []
    for user in users:
        post = conn.execute('SELECT content, created_at FROM posts WHERE user_id = (SELECT id FROM users WHERE username = ? AND is_active = 1) AND is_active = 1', (user['username'],)).fetchone()

        # If the user has an active post, include it
        if post:
            user_posts.append({
                'username': user['username'],
                'content': post['content'],
                'created_at': post['created_at']
            })

    conn.close()

    # everything in the brackets is passed to the html-file which is getting rendered!
    return render_template('index.html', user_posts=user_posts, has_post=has_post)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error_message = None  # Initialize the error message

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        # Check if the user exists and is active
        user = conn.execute('SELECT * FROM users WHERE username = ? AND is_active = 1', (username,)).fetchone()
        conn.close()

        if user:
            # Check if the password is correct
            if check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                return redirect(url_for('index'))
            else:
                error_message = "Invalid credentials."
        else:
            # If the user is inactive or doesn't exist
            error_message = "Account is inactive or doesn't exist."

    return render_template('login.html', error_message=error_message)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error_message = None  # Initialize a variable to store the error message

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()

        # Check if the username already exists
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user:
            # Set an error message if the username already exists
            error_message = "Username already exists. Please choose a different one."
        else:
            # If the username is unique, proceed with registration
            password_hash = generate_password_hash(password)

            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password_hash))
            conn.commit()
            conn.close()

            # Redirect to the login page after successful registration
            return redirect(url_for('login'))

        conn.close()

    # Pass the error_message to the template (if any)
    return render_template('register.html', error_message=error_message)


# das template wo man einen post creiiert
@app.route('/post', methods=['GET', 'POST'])
def post():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user_post = conn.execute('SELECT * FROM posts WHERE user_id = ?', (session['user_id'],)).fetchone()
    
    if request.method == 'POST':
        # Handle post creation or editing
        if 'content' in request.form and not 'abbrechen' in request.form:
            content = request.form['content']
            if user_post:
                # Edit existing post
                conn.execute('UPDATE posts SET content = ? WHERE user_id = ?', (content, session['user_id']))
            else:
                # Create new post
                conn.execute('INSERT INTO posts (user_id, content) VALUES (?, ?)', (session['user_id'], content))
            conn.commit()
            conn.close()
            return redirect(url_for('index'))

        # Handle the "Abbrechen" button to delete the post
        elif 'abbrechen' in request.form:
            if user_post:
                conn.execute('DELETE FROM posts WHERE user_id = ?', (session['user_id'],))
                conn.commit()
            conn.close()
            return redirect(url_for('index'))

    conn.close()

    # Render the appropriate template based on whether the user has a post
    if user_post:
        return render_template('edit_post.html', post=user_post)
    else:
        return render_template('post.html')

# das template wo man einen post bearbeitet wenn man bereits einen hat
@app.route('/edit_post', methods=['GET', 'POST'])
def edit_post():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    post = conn.execute('SELECT * FROM posts WHERE user_id = ?', (session['user_id'],)).fetchone()

    # Calculate whether the user has a post (used for the "Edit Post"/"Create Post" button)
    has_post = post is not None

    if request.method == 'POST':
        if 'update' in request.form:
            # Update the post content
            content = request.form['content']
            conn.execute('UPDATE posts SET content = ? WHERE user_id = ?', (content, session['user_id']))
            conn.commit()
            conn.close()
            return redirect(url_for('index'))

        elif 'delete' in request.form:
            # Delete the post
            conn.execute('DELETE FROM posts WHERE user_id = ?', (session['user_id'],))
            conn.commit()
            conn.close()
            return redirect(url_for('index'))

    conn.close()
    
    # Pass `has_post` along with the post to the template
    return render_template('edit_post.html', post=post, has_post=has_post)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('landing'))


# einzelne posts zum durchklicken
# NEW FUNCTION: Display a single post with forward/backward navigation
@app.route('/buchseiten/<username>', methods=['GET'])
def show_post(username):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    # Get user by username
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    
    if not user:
        return "User not found", 404

    # Get the user's post
    post = conn.execute('SELECT * FROM posts WHERE user_id = ?', (user['id'],)).fetchone()


    # Get all usernames to determine navigation
    users = conn.execute('SELECT username FROM users ORDER BY username').fetchall()
    conn.close()

    # Find the current index of the username
    usernames = [u['username'] for u in users]
    current_index = usernames.index(username)

    # Calculate previous and next usernames for navigation
    next_username = usernames[current_index + 1] if current_index < len(usernames) - 1 else None
    prev_username = usernames[current_index - 1] if current_index > 0 else None

    return render_template('userpage.html', post=post, username=username, prev_username=prev_username, next_username=next_username)



# ensures that the has_post-variable is used globally and for all the templates and views
@app.context_processor
def inject_has_post():
    if 'user_id' in session:
        conn = get_db_connection()
        user_post = conn.execute('SELECT * FROM posts WHERE user_id = ?', (session['user_id'],)).fetchone()
        conn.close()
        # if there is something in the users table that means that the corresponding user already has a post
        has_post = user_post is not None
    else:
        has_post = False

    return dict(has_post=has_post)



@app.route('/delete_account', methods=['POST', 'GET'])
def delete_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    conn = get_db_connection()

    # Step 1: Soft delete the user's posts by setting is_active to 0
    conn.execute('UPDATE posts SET is_active = 0 WHERE user_id = ?', (session['user_id'],))

    # Step 2: Soft delete the user's account by setting is_active to 0
    conn.execute('UPDATE users SET is_active = 0 WHERE id = ?', (session['user_id'],))

    conn.commit()
    conn.close()

    # Step 3: Clear the session since the user is "deleted"
    session.clear()

    # Step 4: Redirect to the landing page after deletion
    return redirect(url_for('landing'))


@app.route('/reactivate_account', methods=['POST', 'GET'])
def reactivate_account():
    error_message = None  # Initialize the error message

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()

        # Check if the user exists in the users table but is inactive
        inactive_user = conn.execute('SELECT * FROM users WHERE username = ? AND is_active = 0', (username,)).fetchone()

        if inactive_user and check_password_hash(inactive_user['password'], password):
            # Reactivate the user by setting is_active to 1
            conn.execute('UPDATE users SET is_active = 1 WHERE username = ?', (username,))

            # Reactivate all their posts by setting is_active to 1
            conn.execute('UPDATE posts SET is_active = 1 WHERE user_id = ?', (inactive_user['id'],))

            conn.commit()
            conn.close()

            # Log the user in by creating a session
            session['user_id'] = inactive_user['id']
            session['username'] = inactive_user['username']

            return redirect(url_for('index'))
        else:
            # Account not found or invalid credentials
            error_message = "Account not found or invalid credentials"
            conn.close()

    # Render the template with or without the error message
    return render_template('reactivate.html', error_message=error_message)


    

if __name__ == '__main__':
    app.run(debug=True)
