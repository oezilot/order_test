from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'secret_key'  # For session management

# Database setup, sodass tabelle entsteht und informationnnach restart nicht verloren geht. wenn man nachträglich eine kolonne oder so einfügt wird diese einfach dazugefügt (in diesem fall werden aber die daten glaubs gelöscht!)
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Create users table if it doesn't exist
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT)''')

    # Create posts table if it doesn't exist
    c.execute('''CREATE TABLE IF NOT EXISTS posts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    content TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id))''')

    # Try to add the 'created_at' column if it doesn't exist
    try:
        c.execute('ALTER TABLE posts ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
    except sqlite3.OperationalError:
        # This error occurs if the column already exists, so we ignore it
        pass

    conn.commit()
    conn.close()


init_db()

# Helper function to get DB connection
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/buchseiten/inhaltsverzeichnis')
def index():
    if 'user_id' in session:
        conn = get_db_connection()
        
        # Query all posts to display on the home page
        posts = conn.execute('''SELECT 
            posts.content, posts.created_at, users.username 
            FROM posts 
            JOIN users ON posts.user_id = users.id 
            ORDER BY users.username ASC
            ''').fetchall()

        # Check if the logged-in user has a post
        user_post = conn.execute('SELECT * FROM posts WHERE user_id = ?', (session['user_id'],)).fetchone()
        conn.close()

        # Pass 'posts' and 'has_post' to the template
        return render_template('index.html', posts=posts, has_post=(user_post is not None))

    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('index'))
        else:
            return "Invalid credentials"
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return "Username already exists"
        
        conn.close()
        return redirect(url_for('login'))

    return render_template('register.html')

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
    return redirect(url_for('login'))




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

    if not post:
        return "No post for this user", 404

    # Get all usernames to determine navigation
    users = conn.execute('SELECT username FROM users ORDER BY username').fetchall()
    conn.close()

    # Find the current index of the username
    usernames = [u['username'] for u in users]
    current_index = usernames.index(username)

    # Calculate previous and next usernames for navigation
    next_username = usernames[current_index + 1] if current_index < len(usernames) - 1 else None
    prev_username = usernames[current_index - 1] if current_index > 0 else None

    return render_template('index.html', post=post, username=username, prev_username=prev_username, next_username=next_username)






if __name__ == '__main__':
    app.run(debug=True)
