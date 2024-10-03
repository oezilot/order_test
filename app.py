from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3


# for the png submission
import os
from werkzeug.utils import secure_filename

import secrets
from flask_mail import Message



app = Flask(__name__)
app.secret_key = 'secret_key' # For session management (damit man sich einloggen kann braucht es einen secret key!)



# Define the folder where uploaded images will be stored
UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'png'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Database setup, sodass tabelle entsteht und informationnnach restart nicht verloren geht. wenn man nachträglich eine kolonne oder so einfügt wird diese einfach dazugefügt (in diesem fall werden aber die daten glaubs gelöscht!)
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Drop the old tables (be careful with this step if you have important data)
    #c.execute('DROP TABLE IF EXISTS users')
    #c.execute('DROP TABLE IF EXISTS posts')

    # Create users table with 'is_active' column for soft deletion
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE,
                    reset_token TEXT,
                    username TEXT UNIQUE,
                    password TEXT,
                    time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active INTEGER DEFAULT -1,
                    is_admin BOOLEAN DEFAULT 0)''')  # Default is_active = 1 (active)


    # Create posts table with 'is_active' column for soft deletion
    c.execute('''CREATE TABLE IF NOT EXISTS posts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    content TEXT,
                    birthday TEXT, 
                    color TEXT, 
                    food TEXT, 
                    greenFlags TEXT, 
                    redFlags TEXT,
                    pinterest TEXT,
                    Name TEXT,
                    Personnality TEXT, 
                    Zoe TEXT, 
                    Interest TEXT, 
                    Desinterest TEXT, 
                    Lernen TEXT, 
                    Idol TEXT, 
                    Serie TEXT, 
                    Musik TEXT, 
                    Fashion TEXT, 
                    Zukunft TEXT, 
                    Love TEXT, 
                    Date TEXT, 
                    Pleasure TEXT,
                    Regret TEXT, 
                    Party_Movie TEXT,
                    Ski_Snowboard TEXT,
                    Wg_Alleine TEXT,
                    Hund_Katze TEXT,
                    Regen_Sonne TEXT,
                    Spotify TEXT,
                    image_path TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    FOREIGN KEY(user_id) REFERENCES users(id))''')


    conn.commit()
    conn.close()

# Call the function to initialize the database
init_db()

#admin-account: only the admin can access this page (admin is the user with id=1)
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    # Check if the user is logged in and is an admin
    if 'user_id' in session:
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        
        active_users = conn.execute('SELECT * FROM users WHERE is_active = 1 AND is_admin = 0').fetchall()
        inactive_users = conn.execute('SELECT * FROM users WHERE is_active = 0 AND is_admin = 0').fetchall()
        waiting_users = conn.execute('SELECT * FROM users WHERE is_active = -1 AND is_admin = 0').fetchall() # only use fetchone or fetchall when returning something!
        admin_accounts = conn.execute('SELECT * FROM users WHERE is_admin = 1').fetchall()

          # Handle the form submission for approving or denying users
        if request.method == 'POST':
            user_id = request.form['user_id']  # Get the user_id from the form
            action = request.form['action']  # Get the action (approve/deny) from the button clicked

            if action == 'activate':
                conn.execute('UPDATE users SET is_active = 1 WHERE id = ?', (user_id,))
            if action == 'deactivate':
                conn.execute('UPDATE users SET is_active = 0 WHERE id = ?', (user_id,))
            if action == 'delete':
                conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
            if action == 'promote':
                conn.execute('UPDATE users SET is_admin = 1 WHERE id = ?', (user_id,))
            if action == 'depromote':
                conn.execute('UPDATE users SET is_admin = 0 WHERE id = ?', (user_id,))


        

            conn.commit()  # Save the changes to the database
            return redirect(url_for('admin'))  # Refresh the admin page after changes
        
        conn.close()

        # If the user is an admin, render the admin page
        # is_admin is a boolean therefore when it is true this case gets runned (if user['is_admin] is the same as if the user has a true in the column admin)
        if user and user['is_admin']:
            return render_template('admin.html', inactive_users=inactive_users, active_users=active_users, waiting_users=waiting_users, admin_accounts=admin_accounts)
        else:
            # If the user is not an admin, show an unauthorized message
            return "Unauthorized access", 403
    else:
        return redirect(url_for('login'))


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
        user_post = None # variable which tells if the user logged in or not (this variable holds the information of the logged in user)
        has_post = False # variable which tells if the user has a post or not
    else:
        # Check if the logged-in user has a post
        user_post = conn.execute('SELECT * FROM posts WHERE user_id = ? AND is_active = 1', (session['user_id'],)).fetchone()
        has_post = user_post is not None

    # Query to get all active users
    users = conn.execute('SELECT username FROM users WHERE is_active = 1 ORDER BY username ASC').fetchall()

    # Create a list with all users and their posts (if they have one)
    user_posts = []
    for user in users:
        # Try to find the user's post
        post = conn.execute('SELECT content, created_at FROM posts WHERE user_id = (SELECT id FROM users WHERE username = ?) AND is_active = 1', (user['username'],)).fetchone()

        # Always add the user, even if they don't have a post
        user_posts.append({
            'username': user['username'],
            'content': post['content'] if post else None,  # Add content if a post exists, otherwise None
            'created_at': post['created_at'] if post else None  # Add created_at if a post exists, otherwise None
        })

    conn.close()

    # everything in the brackets is passed to the html-file which is getting rendered!
    return render_template('index.html', user_posts=user_posts, has_post=has_post)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error_message = None  # Initialize the error message

    if request.method == 'POST':
        username_or_email = request.form['username_or_email']  # Can be either username or email
        password = request.form['password']
        
        conn = get_db_connection()
        # Check if the user exists and is active
        user = conn.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username_or_email, username_or_email)).fetchone()
        conn.close()

        if user:
            # Check if the password is correct
            if check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = bool(user['is_admin'])  # Convert is_admin to a boolean
                
                if user['is_active'] == -1:
                    return redirect(url_for('waiting'))
                elif user['is_active'] == 1:
                    # is_admin, id and username are the names of the database columns from users
                    return redirect(url_for('index'))
                else:
                    error_message = "Invalid credentials."
        else:
            # If the user is inactive or doesn't exist
            error_message = "Account is inactive or doesn't exist."

    return render_template('login.html', error_message=error_message)

'''
@app.route('/reset', methods=['GET', 'POST'])
def reset():
    error_message = None
    if request.method == 'POST':
        email = request.form['email']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if user:
            # Generate a password reset token (using itsdangerous or any other method)
            token = s.dumps(user['email'], salt='password-reset-salt')
            
            # Send the reset link to the user's email (using your email sending logic)
            reset_url = url_for('reset_password', token=token, _external=True)
            send_reset_email(user['email'], reset_url)
            flash('A password reset link has been sent to your email.')
        else:
            error_message = "Email address not found."

        conn.close()

    return render_template('forgot_password.html', error_message=error_message)
'''

@app.route('/waiting')
def waiting():
    return render_template('waiting.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    error_message = None  # Initialize a variable to store the error message

    if request.method == 'POST':
        email = request.form['email']
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

            conn.execute('INSERT INTO users (email, username, password) VALUES (?, ?, ?)', (email, username, password_hash))
            conn.commit()
            conn.close()

            # Redirect to the login page after successful registration
            return redirect(url_for('login'))

        conn.close()

    # Pass the error_message to the template (if any)
    return render_template('register.html', error_message=error_message)


# CREATE A POST
@app.route('/post', methods=['GET', 'POST'])
def post():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    # in dieser variable werden alle daten des posts der eingeloggten person gespeichert!
    user_post = conn.execute('SELECT * FROM posts WHERE user_id = ?', (session['user_id'],)).fetchone()
    
    if request.method == 'POST':
        # Handle the "Abbrechen" button first
        if 'abbrechen' in request.form:
            if user_post:
                conn.execute('DELETE FROM posts WHERE user_id = ?', (session['user_id'],))
                conn.commit()
            conn.close()
            return redirect(url_for('index'))

        # save the input-information submitted into the form in a variable: 'content' is the name of the textfield of the form
        # es existiert eine variable für jedes inputfeld des forms (ausser für das image nicht!)
        content = request.form['content']
        bday = request.form['bday'] 
        color = request.form['favcolor']
        food = request.form['Food']
        redFlag = request.form['rFlag']
        greenFlag = request.form['gFlag']
        pinterest = request.form['Pinterest']
        name = request.form['name']
        personnality = request.form['personnality']
        zoe = request.form['zoe']
        interest = request.form['interest']
        desinterest = request.form['desinterest']
        lernen = request.form['lernen']
        idol = request.form['idol']
        serie = request.form['serie']
        musik = request.form['musik']
        fashion = request.form['fashion']
        zukunft = request.form['zukunft']
        love = request.form['love']
        date = request.form['date']
        pleasure = request.form['pleasure']
        regret = request.form['regret']
        party_movie = request.form.get('party_movie')
        ski_snowboard = request.form.get('ski_snowboard')
        wg_alleine = request.form.get('wg_alleine')
        hund_katze = request.form.get('hund_katze')
        regen_sonne = request.form.get('regen_sonne')
        spotify = request.form.get('spotify')


        # Handle the file upload
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
            else:
                file_path = None
        else:
            file_path = None  # No image uploaded

        
        # falls noch kein post existiert...
        # Create new post with image path
        # INSERT: Spaltenname in der Datenbank
        # VALUES: Variablen
        # Adjust the form field variable names and column names
        conn.execute('''
            INSERT INTO posts (
                user_id, content, birthday, color, food, redFlags, greenFlags, pinterest, name, personnality, zoe, interest, 
                desinterest, lernen, idol, serie, musik, fashion, zukunft, love, date, pleasure, regret, party_movie, 
                ski_snowboard, wg_alleine, hund_katze, regen_sonne, spotify, image_path
            ) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session['user_id'], content, bday, color, food, redFlag, greenFlag, pinterest, name, personnality, zoe, 
            interest, desinterest, lernen, idol, serie, musik, fashion, zukunft, love, date, pleasure, regret, 
            party_movie, ski_snowboard, wg_alleine, hund_katze, regen_sonne, spotify, file_path
        ))

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
    # wenn der user nicht eingeloggt ist dann wird man zur login-page gelinkt
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    # der post des eingeloggten users werden "geholt" (wenn nichts drin ist dann ist post = None)
    post = conn.execute('SELECT * FROM posts WHERE user_id = ?', (session['user_id'],)).fetchone()

    # Calculate whether the user has a post (used for the "Edit Post"/"Create Post" button)
    # nur die user die bereits einen post haben können ihn editet (onst wird die create-function aufgerufen!)
    has_post = post is not None

    # if something was posted
    if request.method == 'POST':
        # if the update-button gets clicked
        if 'update' in request.form:
            # the updated content is stored in a variable
            content = request.form['content']
            bday = request.form['bday'] 
            color = request.form['favcolor']
            food = request.form['Food']
            redFlag = request.form['rFlag']
            greenFlag = request.form['gFlag']
            pinterest = request.form['Pinterest']
            name = request.form['name']
            personnality = request.form['personnality']
            zoe = request.form['zoe']
            interest = request.form['interest']
            desinterest = request.form['desinterest']
            lernen = request.form['lernen']
            idol = request.form['idol']
            serie = request.form['serie']
            musik = request.form['musik']
            fashion = request.form['fashion']
            zukunft = request.form['zukunft']
            love = request.form['love']
            date = request.form['date']
            pleasure = request.form['pleasure']
            regret = request.form['regret']
            party_movie = request.form.get('party_movie')
            ski_snowboard = request.form.get('ski_snowboard')
            wg_alleine = request.form.get('wg_alleine')
            hund_katze = request.form.get('hund_katze')
            regen_sonne = request.form.get('regen_sonne')
            spotify = request.form.get('spotify')


            # Initialize image path as None
            file_path = None

            # if an image is uploaded
            if 'image' in request.files:
                file = request.files['image']
                
                # Check if the file is allowed and has a filename
                if file and allowed_file(file.filename):
                    # Secure the filename and save the new image
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    print(f"New image uploaded: {file_path}")  # Debugging print

                    # Optional: Remove old image if a new one is uploaded
                    if post and post['image_path']:
                        old_image_path = post['image_path']
                        if os.path.exists(old_image_path):
                            os.remove(old_image_path)
                            print(f"Old image removed: {old_image_path}")  # Debugging print

                else:
                    file_path = post['image_path']  # Keep old image if no new image uploaded
                    print("No new image uploaded, keeping the old image.")

            else:
                file_path = post['image_path']  # Keep old image if no new image uploaded
                print("No image uploaded at all, retaining current image.")

            # Update the post with the new content and the (new or old) image path
            # content = ? (content is the column name of the database) and the other content in the brackets after where is a variable
            conn.execute('''
                UPDATE posts 
                SET content = ?, birthday = ?, color = ?, redFlags = ?, greenFlags = ?, food = ?, pinterest = ?, 
                    name = ?, personnality = ?, zoe = ?, interest = ?, desinterest = ?, lernen = ?, idol = ?, 
                    serie = ?, musik = ?, fashion = ?, zukunft = ?, love = ?, date = ?, pleasure = ?, regret = ?, 
                    party_movie = ?, ski_snowboard = ?, wg_alleine = ?, hund_katze = ?, regen_sonne = ?, 
                    spotify = ?, image_path = ?
                WHERE user_id = ? 
            ''', (
                content, bday, color, redFlag, greenFlag, food, pinterest, name, personnality, zoe, interest, 
                desinterest, lernen, idol, serie, musik, fashion, zukunft, love, date, pleasure, regret, party_movie, 
                ski_snowboard, wg_alleine, hund_katze, regen_sonne, spotify, file_path, session['user_id']
            ))
            conn.commit()
            conn.close()
            print("Post updated in the database.")  # Debugging print
            return redirect(url_for('index'))

        # if the delete-button gets clicked
        elif 'delete' in request.form:
            print("Delete button clicked")  # Debugging print
            # Delete the post
            conn.execute('DELETE FROM posts WHERE user_id = ?', (session['user_id'],))
            conn.commit()
            conn.close()
            print("Post deleted.")  # Debugging print
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
    conn = get_db_connection()
    
    # Get active user by username
    user = conn.execute('SELECT * FROM users WHERE username = ? AND is_active = 1', (username,)).fetchone()
    
    if not user:
        conn.close()
        return "User not found or inactive", 404


    # Fetch the user's post
    post = conn.execute('SELECT * FROM posts WHERE user_id = ? AND is_active = 1', (user['id'],)).fetchone()

    # Get all active usernames for navigation
    users = conn.execute('SELECT username FROM users WHERE is_active = 1 ORDER BY username').fetchall()
    conn.close()

    # Prepare navigation links
    usernames = [u['username'] for u in users]
    current_index = usernames.index(username)
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

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    error_message = None
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db_connection()
        # fetch user by their email
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user:
            reset_token = secrets.token_urlsafe(16)
            conn = get_db_connection()
            conn.execute('UPDATE users SET reset_token = ? WHERE email = ?', (reset_token, email))
            conn.commit()
            conn.close()

            # Send reset email
            reset_link = url_for('reset_form', token=reset_token, _external=True)
            msg = Message('Reset your password', recipients=[email])
            msg.body = f'Click the link to reset your password: {reset_link}'
            mail.send(msg)

            flash('A password reset link has been sent to your email.')
            return redirect(url_for('login'))
        # if the email provided does not exist there comes this error message
        error_message = "Email not found!"
    return render_template('reset.html', error_message=error_message)


# display the form to enter the email to reset the password for
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_form(token):
    # handle the form submission
    if request.method == 'POST':
        new_password = request.form['new_password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE reset_token = ?', (token,)).fetchone()

        if user:
            hashed_password = generate_password_hash(new_password)
            conn.execute('UPDATE users SET password = ?, reset_token = NULL WHERE reset_token = ?', (hashed_password, token))
            conn.commit()
            conn.close()

            flash('Password successfully reset. Please log in.')
            return redirect(url_for('login'))
        else:
            flash('Invalid or expired token.')
            return redirect(url_for('forgot_password'))

    return render_template('reset2.html', token=token)



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
