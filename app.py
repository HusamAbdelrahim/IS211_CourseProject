from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import requests
import hashlib
import os
from functools import wraps


app = Flask(__name__)
app.secret_key = 'MYsuperSecretPa$$word2024' 

# database initialization
def init_db():
    conn = sqlite3.connect('books.db')
    c = conn.cursor()
    # updated users table with salt column
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  salt BLOB NOT NULL)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS books
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  isbn TEXT NOT NULL,
                  title TEXT NOT NULL,
                  author TEXT NOT NULL,
                  page_count INTEGER,
                  average_rating REAL,
                  thumbnail_url TEXT,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    conn.commit()
    conn.close()

def hash_password(password, salt=None):
    """Hash a password with a salt for secure storage"""
    if salt is None:
        salt = os.urandom(16)  # generate a new random salt
    # combine password and salt, then hash
    salted = password.encode() + salt
    hashed = hashlib.sha256(salted).hexdigest()
    return hashed, salt

def verify_password(password, hashed_password, salt):
    """Verify a password against its hash"""
    # hash the provided password with the stored salt
    verification_hash, _ = hash_password(password, salt)
    return verification_hash == hashed_password

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('register'))

        if len(password) < 6:
            flash('Password must be at least 6 characters long')
            return redirect(url_for('register'))

        # hash the password with a salt
        password_hash, salt = hash_password(password)

        conn = sqlite3.connect('books.db')
        c = conn.cursor()
        
        # Check if username already exists
        c.execute('SELECT id FROM users WHERE username = ?', (username,))
        if c.fetchone() is not None:
            conn.close()
            flash('Username already exists')
            return redirect(url_for('register'))

        try:
            c.execute('INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)',
                     (username, password_hash, salt))
            conn.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            print(e)
            flash('An error occurred during registration')
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('books.db')
        c = conn.cursor()
        c.execute('SELECT id, password_hash, salt FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and verify_password(password, user[1], user[2]):
            session['user_id'] = user[0]
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    conn = sqlite3.connect('books.db')
    c = conn.cursor()
    c.execute('SELECT * FROM books WHERE user_id = ?', (session['user_id'],))
    books = c.fetchall()
    conn.close()
    return render_template('index.html', books=books)

@app.route('/add_book', methods=['POST'])
@login_required
def add_book():
    isbn = request.form['isbn']
    
    # google Books API request
    response = requests.get(f'https://www.googleapis.com/books/v1/volumes?q=isbn:{isbn}')
    
    if response.status_code != 200:
        flash('Error connecting to Google Books API')
        return redirect(url_for('index'))
    
    data = response.json()
    
    if 'items' not in data or len(data['items']) == 0:
        flash('No books found with this ISBN')
        return redirect(url_for('index'))
    
    # Get the first book's info
    book_info = data['items'][0]['volumeInfo']
    
    # extract required information
    title = book_info.get('title', 'Unknown Title')
    authors = book_info.get('authors', ['Unknown Author'])
    page_count = book_info.get('pageCount', 0)
    average_rating = book_info.get('averageRating', 0.0)
    thumbnail_url = book_info.get('imageLinks', {}).get('thumbnail', '')
    
    # save to database
    conn = sqlite3.connect('books.db')
    c = conn.cursor()
    c.execute('''INSERT INTO books 
                 (user_id, isbn, title, author, page_count, average_rating, thumbnail_url)
                 VALUES (?, ?, ?, ?, ?, ?, ?)''',
              (session['user_id'], isbn, title, authors[0], page_count, average_rating, thumbnail_url))
    conn.commit()
    conn.close()
    
    flash('Book added successfully!')
    return redirect(url_for('index'))

@app.route('/delete_book/<int:book_id>')
@login_required
def delete_book(book_id):
    conn = sqlite3.connect('books.db')
    c = conn.cursor()
    c.execute('DELETE FROM books WHERE id = ? AND user_id = ?',
              (book_id, session['user_id']))
    conn.commit()
    conn.close()
    flash('Book deleted successfully!')
    return redirect(url_for('index'))

@app.route('/search_title', methods=['POST'])
@login_required
def search_title():
    title = request.form['title']
    response = requests.get(f'https://www.googleapis.com/books/v1/volumes?q=intitle:{title}')
    
    if response.status_code != 200:
        flash('Error connecting to Google Books API')
        return redirect(url_for('index'))
    
    data = response.json()
    if 'items' not in data:
        flash('No books found with this title')
        return redirect(url_for('index'))
        
    return render_template('search_results.html', books=data['items'])

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
