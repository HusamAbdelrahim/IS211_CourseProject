# Course Project

## Author: Husam Abdelrahim 

I built a web app using Flask and the Google Books API to help users track their personal book collections. The app lets users easily save and manage their book lists by searching via ISBN. I used SQLite for data storage, ensuring collections are saved reliably. This project stemmed from my own need to organize a growing library and turned into a fun way to explore APIs and backend development.

## Core Features

- ISBN-based book search through Google Books API
- Data storage of book title, author, page count, rating
- Book deletion functionality
- Basic error handling for API responses

## Extra Features Implemented
- Multi-user support with login system and password hashing
- Title-based book search
- Thumbnail display from Google Books image links
- Error handling for multiple ISBN results with user selection


Used SQLite for the database with two tables:

```sql
users (id, username, password_hash, salt)
books (id, user_id, isbn, title, author, page_count, average_rating, thumbnail_url)
```

API calls hit the Google Books endpoint:
https://www.googleapis.com/books/v1/volumes?q=isbn:[ISBN]

Password storage uses SHA-256 with unique salts per user to avoid storing plaintext passwords.


## How to run the project

1. Install requirements
`
pip install -r requirements.txt
`
2. Run flask web server 
`
python3 app.py
`
For the first time it will initialize the database with correct tables which we will use to store user login and list data.