from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

# Connect to the database
def get_db_connection():
    conn = sqlite3.connect('example.db')
    conn.row_factory = sqlite3.Row
    return conn

# Route for retrieving user data
@app.route('/user/<username>', methods=['GET'])
def get_user(username):
    conn = get_db_connection()
    user = conn.execute(f"SELECT * FROM users WHERE username = '{username}'").fetchone()
    conn.close()
    if user is None:
        return jsonify({"error": "User not found"}), 404
    return jsonify(dict(user))

# Route for adding new user
@app.route('/user', methods=['POST'])
def add_user():
    data = request.json
    username = data['username']
    password = data['password']  # plaintext password (insecure)
    conn = get_db_connection()
    conn.execute(f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')")
    conn.commit()
    conn.close()
    return jsonify({"message": "User added"}), 201

if __name__ == "__main__":
    app.run(debug=True)
